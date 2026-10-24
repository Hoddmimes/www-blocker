#!/usr/bin/env python3
"""
www-blocker - follow Apache access logs in real time and ban hosts that
hammer the server with bad requests (by default 400 and 404 responses).

A ban is an entry in an ipset with its own timeout, so the kernel expires it
by itself - also while this program is stopped. One iptables rule per address
family drops web traffic from addresses in the set.

Commands:
  run [--dry-run]          follow the logs and ban (this is what systemd runs)
  simulate LOG...          replay old logs and report what would have been banned
  list                     show active bans with time left and dropped packets
  ban ADDR [-m MINUTES]    ban an IP or CIDR by hand
  unban ADDR               lift a ban
  flush                    lift all bans (the sets and rules are kept)
  check                    validate the config and show what would be watched

Only the Python standard library is used.
"""

import argparse
import collections
import ctypes
import ctypes.util
import functools
import glob
import gzip
import heapq
import ipaddress
import logging
import os
import re
import select
import shlex
import signal
import struct
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(HERE, "www-blocker.conf")

log = logging.getLogger("www-blocker")
bans = log.getChild("bans")    # BAN/EXPIRED/REMOVED events: journal + bans log file

# "%h %l %u <time> "%r" %>s ..." - works for both [%t] and the custom
# "%{%Y-%m-%d %H:%M:%S}t" timestamps used on this host, common and combined.
LINE_RE = re.compile(
    rb'(?P<ip>\S+) \S+ \S+ +'
    rb'(?:\[(?P<clf>[^\]]*)\]|(?P<iso>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)) +'
    rb'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3})\b'
)


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULTS = {
    "dry_run": True,
    "allowlist": ["127.0.0.0/8", "::1/128"],
    "logs": {"files": ["/var/log/httpd/*access*log"], "rescan_interval": 60, "bans_log": "bans"},
    "detect": {"statuses": [400, 404], "threshold": 20, "window": 60, "ban_minutes": 30},
    "subnet": {"enabled": True, "min_hosts": 3, "window": 3600, "ban_minutes": 120,
               "prefix_v4": 24, "prefix_v6": 64},
    "firewall": {"ports": [80, 443], "set_name": "www-blocker", "chain": "WWW-BLOCKER",
                 "ipv6": True, "log_drops": False, "maxelem": 65536},
}


class ConfigError(Exception):
    pass


@dataclass
class Config:
    dry_run: bool
    allowlist: list
    log_files: list
    rescan_interval: float
    bans_log: str
    statuses: frozenset
    threshold: int
    window: float
    ban_seconds: int
    subnet_enabled: bool
    subnet_min_hosts: int
    subnet_window: float
    subnet_ban_seconds: int
    prefix: dict
    ports: list
    set_name: str
    chain: str
    ipv6: bool
    log_drops: bool
    maxelem: int


def load_config(path):
    try:
        with open(path, "rb") as fh:
            user = tomllib.load(fh)
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}")
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}")

    merged = {}
    for key, default in DEFAULTS.items():
        value = user.get(key, default)
        if isinstance(default, dict):
            if not isinstance(value, dict):
                raise ConfigError(f"[{key}] must be a table")
            unknown = set(value) - set(default)
            if unknown:
                raise ConfigError(f"unknown key(s) in [{key}]: {', '.join(sorted(unknown))}")
            value = {**default, **value}
        merged[key] = value
    unknown = set(user) - set(DEFAULTS)
    if unknown:
        raise ConfigError(f"unknown top-level key(s): {', '.join(sorted(unknown))}")

    d, s, f = merged["detect"], merged["subnet"], merged["firewall"]

    def positive(name, v, kind=int):
        if not isinstance(v, (int, float)) or isinstance(v, bool) or v <= 0:
            raise ConfigError(f"{name} must be a positive number, got {v!r}")
        return kind(v)

    try:
        allowlist = [ipaddress.ip_network(a, strict=False) for a in merged["allowlist"]]
    except (TypeError, ValueError) as e:
        raise ConfigError(f"allowlist: {e}")

    ports = f["ports"]
    if not ports or len(ports) > 15 or not all(isinstance(p, int) and 0 < p < 65536 for p in ports):
        raise ConfigError("firewall.ports must be 1-15 port numbers")
    if not all(isinstance(x, int) and 100 <= x <= 599 for x in d["statuses"]):
        raise ConfigError("detect.statuses must be HTTP status codes")
    if not (8 <= s["prefix_v4"] <= 32 and 16 <= s["prefix_v6"] <= 128):
        raise ConfigError("subnet.prefix_v4 must be 8-32 and subnet.prefix_v6 16-128")
    if len(f["set_name"]) > 30 or len(f["chain"]) > 28:
        raise ConfigError("firewall.set_name max 30 chars, firewall.chain max 28 chars")
    if isinstance(merged["logs"]["files"], str):
        merged["logs"]["files"] = [merged["logs"]["files"]]

    return Config(
        dry_run=bool(merged["dry_run"]),
        allowlist=allowlist,
        log_files=list(merged["logs"]["files"]),
        bans_log=os.path.join(HERE, merged["logs"]["bans_log"]) if merged["logs"]["bans_log"] else "",
        rescan_interval=positive("logs.rescan_interval", merged["logs"]["rescan_interval"], float),
        statuses=frozenset(d["statuses"]),
        threshold=positive("detect.threshold", d["threshold"]),
        window=positive("detect.window", d["window"], float),
        ban_seconds=int(positive("detect.ban_minutes", d["ban_minutes"], float) * 60),
        subnet_enabled=bool(s["enabled"]),
        subnet_min_hosts=positive("subnet.min_hosts", s["min_hosts"]),
        subnet_window=positive("subnet.window", s["window"], float),
        subnet_ban_seconds=int(positive("subnet.ban_minutes", s["ban_minutes"], float) * 60),
        prefix={4: s["prefix_v4"], 6: s["prefix_v6"]},
        ports=ports,
        set_name=f["set_name"],
        chain=f["chain"],
        ipv6=bool(f["ipv6"]),
        log_drops=bool(f["log_drops"]),
        maxelem=positive("firewall.maxelem", f["maxelem"]),
    )


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def fmt_dur(seconds):
    """3725 -> '1h2m'; shows the two most significant units."""
    s = max(0, int(round(seconds)))
    parts = []
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if s >= n:
            parts.append(f"{s // n}{unit}")
            s %= n
    return "".join(parts[:2]) or "0s"


def show_net(net):
    """Hosts print as a plain address, subnets with their prefix."""
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)


@functools.lru_cache(maxsize=65536)
def to_addr(raw):
    try:
        addr = ipaddress.ip_address(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return None
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr


@functools.lru_cache(maxsize=65536)
def subnet_of(addr, prefix):
    return ipaddress.ip_network((addr, prefix), strict=False)


@functools.lru_cache(maxsize=8192)
def parse_ts(clf, iso):
    if iso:
        return time.mktime(time.strptime(iso.decode(), "%Y-%m-%d %H:%M:%S"))
    return datetime.strptime(clf.decode(), "%d/%b/%Y:%H:%M:%S %z").timestamp()


def need_root():
    if os.geteuid() != 0:
        sys.exit("www-blocker: this needs root to manage ipset/iptables (try sudo)")


# --------------------------------------------------------------------------
# Firewall: ipset with per-entry timeouts + one iptables jump rule
# --------------------------------------------------------------------------

class FirewallError(Exception):
    pass


class Firewall:
    IPT = {4: "iptables", 6: "ip6tables"}
    FAMILY = {4: "inet", 6: "inet6"}

    def __init__(self, cfg, dry_run):
        self.cfg = cfg
        self.dry_run = dry_run
        self.versions = [4, 6] if cfg.ipv6 else [4]
        self.known = {}         # net -> (expected expiry, dropped packets) at the last look
        self.durations = {}     # net -> ban length, for bans made by this process
        self.notes = {}         # net -> why we removed it ourselves

    def adopt(self, old):
        """Keep the expiry bookkeeping across a config reload."""
        self.known, self.durations, self.notes = old.known, old.durations, old.notes

    def set_name(self, version):
        return f"{self.cfg.set_name}{version}"

    def _run(self, *args, check=True):
        try:
            p = subprocess.run(args, capture_output=True, text=True)
        except FileNotFoundError:
            raise FirewallError(f"{args[0]} not found")
        if check and p.returncode != 0:
            raise FirewallError(f"{' '.join(args)}: {p.stderr.strip() or p.stdout.strip()}")
        return p

    def _jump_rule(self, v):
        return ["-p", "tcp", "-m", "multiport", "--dports", ",".join(map(str, self.cfg.ports)),
                "-m", "set", "--match-set", self.set_name(v), "src",
                "-m", "comment", "--comment", "www-blocker", "-j", self.cfg.chain]

    def setup(self):
        """Create sets, chain and jump rules if missing. Never removes bans."""
        for v in self.versions:
            ipt, name, chain = self.IPT[v], self.set_name(v), self.cfg.chain
            p = self._run("ipset", "create", name, "hash:net", "family", self.FAMILY[v],
                          "timeout", "3600", "maxelem", str(self.cfg.maxelem),
                          "counters", "-exist", check=False)
            if p.returncode != 0:
                if self._run("ipset", "list", "-n", name, check=False).returncode != 0:
                    raise FirewallError(f"cannot create ipset {name}: {p.stderr.strip()}")
                log.warning("ipset %s exists with other parameters; using it as is", name)

            if self._run(ipt, "-w", "-n", "-L", chain, check=False).returncode != 0:
                self._run(ipt, "-w", "-N", chain)
            self._run(ipt, "-w", "-F", chain)
            if self.cfg.log_drops:
                self._run(ipt, "-w", "-A", chain, "-m", "limit", "--limit", "6/min",
                          "-j", "LOG", "--log-prefix", "www-blocker drop: ", "--log-level", "6")
            self._run(ipt, "-w", "-A", chain, "-j", "DROP")

            want = self._jump_rule(v)
            jumps = [l for l in self._run(ipt, "-w", "-S", "INPUT").stdout.splitlines()
                     if f"-j {chain}" in l]
            ok = self._run(ipt, "-w", "-C", "INPUT", *want, check=False).returncode == 0
            if ok and len(jumps) == 1:
                continue
            # Ports or set changed (or duplicates): replace our jump rule(s).
            for line in jumps:
                args = shlex.split(line)
                args[0] = "-D"
                self._run(ipt, "-w", *args, check=False)
            self._run(ipt, "-w", "-I", "INPUT", "1", *want)
            log.info("%s: INPUT tcp/%s -> set %s -> %s (DROP)", ipt,
                     ",".join(map(str, self.cfg.ports)), name, chain)

    def rules_ok(self):
        return all(self._run(self.IPT[v], "-w", "-C", "INPUT", *self._jump_rule(v),
                             check=False).returncode == 0 for v in self.versions)

    def ensure(self):
        """Put the rules back if someone (iptables-restore, a reload) removed them."""
        if self.dry_run:
            return
        try:
            if not self.rules_ok():
                log.warning("firewall rules were missing - restoring them")
                self.setup()
        except FirewallError as e:
            log.error("firewall check failed: %s", e)

    def ban(self, net, seconds, reason, now=None):
        verb = "WOULD BAN" if self.dry_run else "BAN"
        if net.version not in self.versions:
            log.info("%s %s skipped (IPv6 blocking disabled): %s", verb, show_net(net), reason)
            return
        bans.warning("%s %s for %s: %s", verb, show_net(net), fmt_dur(seconds), reason)
        self.durations[net] = seconds
        if self.dry_run:
            return
        if net in self.known:
            # Expired since the last look and is being banned again: report that first.
            self._report_gone(net, *self.known.pop(net), now=time.time())
            self.durations[net] = seconds
        self.known[net] = (time.time() + seconds, 0)
        try:
            self._run("ipset", "add", self.set_name(net.version), str(net),
                      "timeout", str(int(seconds)), "-exist")
        except FirewallError as e:
            log.error("ban of %s failed: %s", net, e)

    def unban(self, net, quiet=False, note=None):
        if net.version not in self.versions or self.dry_run:
            return False
        p = self._run("ipset", "del", self.set_name(net.version), str(net), check=False)
        if p.returncode == 0:
            if note:
                self.notes[net] = note
            if not quiet:
                bans.info("UNBAN %s (by hand)", show_net(net))
        return p.returncode == 0

    def watch_expiry(self, now, baseline=False):
        """Compare the sets with the last look and report bans that are gone."""
        current = {}
        for v in self.versions:
            for net, left, pkts, _ in self.entries(v) or []:
                current[net] = (now + left, pkts)
        if not baseline:
            for net in self.known.keys() - current.keys():
                self._report_gone(net, *self.known[net], now=now)
        self.known = current

    def _report_gone(self, net, expiry, packets, now):
        dur = self.durations.pop(net, None)
        note = self.notes.pop(net, None)
        banned = f" (banned {fmt_dur(dur)})" if dur else ""
        dropped = f"dropped {packets:,} packets"
        if note:
            bans.info("REMOVED %s%s: %s - %s", show_net(net), banned, note, dropped)
        elif expiry <= now + 2:
            bans.info("EXPIRED %s%s - %s while banned", show_net(net), banned, dropped)
        else:
            bans.info("REMOVED %s%s: unbanned by hand or flushed, %s left - %s",
                      show_net(net), banned, fmt_dur(expiry - now), dropped)

    def dry_expired(self, nets):
        for net in nets:
            dur = self.durations.pop(net, None)
            bans.info("WOULD EXPIRE %s%s", show_net(net), f" (banned {fmt_dur(dur)})" if dur else "")

    def covering(self, addr):
        """Is addr dropped by the set (as host or via a subnet entry)?"""
        p = self._run("ipset", "test", self.set_name(addr.version), str(addr), check=False)
        return p.returncode == 0

    def entries(self, v):
        """[(net, seconds_left, packets, bytes)] or None if the set does not exist."""
        p = self._run("ipset", "save", self.set_name(v), check=False)
        if p.returncode != 0:
            return None
        out = []
        for line in p.stdout.splitlines():
            tok = line.split()
            if len(tok) < 3 or tok[0] != "add":
                continue
            opts = dict(zip(tok[3::2], tok[4::2]))
            out.append((ipaddress.ip_network(tok[2], strict=False), int(opts.get("timeout", 0)),
                        int(opts.get("packets", 0)), int(opts.get("bytes", 0))))
        return out

    def flush(self):
        for v in self.versions:
            self._run("ipset", "flush", self.set_name(v), check=False)


class Recorder:
    """Stand-in firewall for `simulate`: remembers bans instead of making them."""

    def __init__(self, cfg):
        self.versions = [4, 6] if cfg.ipv6 else [4]
        self.events = []

    def ban(self, net, seconds, reason, now=None):
        self.events.append((now, net, seconds, reason))

    def unban(self, net, quiet=False, note=None):
        return False


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

class Track:
    __slots__ = ("times", "request", "status", "source")

    def __init__(self):
        self.times = collections.deque()


class Detector:
    def __init__(self, cfg, firewall):
        self.cfg = cfg
        self.fw = firewall
        self.hits = {}                                  # addr -> Track
        self.active = {}                                # network -> expiry
        self.recent = collections.defaultdict(dict)     # subnet -> {addr: ban time}
        self.stats = collections.Counter()

    def reconfigure(self, cfg, firewall):
        self.cfg, self.fw = cfg, firewall

    def allowed(self, addr):
        return any(addr in net for net in self.cfg.allowlist)

    def covered(self, addr, now):
        """Already banned by us (host or subnet) and not yet expired?"""
        for net in (ipaddress.ip_network(addr), subnet_of(addr, self.cfg.prefix[addr.version])):
            exp = self.active.get(net)
            if exp is not None and exp > now:
                return True
        return False

    def bad(self, addr, request, status, source, now):
        """Count one bad response from addr; ban when the threshold is reached."""
        cfg = self.cfg
        self.stats["bad"] += 1
        if self.allowed(addr) or self.covered(addr, now):
            return
        t = self.hits.get(addr)
        if t is None:
            t = self.hits[addr] = Track()
        t.times.append(now)
        t.request, t.status, t.source = request, status, source
        cutoff = now - cfg.window
        while t.times[0] <= cutoff:
            t.times.popleft()
        if len(t.times) >= cfg.threshold:
            del self.hits[addr]
            self._ban_host(addr, t, now)

    def _ban_host(self, addr, t, now):
        cfg = self.cfg
        net = ipaddress.ip_network(addr)
        req = t.request.decode("utf-8", "replace")
        if len(req) > 80:
            req = req[:77] + "..."
        reason = (f"{len(t.times)} bad responses in {fmt_dur(now - t.times[0])} "
                  f'(last: "{req}" {t.status}, {t.source})')
        self.active[net] = now + cfg.ban_seconds
        self.stats["host_bans"] += 1
        self.fw.ban(net, cfg.ban_seconds, reason, now)
        if cfg.subnet_enabled and addr.version in self.fw.versions:
            self._consider_subnet(addr, now)

    def _consider_subnet(self, addr, now):
        cfg = self.cfg
        sub = subnet_of(addr, cfg.prefix[addr.version])
        if sub.prefixlen == sub.max_prefixlen:
            return
        members = self.recent[sub]
        members[addr] = now
        cutoff = now - cfg.subnet_window
        for a in [a for a, ts in members.items() if ts <= cutoff]:
            del members[a]
        if len(members) < cfg.subnet_min_hosts:
            return
        if any(sub.overlaps(net) for net in cfg.allowlist):
            log.info("not banning %s: overlaps the allowlist", sub)
            return
        hosts = sorted(members)
        listed = ", ".join(map(str, hosts[:5])) + (" ..." if len(hosts) > 5 else "")
        reason = f"{len(hosts)} hosts banned within {fmt_dur(cfg.subnet_window)} ({listed})"
        self.active[sub] = now + cfg.subnet_ban_seconds
        self.stats["subnet_bans"] += 1
        self.fw.ban(sub, cfg.subnet_ban_seconds, reason, now)
        # The subnet entry covers its hosts; drop their own entries and counters.
        for a in hosts:
            host = ipaddress.ip_network(a)
            self.active.pop(host, None)
            self.fw.unban(host, quiet=True, note=f"replaced by subnet ban {sub}")
        for a in [a for a in self.hits if a in sub]:
            del self.hits[a]
        del self.recent[sub]

    def housekeeping(self, now):
        """Forget stale counters and expired bans so memory stays flat."""
        cutoff = now - self.cfg.window
        for a in [a for a, t in self.hits.items() if t.times[-1] <= cutoff]:
            del self.hits[a]
        expired = [n for n, exp in self.active.items() if exp <= now]
        for n in expired:
            del self.active[n]
        cutoff = now - self.cfg.subnet_window
        for sub in list(self.recent):
            members = self.recent[sub]
            for a in [a for a, ts in members.items() if ts <= cutoff]:
                del members[a]
            if not members:
                del self.recent[sub]
        return expired


# --------------------------------------------------------------------------
# Following log files
# --------------------------------------------------------------------------

class Follower:
    """tail -F for one file: survives logrotate renames and truncation."""

    MAX_PARTIAL = 64 * 1024

    def __init__(self, path, from_start):
        self.path = path
        self.name = os.path.basename(path)
        self.fh = None
        self.ident = None
        self.buf = b""
        self.gone_since = None
        self._open(from_start)

    def _open(self, from_start):
        try:
            fh = open(self.path, "rb")
        except OSError:
            self.fh = None
            return False
        st = os.fstat(fh.fileno())
        self.ident = (st.st_dev, st.st_ino)
        if not from_start:
            fh.seek(0, os.SEEK_END)
        self.fh, self.buf = fh, b""
        return True

    def _read(self):
        while True:
            chunk = self.fh.read(1 << 20)
            if not chunk:
                break
            lines = (self.buf + chunk).split(b"\n")
            self.buf = lines.pop()
            yield from lines
        if len(self.buf) > self.MAX_PARTIAL:
            self.buf = b""

    def poll(self, check_rotation):
        if self.fh is None:
            if not self._open(from_start=True):
                return
            log.info("now following %s", self.path)
        if check_rotation:
            try:
                st = os.stat(self.path)
            except FileNotFoundError:
                st = None   # renamed away; the new file is not there yet
            if st is not None and (st.st_dev, st.st_ino) != self.ident:
                yield from self._read()     # finish the old file first
                self.fh.close()
                self._open(from_start=True)
                log.info("%s was rotated - following the new file", self.name)
            elif st is not None and st.st_size < self.fh.tell():
                self.fh.seek(0)
                self.buf = b""
                log.info("%s was truncated - reading from the start", self.name)
        yield from self._read()

    def gone(self):
        return not os.path.exists(self.path)

    def close(self):
        if self.fh:
            self.fh.close()


class Inotify:
    """Wake up as soon as Apache writes, instead of polling. ctypes, no deps."""

    IN_MODIFY, IN_MOVED_FROM, IN_MOVED_TO = 0x2, 0x40, 0x80
    IN_CREATE, IN_DELETE, IN_Q_OVERFLOW = 0x100, 0x200, 0x4000
    STRUCTURAL = IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_Q_OVERFLOW
    EVENT = struct.Struct("iIII")

    def __init__(self):
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        self._add = libc.inotify_add_watch
        self._add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self.fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        self.watched = set()

    def watch(self, directory):
        if directory in self.watched or not os.path.isdir(directory):
            return
        mask = self.IN_MODIFY | self.STRUCTURAL
        if self._add(self.fd, os.fsencode(directory), mask) < 0:
            raise OSError(ctypes.get_errno(), f"inotify_add_watch {directory}")
        self.watched.add(directory)

    def wait(self, timeout):
        """None on timeout, else (set of changed file names, structural change?)."""
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return None
        names, structural = set(), False
        while True:
            try:
                data = os.read(self.fd, 65536)
            except BlockingIOError:
                break
            off = 0
            while off + self.EVENT.size <= len(data):
                _, mask, _, length = self.EVENT.unpack_from(data, off)
                start = off + self.EVENT.size
                names.add(os.fsdecode(data[start:start + length].rstrip(b"\0")))
                structural |= bool(mask & self.STRUCTURAL)
                off = start + length
        return names, structural


# --------------------------------------------------------------------------
# The daemon
# --------------------------------------------------------------------------

class Daemon:
    def __init__(self, cfg_path, force_dry):
        self.cfg_path = cfg_path
        self.force_dry = force_dry
        self.followers = {}
        self.stop = self.reload = self.dump = False
        self.cfg = load_config(cfg_path)
        self.det = None
        self._apply(self.cfg)
        try:
            self.notifier = Inotify()
        except (OSError, AttributeError) as e:
            log.warning("inotify unavailable (%s) - polling twice a second", e)
            self.notifier = None
        self.started = time.time()

    def _apply(self, cfg):
        self.cfg = cfg
        was_dry = getattr(self, "dry", None)
        self.dry = cfg.dry_run or self.force_dry
        if was_dry and not self.dry:
            # Dry-run "bans" never reached the firewall; forget them so those hosts get banned for real.
            self.det.active.clear()
            self.det.recent.clear()
            self.det.fw.durations.clear()
        if not self.dry:
            need_root()
        fw = Firewall(cfg, self.dry)
        if self.det is not None:
            fw.adopt(self.det.fw)
        if not self.dry:
            fw.setup()
            if self.det is None:
                fw.watch_expiry(time.time(), baseline=True)
                if fw.known:
                    log.info("%d ban(s) from before the start are still active", len(fw.known))
        if self.det is None:
            self.det = Detector(cfg, fw)
        else:
            self.det.reconfigure(cfg, fw)
        cfg_desc = (f"{cfg.threshold}x {'/'.join(map(str, sorted(cfg.statuses)))} "
                    f"in {fmt_dur(cfg.window)} -> ban {fmt_dur(cfg.ban_seconds)}")
        if cfg.subnet_enabled:
            cfg_desc += (f"; /{cfg.prefix[4]} after {cfg.subnet_min_hosts} hosts in "
                         f"{fmt_dur(cfg.subnet_window)} -> ban {fmt_dur(cfg.subnet_ban_seconds)}")
        log.info("%s mode: %s; ports %s", "DRY-RUN" if self.dry else "ENFORCING", cfg_desc,
                 ",".join(map(str, cfg.ports)))

    def _signals(self):
        def stop(*_):
            self.stop = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGHUP, lambda *_: setattr(self, "reload", True))
        signal.signal(signal.SIGUSR1, lambda *_: setattr(self, "dump", True))

    def rescan(self, initial=False):
        matched = set()
        for pattern in self.cfg.log_files:
            for path in glob.glob(pattern):
                if os.path.isfile(path):
                    matched.add(path)
            if self.notifier:
                try:
                    self.notifier.watch(os.path.dirname(pattern) or ".")
                except OSError as e:
                    log.warning("%s", e)
        for path in sorted(matched - set(self.followers)):
            # At startup skip history; files appearing later are read from the start.
            self.followers[path] = Follower(path, from_start=not initial)
            log.info("following %s", path)
        # A rotated file is briefly missing until Apache reopens it; keep reading
        # the old one meanwhile and only give up after it has been gone a while.
        now = time.time()
        for path, f in list(self.followers.items()):
            if path in matched or not f.gone():
                f.gone_since = None
            elif f.gone_since is None:
                f.gone_since = now
            elif now - f.gone_since > 600:
                self.followers.pop(path).close()
                log.info("stopped following %s (file gone)", path)
        if not self.followers:
            log.warning("no log files match %s", ", ".join(self.cfg.log_files))

    def do_reload(self):
        try:
            cfg = load_config(self.cfg_path)
            self._apply(cfg)
            self.rescan()
            log.info("configuration reloaded")
        except (ConfigError, FirewallError) as e:
            log.error("reload failed, keeping the old configuration: %s", e)

    def log_stats(self):
        s = self.det.stats
        log.info("stats: up %s, %d lines, %d bad responses, %d host bans, %d subnet bans, "
                 "%d hosts being counted, %d bans active, %d unparsed lines",
                 fmt_dur(time.time() - self.started), s["lines"], s["bad"], s["host_bans"],
                 s["subnet_bans"], len(self.det.hits), len(self.det.active), s["unparsed"])

    def handle(self, line, source, now):
        stats = self.det.stats
        stats["lines"] += 1
        m = LINE_RE.match(line)
        if m is None:
            if line.strip():
                stats["unparsed"] += 1
            return
        status = int(m["status"])
        if status in self.cfg.statuses:
            addr = to_addr(m["ip"])
            if addr is not None:
                self.det.bad(addr, m["req"], status, source, now)

    def loop(self):
        self._signals()
        self.rescan(initial=True)
        now = time.time()
        last = dict(rotation=now, rescan=now, house=now, ensure=now, stats=now)
        while not self.stop:
            if self.reload:
                self.reload = False
                self.do_reload()
            if self.dump:
                self.dump = False
                self.log_stats()

            if self.notifier:
                event = self.notifier.wait(1.0)
            else:
                time.sleep(0.5)
                event = None
            now = time.time()

            if (event and event[1]) or now - last["rescan"] >= self.cfg.rescan_interval:
                self.rescan()
                last["rescan"] = now
            rotation = event is None or event[1] or now - last["rotation"] >= 1.0
            if rotation:
                last["rotation"] = now
            only = None if rotation else event[0]

            for f in list(self.followers.values()):
                if only is not None and f.name not in only:
                    continue
                for line in f.poll(rotation):
                    self.handle(line, f.name, now)

            if now - last["house"] >= 10:
                expired = self.det.housekeeping(now)
                if self.dry:
                    self.det.fw.dry_expired(expired)
                else:
                    self.det.fw.watch_expiry(now)
                last["house"] = now
            if now - last["ensure"] >= 60:
                self.det.fw.ensure()
                last["ensure"] = now
            if now - last["stats"] >= 3600:
                self.log_stats()
                last["stats"] = now

        self.log_stats()
        log.info("stopping; active bans stay in place and expire on their own")


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_run(args, cfg):
    Daemon(args.config, args.dry_run).loop()


def read_log(path):
    """Yield (ts, ip, status, request, name) from a (possibly gzipped) log."""
    opener = gzip.open if path.endswith(".gz") else open
    name = os.path.basename(path)
    with opener(path, "rb") as fh:
        for line in fh:
            m = LINE_RE.match(line)
            if m is None:
                continue
            try:
                ts = parse_ts(m["clf"], m["iso"])
            except ValueError:
                continue
            yield ts, m["ip"], int(m["status"]), m["req"], name


def cmd_simulate(args, cfg):
    if args.threshold:
        cfg.threshold = args.threshold
    if args.window:
        cfg.window = args.window
    if args.ban_minutes:
        cfg.ban_seconds = int(args.ban_minutes * 60)
    if args.min_hosts:
        cfg.subnet_min_hosts = args.min_hosts
    if args.no_subnet:
        cfg.subnet_enabled = False

    rec = Recorder(cfg)
    det = Detector(cfg, rec)
    ok = collections.Counter()          # addr -> successful responses
    total = bad = blocked = blocked_bad = 0
    first = last = None
    house = 0
    streams = []
    for path in args.logs:
        try:
            streams.append(read_log(path))
        except OSError as e:
            sys.exit(f"www-blocker: {e}")

    try:
        for ts, ip, status, req, name in heapq.merge(*streams, key=lambda r: r[0]):
            total += 1
            first = ts if first is None else first
            last = ts
            addr = to_addr(ip)
            if addr is None:
                continue
            if det.covered(addr, ts):
                blocked += 1
                blocked_bad += status in cfg.statuses
                continue
            if status < 400:
                ok[addr] += 1
            if status in cfg.statuses:
                bad += 1
                det.bad(addr, req, status, name, ts)
            if ts - house >= 30:
                det.housekeeping(ts)
                house = ts
    except OSError as e:
        sys.exit(f"www-blocker: {e}")

    if not total:
        sys.exit("www-blocker: no parsable lines in the given log(s)")

    def when(ts):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

    bad_all = bad + blocked_bad
    hosts = [e for e in rec.events if e[1].prefixlen == e[1].max_prefixlen]
    subnets = [e for e in rec.events if e[1].prefixlen != e[1].max_prefixlen]
    statuses = "/".join(map(str, sorted(cfg.statuses)))

    print(f"Simulated {total:,} requests from {len(args.logs)} file(s), "
          f"{when(first)} -> {when(last)} ({fmt_dur(last - first)})")
    print(f"Rule: {cfg.threshold}x {statuses} within {fmt_dur(cfg.window)} -> ban "
          f"{fmt_dur(cfg.ban_seconds)}" + (
              f"; /{cfg.prefix[4]} after {cfg.subnet_min_hosts} banned hosts within "
              f"{fmt_dur(cfg.subnet_window)} -> ban {fmt_dur(cfg.subnet_ban_seconds)}"
              if cfg.subnet_enabled else "; subnet bans off"))
    print()
    print(f"  {statuses} responses        {bad_all:>10,}  ({100 * bad_all / total:.1f}% of all)")
    print(f"  bans                      {len(hosts):>10,} hosts, {len(subnets)} subnets "
          f"({len({e[1] for e in rec.events}):,} distinct)")
    print(f"  requests dropped by bans  {blocked:>10,}  ({100 * blocked / total:.1f}% of all)")
    if bad_all:
        print(f"  {statuses} stopped            {blocked_bad:>10,}  "
              f"({100 * blocked_bad / bad_all:.1f}% of them never reach Apache)")

    banned = {}
    for ts, net, secs, reason in rec.events:
        banned.setdefault(net, []).append(ts)
    if banned:
        print("\nBan events" + ("" if args.all or len(rec.events) <= 30 else
                                f" (first 30 of {len(rec.events)}, --all for every one)") + ":")
        for ts, net, secs, reason in rec.events[:None if args.all else 30]:
            print(f"  {when(ts)}  {show_net(net):<18} {fmt_dur(secs):>4}  {reason}")

        # Did banned addresses also get real pages? Those could be false positives.
        suspects = []
        for net in banned:
            served = sum(c for a, c in ok.items() if a in net)
            if served:
                suspects.append((served, net))
        suspects.sort(key=lambda x: (-x[0], str(x[1])))
        print("\nBanned addresses that also received successful (<400) responses:")
        if not suspects:
            print("  none - every banned address only produced errors")
        for served, net in suspects[:15]:
            print(f"  {show_net(net):<18} {served:>7,} ok responses, banned {len(banned[net])}x")
    else:
        print("\nNo bans would have been made with these settings.")

    # Who keeps erroring just below the threshold?
    if args.near:
        print("\nTop error sources overall (to help pick a threshold):")
        per = collections.Counter()
        for path in args.logs:
            for ts, ip, status, req, name in read_log(path):
                if status in cfg.statuses:
                    per[ip.decode(errors="replace")] += 1
        for ip, n in per.most_common(15):
            print(f"  {ip:<18} {n:>8,}")


def cmd_list(args, cfg):
    need_root()
    fw = Firewall(cfg, dry_run=False)
    now = time.time()
    for v in fw.versions:
        entries = fw.entries(v)
        name = fw.set_name(v)
        if entries is None:
            print(f"{name}: does not exist yet (the service has not run in enforcing mode)")
            continue
        rule = "active" if fw._run(fw.IPT[v], "-w", "-C", "INPUT", *fw._jump_rule(v),
                                   check=False).returncode == 0 else "MISSING"
        print(f"{name}: {len(entries)} ban(s), iptables rule {rule} "
              f"(tcp/{','.join(map(str, cfg.ports))})")
        if not entries:
            continue
        print(f"  {'ADDRESS':<20} {'TYPE':<7} {'EXPIRES IN':>10}  {'AT':<8} {'DROPPED PKTS':>12}")
        for net, left, pkts, _ in sorted(entries, key=lambda e: (-e[1], str(e[0]))):
            kind = "host" if net.prefixlen == net.max_prefixlen else "subnet"
            at = time.strftime("%H:%M:%S", time.localtime(now + left))
            print(f"  {show_net(net):<20} {kind:<7} {fmt_dur(left):>10}  {at:<8} {pkts:>12,}")


def parse_net(text):
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        sys.exit(f"www-blocker: not an IP address or network: {text}")


def cmd_ban(args, cfg):
    need_root()
    net = parse_net(args.addr)
    if any(net.overlaps(a) for a in cfg.allowlist) and not args.force:
        sys.exit(f"www-blocker: {net} overlaps the allowlist (use --force to ban anyway)")
    fw = Firewall(cfg, dry_run=False)
    fw.setup()
    if args.minutes:
        seconds = int(args.minutes * 60)
    else:
        seconds = cfg.ban_seconds if net.prefixlen == net.max_prefixlen else cfg.subnet_ban_seconds
    fw.ban(net, seconds, "manual ban")


def cmd_unban(args, cfg):
    need_root()
    net = parse_net(args.addr)
    fw = Firewall(cfg, dry_run=False)
    if fw.unban(net):
        print(f"unbanned {show_net(net)}")
    else:
        print(f"{show_net(net)} was not in the ban list")
    if net.prefixlen == net.max_prefixlen and net.version in fw.versions \
            and fw.covering(net.network_address):
        for other, *_ in fw.entries(net.version) or []:
            if net.network_address in other:
                print(f"note: still blocked by the subnet ban {other} - unban that too if needed")


def cmd_flush(args, cfg):
    need_root()
    Firewall(cfg, dry_run=False).flush()
    bans.info("FLUSH all bans lifted (by hand)")
    print("all bans lifted (sets and rules kept)")


def cmd_check(args, cfg):
    print(f"config {args.config}: OK")
    print(f"  mode: {'DRY-RUN' if cfg.dry_run else 'ENFORCING'}")
    print(f"  rule: {cfg.threshold}x {'/'.join(map(str, sorted(cfg.statuses)))} within "
          f"{fmt_dur(cfg.window)} -> ban {fmt_dur(cfg.ban_seconds)}")
    if cfg.subnet_enabled:
        print(f"  subnet: /{cfg.prefix[4]} (v6 /{cfg.prefix[6]}) after {cfg.subnet_min_hosts} "
              f"banned hosts within {fmt_dur(cfg.subnet_window)} -> ban "
              f"{fmt_dur(cfg.subnet_ban_seconds)}")
    print(f"  ports: {','.join(map(str, cfg.ports))}   ipv6: {cfg.ipv6}")
    print(f"  allowlist: {', '.join(map(str, cfg.allowlist))}")
    print("  log files:")
    for pattern in cfg.log_files:
        paths = sorted(p for p in glob.glob(pattern) if os.path.isfile(p))
        if not paths:
            print(f"    {pattern}: no match" + ("" if os.geteuid() == 0 else " (run as root?)"))
        for p in paths:
            print(f"    {p}")
    try:
        Inotify()
        print("  inotify: available")
    except (OSError, AttributeError) as e:
        print(f"  inotify: unavailable ({e}), will poll")


def main():
    ap = argparse.ArgumentParser(prog="www-blocker",
                                 description="Ban hosts that hammer Apache with bad requests.")
    ap.add_argument("-c", "--config", default=DEFAULT_CONFIG, help="config file (default: %(default)s)")
    ap.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("run", help="follow the logs and ban (used by systemd)")
    p.add_argument("--dry-run", action="store_true", help="only log WOULD BAN, overrides the config")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("simulate", help="replay old logs and report what would have been banned")
    p.add_argument("logs", nargs="+", help="access log files (.gz ok)")
    p.add_argument("--threshold", type=int, help="override detect.threshold")
    p.add_argument("--window", type=float, help="override detect.window (seconds)")
    p.add_argument("--ban-minutes", type=float, help="override detect.ban_minutes")
    p.add_argument("--min-hosts", type=int, help="override subnet.min_hosts")
    p.add_argument("--no-subnet", action="store_true", help="disable subnet bans")
    p.add_argument("--all", action="store_true", help="print every ban event")
    p.add_argument("--near", action="store_true", help="also list the top error sources")
    p.set_defaults(func=cmd_simulate)

    sub.add_parser("list", help="show active bans").set_defaults(func=cmd_list)

    p = sub.add_parser("ban", help="ban an IP or CIDR by hand")
    p.add_argument("addr")
    p.add_argument("-m", "--minutes", type=float, help="duration (default from config)")
    p.add_argument("--force", action="store_true", help="ban even if it overlaps the allowlist")
    p.set_defaults(func=cmd_ban)

    p = sub.add_parser("unban", help="lift a ban")
    p.add_argument("addr")
    p.set_defaults(func=cmd_unban)

    sub.add_parser("flush", help="lift all bans").set_defaults(func=cmd_flush)
    sub.add_parser("check", help="validate config, show watched files").set_defaults(func=cmd_check)

    args = ap.parse_args()
    setup_logging(args.verbose)
    try:
        cfg = load_config(args.config)
        if args.cmd == "run":
            open_bans_log(cfg.bans_log, new_file=True)
        elif args.cmd in ("ban", "unban", "flush"):
            open_bans_log(cfg.bans_log, new_file=False)
        args.func(args, cfg)
    except ConfigError as e:
        sys.exit(f"www-blocker: config error: {e}")
    except FirewallError as e:
        sys.exit(f"www-blocker: firewall error: {e}")


class JournalFormatter(logging.Formatter):
    """Prefix syslog priorities so journalctl shows levels (and colours)."""

    PRIO = {logging.DEBUG: 7, logging.INFO: 6, logging.WARNING: 4, logging.ERROR: 3,
            logging.CRITICAL: 2}

    def format(self, record):
        return f"<{self.PRIO.get(record.levelno, 6)}>{super().format(record)}"


def open_bans_log(base, new_file):
    """Send ban events to <base>-YYYYMMDD-HHMMSS.log as well as the journal.

    Each start of the service begins a new file; <base>.log is a symlink to
    the current one, which the manual ban/unban/flush commands append to.
    """
    if not base:
        return
    link = base + ".log"
    try:
        if new_file:
            path = f"{base}-{time.strftime('%Y%m%d-%H%M%S')}.log"
            tmp = link + ".tmp"
            if os.path.lexists(tmp):
                os.unlink(tmp)
            os.symlink(os.path.basename(path), tmp)
            os.replace(tmp, link)
        elif os.path.exists(link):
            path = link
        else:
            return
        handler = logging.FileHandler(path)
    except OSError as e:
        log.warning("cannot write ban log %s: %s", link, e)
        return
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s", "%Y-%m-%d %H:%M:%S"))
    bans.addHandler(handler)
    if new_file:
        log.info("ban events also go to %s", path)


def setup_logging(verbose):
    handler = logging.StreamHandler(sys.stdout)
    if os.environ.get("JOURNAL_STREAM"):
        handler.setFormatter(JournalFormatter("%(message)s"))
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s",
                                               "%Y-%m-%d %H:%M:%S"))
    log.addHandler(handler)
    log.setLevel(logging.DEBUG if verbose else logging.INFO)


if __name__ == "__main__":
    main()
