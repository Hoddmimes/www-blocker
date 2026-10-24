I got tiered on all AI scrappers and other malicious clients hammering my HTTP server.
I kindly asked Claude to come up with a solution and 15 min later it was up and running.



# www-blocker

Follows the Apache access logs in real time and bans hosts that hammer the
server with bad requests (400/404). A host that gets `threshold` bad responses
within `window` seconds is banned for `ban_minutes`. When `min_hosts` hosts from
the same /24 have been banned within an hour, the whole /24 is banned.

## How it works

- **Following**: inotify wakes the program as soon as Apache writes a line.
  It handles logrotate (rename + new file, no lines lost) and picks up new
  `*access*log` files by itself. At startup it begins at the end of each log.
- **Blocking**: one ipset per family (`www-blocker4`, `www-blocker6`, type
  `hash:net`), each entry with its **own timeout**, plus one iptables rule:
  `INPUT tcp/80,443 match-set www-blocker4 -> WWW-BLOCKER (DROP)`.
  Only web ports are blocked - mail, VPN etc. are unaffected.
- **Expiry**: the kernel deletes an entry when its timeout runs out, also while
  the service is stopped. Nothing is removed on stop or crash; a restart begins
  counting from zero.
- If something wipes the rules (e.g. `iptblocker.sh` runs `iptables --flush`
  at boot), the service puts them back within 60 seconds.

## Files

| file | |
|---|---|
| `www-blocker.py` | the program (Python 3 standard library only) |
| `www-blocker.conf` | configuration (TOML, commented) |
| `bans.log` | ban log of the current run (symlink to `bans-<start time>.log`) |
| `www-blocker.service` | systemd unit, symlinked into `/etc/systemd/system` |

## Ban log

Every ban, expiry and removal goes to the journal and to a ban log file in
this directory. Each start of the service begins a new file,
`bans-YYYYMMDD-HHMMSS.log`; `bans.log` is a symlink to the current one.

```
2026-10-23 16:02:11 BAN 34.13.203.48 for 30m: 4 bad responses in 0s (last: "GET /login HTTP/1.1" 404, hoddmimes-access.log)
2026-10-23 16:32:15 EXPIRED 34.13.203.48 (banned 30m) - dropped 412 packets while banned
2026-10-23 16:40:02 REMOVED 34.13.203.48 (banned 30m): replaced by subnet ban 34.13.203.0/24 - dropped 3 packets
2026-10-23 16:45:20 REMOVED 1.2.3.4: unbanned by hand or flushed, 12m left - dropped 0 packets
```

The sets are compared every 10 seconds, so EXPIRED/REMOVED lines can be up to
10 s late. In dry-run the lines read `WOULD BAN` / `WOULD EXPIRE`.
Old files are never deleted by the program.

## Everyday use

```sh
sudo systemctl status www-blocker
journalctl -u www-blocker -f                 # live: BAN / WOULD BAN lines
sudo ./www-blocker.py list                   # active bans, time left, dropped packets
sudo ./www-blocker.py unban 1.2.3.4
sudo ./www-blocker.py ban 1.2.3.0/24 -m 600  # manual ban, 10 hours
sudo ./www-blocker.py flush                  # lift all bans
sudo systemctl kill -s USR1 www-blocker      # log statistics now
```

## Dry run and going live

`dry_run = true` in the config logs `WOULD BAN ...` and touches nothing.
To start blocking set `dry_run = false` and run `sudo systemctl reload
www-blocker` (reload applies any config change without a restart).

## Tuning against real traffic

Replay old logs (rotated and `.gz` work) through the detector:

```sh
sudo ./www-blocker.py simulate /var/log/httpd/hoddmimes-access.log*
sudo ./www-blocker.py simulate --threshold 10 --window 30 --near /var/log/httpd/*access*log
```

It reports how much would have been dropped, every ban, and banned addresses
that *also* received successful pages (possible false positives).

## Install / uninstall

```sh
sudo ln -sf /usr/local/www-blocker/www-blocker.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now www-blocker

# uninstall
sudo systemctl disable --now www-blocker && sudo rm /etc/systemd/system/www-blocker.service
sudo iptables -D INPUT $(sudo iptables -S INPUT | grep -- '-j WWW-BLOCKER' | cut -d' ' -f3-)
sudo iptables -F WWW-BLOCKER && sudo iptables -X WWW-BLOCKER && sudo ipset destroy www-blocker4
# (same for ip6tables / www-blocker6)
```
