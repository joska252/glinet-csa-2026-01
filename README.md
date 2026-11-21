<div align="center">

<img src="images/logo.svg" width="300" alt="A seal resting on a patched-up router">

## gl-helper Triage for GL.iNet Routers and KVMs

**Check a device for the malware from GL.iNet's security notice of 20 November 2026, save the evidence, then clean up.**

[![Advisory CSA-2026-01](https://img.shields.io/badge/Advisory-CSA--2026--01-b3261e?style=for-the-badge)](https://gl-i.net/security/csa-2026-01/) [![Guide](https://img.shields.io/badge/Guide-gl--i.net-16774c?style=for-the-badge)](https://gl-i.net/security/csa-2026-01/fix/) [![License](https://img.shields.io/github/license/admonstrator/glinet-csa-2026-01?style=for-the-badge)](LICENSE) [![Last Commit](https://img.shields.io/github/last-commit/admonstrator/glinet-csa-2026-01?style=for-the-badge&logo=github)](https://github.com/admonstrator/glinet-csa-2026-01/commits) [![Issues](https://img.shields.io/github/issues/admonstrator/glinet-csa-2026-01?style=for-the-badge&logo=github)](https://github.com/admonstrator/glinet-csa-2026-01/issues) [![Stars](https://img.shields.io/github/stars/admonstrator/glinet-csa-2026-01?style=for-the-badge&logo=github)](https://github.com/admonstrator/glinet-csa-2026-01/stargazers)

</div>

---

> [!WARNING]
> **Community work, not an official GL.iNet tool.** GL.iNet has not reviewed or endorsed it.
> It finds and removes only the indicators we know of, and it **does not replace the factory
> reset** GL.iNet recommends. Use it at your own risk.

---

## 📖 About

On 20 November 2026 GL.iNet published a [security notice](https://www.gl-inet.com/blogs/blog/glinet-security-notice-2026-11-20):
its cloud remote management service had been abused to install malware on a subset of
GL.iNet routers and KVM devices. The community advisory is
[CSA-2026-01](https://gl-i.net/security/csa-2026-01/).

This repository contains a triage script for the implant known as "gl-helper". It runs on
GL.iNet KVMs (RM1 family, buildroot based) and on GL.iNet / OpenWrt routers.

By [Admon](https://forum.gl-inet.com/u/admon/) and the community: [RemoteToHome Consulting](https://remotetohome.io)
and users of GL.iNet's forum contributed findings and checks. See [Credits](#-credits).

> 🎖️ **Community Maintained** – Part of the [GL.iNet Toolbox](https://github.com/Admonstrator/glinet-toolbox) project  
> ⚠️ **Independent Project** – Not affiliated with GL.iNet

---

## ✨ Features

- 🔎 **Check** – Read-only detection of the known indicators of the implant
- 📦 **Archive** – Saves evidence before anything is changed. No archive, no changes.
- 🧹 **Fix** – Removes the known implant files and their persistence on request
- 🛡️ **Trusted tools** – Uses the busybox from the read-only base image, not the tools an attacker may have replaced
- 👀 **Review list** – Reports other unusual changes for a human to judge and never touches them
- 🖥️ **Routers and KVMs** – GL.iNet / OpenWrt routers and GL.iNet KVMs (RM1 family)

---

## 📋 Requirements

| Requirement | Details |
|-------------|---------|
| **Device** | GL.iNet KVM (RM1 family) or GL.iNet / OpenWrt router, with root SSH access |
| **On the device** | busybox `sh`/`ash` or bash, nothing to install |
| **On your computer** | Only for `triage-remote.sh`: Linux with bash, ssh, tar and sha256sum |

---

## 🔎 Indicators

The indicators come from the cleanup GL.iNet shipped in RM1PE firmware **1.10.2**
(`/etc/init.d/S08overlayfs`, built 2026-11-21). At boot it scrubs the writable overlay
layer when one of these marker files exists:

| Marker files (any one triggers) | Persistence removed together with them |
|---|---|
| `/etc/glinet/.cache/gl-helper` | `/etc/glinet/.cache/` |
| `/etc/glinet/.cache/gb` | `/etc/config/.gl/` |
| `/etc/config/.gl/gl-helper` | `/etc/rc.local` |
| `/etc/config/.gl/gb` | `/etc/crontabs/root` |
| | `/usr/bin/netstat` (a replaced, trojanized netstat) |

The vendor cleanup only runs when a marker file is present and only touches this set.
This script also detects:

- busybox/coreutils applets in the overlay that were replaced by a foreign regular file
  (for example `netstat`), unless a package (apk/opkg) installed the file,
- running processes started from implant paths or from a replaced applet,
- autostart and config files that reference implant paths: crontabs, `rc.local`, init
  scripts, hotplug, profile, and **sysupgrade keep lists** (an entry there makes the
  implant survive a firmware update with "keep settings"),
- implant persistence even when the marker files were deleted.

### Running processes

On 2026-11-21 GL.iNet posted a [quick check for routers](https://forum.gl-inet.com/t/quickly-check-if-your-router-is-under-attack/73070):
a router is under attack when `ps | grep tmp` shows a process `crond -i /tmp/.log`. The
script runs the same check and reports the process as `IOC`.

There are three reports of a remote root shell on GL-AXT1800 routers (firmware 4.8.3):
two from forum users (kosrkosr and TakashiSasaki) and one from
[RemoteToHome Consulting](https://github.com/RemoteToHome-io/gl-security-incident-2026), found on one of its own routers. It is a loop around a
pipe at `/tmp/f` that connects `/bin/sh -i` through `nc` to `170.39.226.219`, on a
different port each time. Where it was measured, the shell started at about 21:40 UTC on
2026-11-20. GL.iNet's indicator process was not running on RemoteToHome's router.

RemoteToHome read the code of the GoodCloud client taken from that router
(`gl-sdk4-cloud`): a cloud command for SD-WAN IP mapping puts an address into an
`iptables` command without checking it. It reports that this runs whether or not
AstroWarp is enabled, and that the same code is in the 4.8.4 beta for the GL-AXT1800 and
in GL-MT3000 4.11.0. GL.iNet has not confirmed this analysis. See
[RemoteToHome's write-up](https://github.com/RemoteToHome-io/gl-security-incident-2026/blob/main/docs/router-reverse-shell.md). GL.iNet staff [recommends checking for it](https://forum.gl-inet.com/t/quickly-check-if-your-router-is-under-attack/73070/32)
and says to treat a router with such a shell as compromised. The script reports as `IOC`:

- these processes, with the time they started,
- open connections to `170.39.226.0/24`,
- the pipe `/tmp/f`. It stays after the shell was stopped and only goes away at a
  restart, so it shows that the shell ran since the last boot. Its time is the last data
  that went through it. `--fix` removes it after the archive is written.

`/etc/mp_ip_mapping_info`, the state file that the cloud handler rewrites each time it
runs, is listed as `REVIEW` with its time. It is normal on a router that uses AstroWarp.

The same post adds two wider checks, which the script runs as well and reports as
`REVIEW`: processes that look like `nc`, `netcat`, `socat`, `/bin/sh -i` or `mkfifo`, and
established connections held by a shell or by such a tool. The post uses `netstat -tnp`
for the connections. The script reads the kernel's lists in `/proc/net/tcp` and `/proc/net/tcp6` instead,
because the implant is known to replace `netstat`.

The script also looks at where every running program comes from. A program started
from a RAM disk (`/tmp`, `/var`, `/run`) is in neither the base image nor the overlay, so
the file checks cannot see it. Such programs, and programs that are not in the base image
or differ from it, are listed as `REVIEW` (`INFO` when a package installed them). A script
that a shell from the base image runs, like the remote shell above, is not caught this
way; only the patterns above find it.

### Reports of a second implant

Users on r/GlInet describe further traces. GL.iNet has not confirmed them, and `--fix`
acts on every `IOC`, so the script reports them as `IOC` only when the content matches
the reports as well as the name. The name alone is `REVIEW`.

| Reported | `IOC` when | Otherwise |
|---|---|---|
| `/etc/glinet/.cache/watch.sh` (KVM, run every 3 minutes by a second cron daemon) | the file exists: it lies in the implant's own directory | |
| `/bin/ulogd`, a loader in Lua bytecode | not in the base image, not installed by a package, and it starts with the Lua bytecode header | `REVIEW` |
| `/usr/bin/monitord`, a copy of `/usr/bin/lua` | not in the base image, not installed by a package, and identical to `/usr/bin/lua` | `REVIEW` |
| lines added to `/etc/init.d/urandom_seed` | a line that the base image does not have names `/bin/ulogd` or `/usr/bin/monitord` | `REVIEW` when the file differs from the base image in any other way |
| `/bin/ulogd` and `/etc/init.d/urandom_seed` appended to `/lib/upgrade/keep.d/netifd` | a keep list has the line `/bin/ulogd` and the base image's does not | `REVIEW` when only the init script is kept |
| payload running from `/tmp` under the name `/usr/sbin/ujaild`, file deleted | a process named `ujaild` whose binary is in a RAM disk or deleted | `REVIEW` for the name on any other binary |
| relay `65.20.71.131`, port 5912 | never | `REVIEW` for an open connection to it |

`urandom_seed` and `keep.d/netifd` belong to packages of the firmware, and the review of
the overlay skips files that a package owns, so these two are compared with the base
image directly. `--fix` removes the two files, puts `urandom_seed` back from the base
image and takes the two lines out of the keep list. It does nothing about the connection
to the relay. The domain `gl-inet[.]top` from the same reports is not checked.

All of this compares with `/rom`. If the base image itself was changed, as one report
claims is possible, these checks do not see it.

### Firewall

The running firewall rules are generated from configuration when the firewall starts, so
no single rule "comes from the firmware". What the script compares with the firmware
image is that configuration (`/etc/config/firewall`, `/etc/firewall.user`,
`/etc/nftables.d/` and similar): every file that differs is a `REVIEW` finding, and the
lines that are not in the image are printed under "Firewall". Your own port forwards and
rules show up there too.

From the running rules the report prints the ones that redirect traffic (`DNAT`,
`REDIRECT` and the chain `SDWAN_IP_MAPPING`). The complete rule set (`iptables-save`,
`nft list ruleset`) goes into the evidence archive. A rule in `SDWAN_IP_MAPPING` that
redirects `127.0.0.1` to `127.0.0.1` is what the command of the user-reported remote
shell leaves behind; the script reports it as `IOC` and `--fix` deletes it.

The process and rule checks show what is running **right now**. `/tmp` is RAM: after a restart these
traces are gone, and a clean result does not show that a device was never compromised.
`--fix` stops the processes. It cannot tell what started them.

It also lists other overlay changes as `REVIEW` for a human to judge: new or modified
binaries, new init scripts, `authorized_keys`, extra uid 0 accounts, hidden files and
processes running from deleted binaries.

> ⚠️ **Do not run `netstat` on a device you suspect.** It may be the implant's replacement,
> and GL.iNet staff [says](https://forum.gl-inet.com/t/quickly-check-if-your-router-is-under-attack/73070/41)
> that running the replacement starts the malware. The script never calls it and uses the
> busybox from the read-only base image (`/rom`) for its own tools.

---

## 🚀 Quick Start

Run the check on the device (SSH as root), without cloning the repository:

```bash
curl -fsSL https://app.gl-i.net/csa-2026-01-fix -o gl-helper-triage.sh ; sh gl-helper-triage.sh
```

This only reads. It changes nothing and prints a report.

> ⚠️ **Read the script before you run it.** It runs as root on a device you suspect is compromised.

If the report shows indicators, save the evidence and then clean up:

```bash
sh gl-helper-triage.sh --archive
```

```bash
sh gl-helper-triage.sh --fix
```

`--fix` writes the evidence archive first and aborts if that fails. On the device `/tmp`
is RAM: copy the archive to your computer before you reboot.

### From Your Computer

`triage-remote.sh` runs the check over SSH, streams the evidence archive to `./evidence/`
on your computer, verifies it and only then runs `--fix`. It needs Linux with bash, ssh,
tar and sha256sum. Several devices can be given at once.

```bash
git clone https://github.com/admonstrator/glinet-csa-2026-01.git
cd glinet-csa-2026-01
./triage-remote.sh root@192.168.8.1          # check + pull the evidence archive
./triage-remote.sh --fix root@192.168.8.1    # also remediate if indicators are found
```

Or pipe the script through SSH yourself, so nothing is stored on the device:

```bash
ssh root@DEVICE 'sh -s -- --check' < gl-helper-triage.sh
ssh root@DEVICE 'sh -s -- --archive --stdout' < gl-helper-triage.sh > evidence.tar.gz
ssh root@DEVICE 'sh -s -- --fix' < gl-helper-triage.sh
```

---

## 🎛️ Modes

| Option | Effect |
|---|---|
| `--check` (default) | Read-only detection and report |
| `--archive [-o DIR]` | Report plus evidence archive in `DIR` (default `/tmp`) |
| `--archive --stdout` | Evidence archive to stdout, log to stderr |
| `--with-secrets` | Keep private keys (SSH, VPN) in the archive. By default they are left out; `/etc/shadow` is never included. |
| `--fix [-o DIR]` | Archive first (aborts if that fails), then remediate and re-check |
| `--report`, `--no-report`, `--show-report` | Send the anonymous report without asking, never offer it, or print it without sending. See below. |
| `--no-device-id` | Leave the device ID out of the report. |
| `--color`, `--no-color` | Force or disable coloured output. By default colours are used only on a terminal; `NO_COLOR=1` also turns them off. |

Exit codes: `0` clean, `1` indicators found, `2` fixed and clean, `3` fix incomplete,
`4` error.

The head of the report appears at once. While the checks run, a line shows which of the
nine steps is in progress. The report groups its findings by label and ends with a summary and a verdict. The copy
in the evidence archive is always plain text.

Findings are labeled:

- `IOC`: a known indicator. `--fix` removes it.
- `PERSIST`: `rc.local` or root crontab in the overlay without an implant reference.
  `--fix` resets it only when an IOC was found, like the vendor cleanup.
- `REVIEW`: unusual change. Archived and reported, never modified.
- `INFO`: context, for example files installed by a package.

Below the findings the report lists, under "Credentials on this device", the keys and VPN
profiles stored on the device: root's SSH client keys with their fingerprint, WireGuard
and AmneziaWG private keys of the GL.iNet client and server, OpenVPN client profiles,
the ZeroTier identity and the Tailscale state. It shows names
and counts, never the content. These are not findings: they are listed with or without
indicators and are never part of the anonymous report. Other passwords and tokens in the
configuration are not listed.

---

## 📮 Anonymous Report

At the end of a run the script offers to send a short report to the community, so that
we can see which models and firmware versions were hit and when. It offers this on a
device without indicators too: those reports show which devices were not hit. At the end of its
run it says in a few lines what the report contains and sends it only after you answer
`y`; `v` shows the complete report first. Without a terminal (for example through
`ssh ... 'sh -s'`) it never sends on its own; add `--report` to send. `--show-report`
prints the complete report and sends nothing, `--no-report` switches the offer off.

The report contains: script version, platform, model, firmware version, time of the
check, uptime, the number of findings per label, the kind and path of each `IOC` and
`PERSIST` finding, whether GL.iNet's quick check hit, and for the reported remote shell
its start time, the remote port and the time of its pipe. For the implant's own files and
for replaced system tools it adds the SHA-256, size and two times of the file: when it
was last written (mtime) and when the kernel last changed its entry (ctime). The first
can come with the file, from an archive or a copy, or be set back with `touch`; the second
cannot, so the two together show when the file really arrived. It also gives the time of
the cloud handler's state file.

When indicators were found, it also contains what the attacker left, as text:

- `/etc/rc.local` in full when it was changed (up to 60 lines), because what stands around
  the attacker's line matters too. From the other changed autostart files (the root
  crontab, init scripts that start the implant) the lines that are not in the firmware
  image, up to 20 per file. From the lists of files a firmware update keeps, only the
  lines that name the implant.
- the rules of the firewall chain `SDWAN_IP_MAPPING`, which the reported attack writes to,
- the command lines of the implant's and the remote shell's processes.

**Your own lines in those files are part of this**, for example a line you added to
`rc.local` or the crontab. The script always prints these lines word for word before it
asks. Read them, and answer `n` if one of them is a password or token.

The report carries a **device ID**, so that several reports from one device count once.
It is a hash of the hardware address of the first network interface; the address itself
never leaves the device. A plain hash of such an address could be reversed by trying all
addresses, so the server does not store it either: it hashes it again with a secret that
only the server has, and keeps a short form of that. `--no-device-id` leaves the ID out.
The ID makes the report pseudonymous rather than fully anonymous: two reports from the
same device can be linked to each other, but not to you.

It does not contain the host name, IP or MAC addresses, or any other file. `REVIEW` findings are only counted.
The receiving [worker](worker/) stores no IP address.

---

## 🧹 What `--fix` Does

1. Writes and verifies the evidence archive. No archive, no changes.
2. Stops implant processes (SIGSTOP all, then SIGKILL).
3. Removes `/etc/glinet/.cache/` and `/etc/config/.gl/`.
4. Resets `rc.local` and the root crontab to the base image version, or removes them
   if the base image has none. The previous versions are in the archive.
5. Restores replaced applets from the base image and removes other autostart files that
   start the implant, including OpenWrt `rc.d` links to removed init scripts.
6. Removes only the implant lines from sysupgrade keep lists.
7. Deletes the firewall rule that the command of the user-reported remote shell left
   behind. Other firewall rules and the firewall configuration are not changed.
8. Restarts cron and checks again.

Changes go through the merged root filesystem, so the overlay stays consistent while it
is mounted. `REVIEW` items are never touched.

---

## 📦 Evidence Archive

`gl-triage-<host>-<time>.tar.gz` contains the report, the findings, a listing and
SHA-256 hashes of the whole overlay upper layer, a full copy of the upper layer (up to
64 MiB), copies of all finding paths, process list with socket owners, decoded TCP
connections, the firewall rules and configuration, `/proc/<pid>/` data and the binary of implant processes, kernel and system
logs, and a `MANIFEST.sha256`.

> ⚠️ **The archive contains device configuration, possibly including Wi-Fi keys and
> other secrets.** Treat it as sensitive and do not post it publicly.

Password hashes are not included: `/etc/shadow` is taken out of every copy, and the archive
only records whether a hash differs from the base image.

Private keys are left out as well, unless you run with `--with-secrets`: root's SSH client
keys (`/root/.ssh/id_*`), dropbear's host keys, OpenVPN profiles, the ZeroTier identity and
the Tailscale state file are removed from the copies, and in `/etc/config/wireguard`,
`wireguard_server` and `zerotier` only the values of `private_key`, `preshared_key` and
`secret` are replaced, so an added peer is still visible. `REDACTED.txt` in the archive
lists what was left out, and the SHA-256 of the original files stays in
`overlay/upper-sha256.txt`. Other passwords in the configuration (Wi-Fi, PPPoE, DDNS) are
not looked for and stay in.

On the device `/tmp` is RAM. Copy the archive off the device before rebooting.

---

## ✅ After Triage

- Keep the evidence archive. Run the triage **before** you restart, reset or update:
  some traces live only in memory, and the RM1PE 1.10.2 cleanup deletes the implant's
  files at boot without keeping a copy.
- KVM: install GL.iNet's security firmware. Only RM1PE 1.10.2 runs the vendor cleanup;
  the builds for RM1 and RM1V2 do not. On an RM1, an update that keeps settings carries
  over the password file, the SSH keys and everything under `/etc/kvmd/user`
  (found by RemoteToHome): change them and look for keys and scripts you did not add.
- Router: update **without keeping settings**. OpenWrt keeps `/etc/config` across a
  sysupgrade, and the implant hides in `/etc/config/.gl`.
- A factory reset wipes the whole overlay and is the safe option on both.
- Check the computer attached to a KVM, and the clients behind a router.
- Change the device password, the GL.iNet cloud account password and SSH keys.
- If the device was hit, everything it held a key for is exposed as well. Remove the
  router's VPN profile on the server or with the VPN provider and create a new one,
  and remove the router's SSH keys from every machine that trusts them.
  The report lists the keys and profiles it found under "Credentials on this device".
  [RemoteToHome's recovery steps](https://github.com/RemoteToHome-io/gl-security-incident-2026#if-you-find-something) go through each kind of VPN.
- Until GL.iNet's security firmware is installed, consider switching GoodCloud off on
  the device. [RemoteToHome](https://github.com/RemoteToHome-io/gl-security-incident-2026#reducing-exposure-until-fixed-firmware-is-installed)
  shows how and what it costs you.

---

## 🧬 Firmware Notes

From the firmware images we compared (1.10.1 vs 1.10.2; both 1.10.2 builds are from 2026-11-21):

- **RM1PE 1.10.2** contains the boot cleanup in `/etc/init.d/S08overlayfs`.
- **RM1V2 1.10.2** does not contain it. Its `S08overlayfs` is unchanged.
- **RM1 1.10.2** does not contain it either, as [RemoteToHome found](https://github.com/RemoteToHome-io/gl-security-incident-2026/blob/main/docs/kvm-firmware.md).
  Their page also covers what an RM1 update keeps and that it leaves SSH switched off.
- Both 1.10.2 builds change `rtty` (the cloud remote terminal): the `-s`, `-C/--cacert`
  and `-x/--insecure` options are gone, the CA path `/var/run/gl-rtty/ca.crt` is built
  in, and `S99rtty` no longer reads a `tls` setting from the cloud-provided config.

---

## 🧪 Tests

The tests mount real overlay filesystems in an unprivileged user namespace, plant an
infection and run check, archive and fix:

```sh
unshare -rm bash tests/run-tests.sh
KVM_LOWER=/path/to/extracted/rm1pe-1.10.2/rootfs unshare -rm bash tests/run-tests.sh
```

Without `KVM_LOWER` only the OpenWrt scenarios run (synthetic base image). The script
was also run in check and archive mode on a GL.iNet router with firmware 4.11
(OpenWrt 25.12).

---

## 🚧 Limitations

- Only known indicators are remediated. A different implant variant, or other changes
  an attacker made, may remain. Read the `REVIEW` items.
- Without a read-only base image (`/rom`) the results are less precise and the tools come
  from `$PATH`.
- The script cannot see anything outside the device, such as changes on an attached
  computer or on the cloud account.

---

## 💡 Getting Help

- 📘 [Guide on gl-i.net](https://gl-i.net/security/csa-2026-01/fix/) – The steps on one page
- 🛡️ [Advisory CSA-2026-01 on gl-i.net](https://gl-i.net/security/csa-2026-01/) – What happened and what GL.iNet recommends
- 💬 [GL.iNet's notice in the forum](https://forum.gl-inet.com/t/2026-11-20-gl-inet-security-notice-goodcloud-kvm-routers/73056) – Discussion and updates from GL.iNet
- 🔬 [RemoteToHome's findings on the incident](https://github.com/RemoteToHome-io/gl-security-incident-2026) – How the remote shell got in, the KVM firmware, how to recover
- 🐛 [Report issues on GitHub](https://github.com/admonstrator/glinet-csa-2026-01/issues) – Bugs and false positives. Never attach an evidence archive.
- 📧 GL.iNet support (support@gl-inet.com) – If you are not sure whether your device is affected

---

## 👥 Credits

This is community work, and not one person's.

- [RemoteToHome Consulting](https://remotetohome.io) – The [analysis of the remote shell](https://github.com/RemoteToHome-io/gl-security-incident-2026/blob/main/docs/router-reverse-shell.md)
  and its cause in the GoodCloud client, the [KVM firmware findings](https://github.com/RemoteToHome-io/gl-security-incident-2026/blob/main/docs/kvm-firmware.md),
  the [recovery steps](https://github.com/RemoteToHome-io/gl-security-incident-2026#if-you-find-something), the look at the attacker's address,
  and [how to read the real firmware build](https://remotetohome.io/blog/glinet-router-firmware-versions/),
  which the report uses. Their [findings list](https://github.com/RemoteToHome-io/gl-security-incident-2026/blob/main/docs/findings.md) says for
  every item how it was checked.
- kosrkosr and TakashiSasaki – The first two reports of the remote shell in GL.iNet's forum
- AdamK – The connection and process checks
- Everyone who sent an anonymous report or posted their output in the forum

---

## ⚠️ Disclaimer

This script is provided **as-is** without any warranty. Use it at your own risk.

It changes files on your device when you run it with `--fix`. It is a stopgap: it cannot
prove that a device is clean, and a factory reset is still recommended.

In a business network, talk to your cyber insurer or incident response provider before you
change or reset the device.

---

## 📜 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

---

<div align="center">

## 🧰 Part of the GL.iNet Toolbox

[![GL.iNet Toolbox](https://img.shields.io/badge/🧰_GL.iNet_Toolbox-Explore_All_Tools-blue?style=for-the-badge)](https://github.com/Admonstrator/glinet-toolbox)

**Made with ❤️ by [Admon](https://github.com/Admonstrator) and the GL.iNet community**

</div>
