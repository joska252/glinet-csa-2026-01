#!/bin/bash
# Tests for gl-helper-triage.sh on real overlayfs mounts inside an unprivileged user
# namespace (no root needed, Linux >= 5.11):
#
#   unshare -rm bash tests/run-tests.sh
#   KVM_LOWER=/path/to/extracted/rm1pe-1.10.2/rootfs unshare -rm bash tests/run-tests.sh
#
# The OpenWrt scenarios use a small synthetic base image. The KVM scenarios need the
# extracted rootfs of a GL.iNet KVM firmware (e.g. RM1PE 1.10.2) in KVM_LOWER.
set -u
T=$(cd "$(dirname "$0")/.." && pwd)/gl-helper-triage.sh
KVM_LOWER=${KVM_LOWER:-}
BASE=$(mktemp -d)
trap 'umount "$BASE"/*/m 2>/dev/null; rm -rf "$BASE"' EXIT
pass=0 fail=0
ok()  { echo "  PASS: $*"; pass=$((pass+1)); }
bad() { echo "  FAIL: $*"; fail=$((fail+1)); }
expect() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

mkscen() { # name lower
	local d=$BASE/$1
	mkdir -p "$d/u" "$d/w" "$d/m" "$d/out"
	mount -t overlay overlay -o "lowerdir=$2,upperdir=$d/u,workdir=$d/w" "$d/m"
	umount "$d/m"
	echo "$d"
}
mnt() { mount -t overlay overlay -o "lowerdir=$2,upperdir=$1/u,workdir=$1/w" "$1/m"; }
run() { # dir lower mode...
	local d=$1 lo=$2; shift 2
	sh "$T" --root "$d/m" --upper "$d/u" --lower "$lo" -o "$d/out" "$@"
}

# ------------------------------------------------------------ OpenWrt base image
OWL=$BASE/openwrt-rom
mkdir -p "$OWL"/{etc/init.d,etc/rc.d,bin,usr/bin,lib/apk/db,etc/crontabs}
echo "DISTRIB_ID='OpenWrt'" >"$OWL/etc/openwrt_release"
printf '# Put your custom commands here\nexit 0\n' >"$OWL/etc/rc.local"
printf '#!/bin/sh\n' >"$OWL/etc/init.d/cron"; printf '#!/bin/sh\n' >"$OWL/etc/init.d/dnsmasq"
printf 'root:x:0:0:root:/root:/bin/ash\ndaemon:*:1:1:daemon:/var:/bin/false\n' >"$OWL/etc/passwd"
echo dummy >"$OWL/bin/busybox"; ln -s busybox "$OWL/bin/netstat"; ln -s busybox "$OWL/bin/login"
mkdir -p "$OWL/etc/uci-defaults"; echo 'uci commit' >"$OWL/etc/uci-defaults/10_firstboot"
printf 'P:busybox\nF:bin\nR:busybox\n\n' >"$OWL/lib/apk/db/installed"
echo openwrt >"$OWL/etc/hostname"
printf '#!/bin/sh /etc/rc.common\nSTART=99\n' >"$OWL/etc/init.d/urandom_seed"
echo lua-interpreter >"$OWL/usr/bin/lua"
mkdir -p "$OWL/lib/upgrade/keep.d"; echo /etc/config/network >"$OWL/lib/upgrade/keep.d/netifd"

if [ -n "$KVM_LOWER" ]; then
echo "=== 1. KVM (RM1PE 1.10.2 base), infected"
D=$(mkscen kvm "$KVM_LOWER"); U=$D/u
mkdir -p "$U"/etc/glinet/.cache "$U"/etc/config/.gl "$U"/etc/crontabs "$U"/usr/bin "$U"/bin "$U"/root/.ssh "$U"/etc/init.d
printf '#!/bin/sh\nwhile :; do sleep 60; done\n' >"$U/etc/glinet/.cache/gl-helper"; chmod 755 "$U/etc/glinet/.cache/gl-helper"
echo payload >"$U/etc/glinet/.cache/gb"; echo payload >"$U/etc/config/.gl/gb"
echo '/etc/glinet/.cache/gl-helper &' >"$U/etc/rc.local"
echo '*/5 * * * * /etc/config/.gl/gb >/dev/null 2>&1' >"$U/etc/crontabs/root"
printf '#!/bin/sh\n# trojan netstat\n' >"$U/usr/bin/netstat"; chmod 755 "$U/usr/bin/netstat"
printf 'fake ls\n' >"$U/bin/ls"; chmod 755 "$U/bin/ls"
cp "$KVM_LOWER/usr/bin/wget" "$U/usr/bin/wget"; echo x >>"$U/usr/bin/wget"
echo 'ssh-ed25519 AAAA attacker' >"$U/root/.ssh/authorized_keys"
printf '#!/bin/sh\n/etc/glinet/.cache/gl-helper\n' >"$U/etc/init.d/S99update-helper"
{ cat "$KVM_LOWER/etc/passwd"; echo 'backdoor:x:0:0::/root:/bin/sh'; } >"$U/etc/passwd"
echo note >"$U/etc/.hidden-note"
cp -a "$KVM_LOWER/etc/hostname" "$U/etc/hostname" 2>/dev/null
mnt "$D" "$KVM_LOWER"
run "$D" "$KVM_LOWER" --check >"$D/check.txt"; rc=$?
cat "$D/check.txt"
expect "check exit 1 (infected)" '[ $rc = 1 ]'
expect "3 markers" '[ $(grep -c "^ *IOC  *marker" "$D/check.txt") = 3 ]'
expect "netstat + ls hijack" 'grep -q "applet-hijack *\/usr\/bin\/netstat" "$D/check.txt" && grep -q "applet-hijack *\/bin\/ls" "$D/check.txt"'
expect "rc.local + crontab + init script reference IOC" '[ $(grep -c "persist-ref" "$D/check.txt") = 3 ] && grep -q "persist-ref *\/etc\/init.d\/S99update-helper" "$D/check.txt"'
expect "wget = REVIEW modified-binary" 'grep -q "REVIEW  *modified-binary *\/usr\/bin\/wget" "$D/check.txt"'
expect "authorized_keys + hidden = REVIEW" 'grep -q "REVIEW  *new *\/root\/.ssh\/authorized_keys" "$D/check.txt" && grep -q "hidden-note" "$D/check.txt"'
expect "uid0 backdoor account" 'grep -A1 "uid0-account" "$D/check.txt" | grep -q backdoor'
expect "identical copy-up (hostname) ignored" '! grep -q "/etc/hostname" "$D/check.txt"'
run "$D" "$KVM_LOWER" --fix >"$D/fix.txt"; rc=$?
sed -n '/== Remediation/,$p' "$D/fix.txt"
expect "fix exit 2 (clean afterwards)" '[ $rc = 2 ]'
A=$(ls "$D"/out/gl-triage-*.tar.gz 2>/dev/null | head -1)
expect "archive exists + sha256 ok" '[ -n "$A" ] && (cd "$D/out" && sha256sum -c "${A##*/}.sha256" >/dev/null)'
expect "archive has implant + trojan netstat + crontab" 'tar -tzf "$A" | grep -q "files/upper/etc/glinet/.cache/gl-helper" && tar -tzf "$A" | grep -q "files/upper/usr/bin/netstat" && tar -tzf "$A" | grep -q "files/merged/etc/crontabs/root"'
expect "archive MANIFEST verifies" 'mkdir -p "$D/x" && tar -C "$D/x" -xzf "$A" && (cd "$D/x/evidence" && sha256sum -c MANIFEST.sha256 >/dev/null)'
expect "markers gone" '[ ! -e "$D/m/etc/glinet/.cache" ] && [ ! -e "$D/m/etc/config/.gl" ]'
expect "rc.local + crontab gone (not in base)" '[ ! -e "$D/m/etc/rc.local" ] && [ ! -e "$D/m/etc/crontabs/root" ]'
expect "netstat restored as busybox symlink" '[ -L "$D/m/usr/bin/netstat" ] && [ "$(readlink "$D/m/usr/bin/netstat")" = "$(readlink "$KVM_LOWER/usr/bin/netstat")" ]'
expect "ls restored as coreutils symlink" '[ -L "$D/m/bin/ls" ] && [ "$(readlink "$D/m/bin/ls")" = coreutils ]'
expect "implant init script removed" '[ ! -e "$D/m/etc/init.d/S99update-helper" ]'
expect "REVIEW items untouched (wget, keys)" '[ -f "$D/m/root/.ssh/authorized_keys" ] && ! cmp -s "$D/m/usr/bin/wget" "$KVM_LOWER/usr/bin/wget"'
run "$D" "$KVM_LOWER" --check >/dev/null; rc=$?
expect "re-check after fix: exit 0" '[ $rc = 0 ]'
umount "$D/m"
else
	echo "=== 1. KVM: skipped (set KVM_LOWER)"
fi

echo; echo "=== 2. OpenWrt router, infected"
D=$(mkscen owrt "$OWL"); U=$D/u
mkdir -p "$U"/etc/config/.gl "$U"/etc/crontabs "$U"/usr/bin "$U"/etc/rc.d "$U"/etc/init.d "$U"/etc/dropbear
echo x >"$U/etc/config/.gl/gl-helper"; echo x >"$U/etc/config/.gl/gb"
echo '0 3 * * * /etc/config/.gl/gl-helper' >"$U/etc/crontabs/root"
printf '/usr/bin/my-led-script\nexit 0\n' >"$U/etc/rc.local"
printf 'trojan\n' >"$U/usr/bin/netstat"; chmod 755 "$U/usr/bin/netstat"
ln -s ../init.d/dnsmasq "$U/etc/rc.d/S19dnsmasq"
printf '#!/bin/sh\n' >"$U/etc/init.d/gl-update"; ln -s ../init.d/gl-update "$U/etc/rc.d/S99gl-update"
echo key >"$U/etc/dropbear/dropbear_ed25519_host_key"
printf '/etc/my-own-file\n/etc/config/.gl/\n' >"$U/etc/sysupgrade.conf"
printf '#!/bin/sh /etc/rc.common\nstart() { /etc/config/.gl/gl-helper & }\n' >"$U/etc/init.d/glhelper"; ln -s ../init.d/glhelper "$U/etc/rc.d/S95glhelper"
mkdir -p "$U/bin"; ln -s /bin/busybox "$U/bin/login"
mnt "$D" "$OWL"
rm "$D/m/etc/uci-defaults/10_firstboot"   # overlay creates a whiteout, like OpenWrt after first boot
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
cat "$D/check.txt"
expect "whiteout really created" '[ -c "$U/etc/uci-defaults/10_firstboot" ]'
expect "whiteout (deleted uci-defaults) not reported" '! grep -q "10_firstboot" "$D/check.txt"'
expect "absolute vs relative symlink to busybox not reported" '! grep -q "/bin/login" "$D/check.txt"'
expect "check exit 1" '[ $rc = 1 ]'
expect "platform openwrt" 'grep -q "Platform  *openwrt" "$D/check.txt"'
expect "markers 2 + crontab + netstat + init script + keep list = 6 IOC" 'grep -q "Summary: IOC=6 " "$D/check.txt" && grep -q "keep-ref *\/etc\/sysupgrade.conf" "$D/check.txt"'
expect "custom rc.local = PERSIST (not IOC)" 'grep -q "PERSIST  *persistence *\/etc\/rc.local" "$D/check.txt"'
expect "known service link S19dnsmasq ignored" '! grep -q "S19dnsmasq" "$D/check.txt"'
expect "benign new service + rc.d link = REVIEW" 'grep -q "REVIEW  *new *\/etc\/rc.d\/S99gl-update" "$D/check.txt" && grep -q "REVIEW  *new *\/etc\/init.d\/gl-update" "$D/check.txt"'
expect "dropbear host key ignored" '! grep -q "host_key" "$D/check.txt"'
expect "recommendation warns about keep-settings" 'grep -q "WITHOUT keeping settings" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
sed -n '/== Remediation/,$p' "$D/fix.txt"
expect "fix exit 2" '[ $rc = 2 ]'
expect "rc.local restored to base content" 'cmp -s "$D/m/etc/rc.local" "$OWL/etc/rc.local"'
expect "netstat removed (not in base), /bin/netstat intact" '[ ! -e "$D/m/usr/bin/netstat" ] && [ -L "$D/m/bin/netstat" ]'
expect "crontab + .gl gone" '[ ! -e "$D/m/etc/crontabs/root" ] && [ ! -e "$D/m/etc/config/.gl" ]'
expect "implant service + its rc.d link removed, benign service kept" '[ ! -e "$D/m/etc/init.d/glhelper" ] && [ ! -L "$D/m/etc/rc.d/S95glhelper" ] && [ -f "$D/m/etc/init.d/gl-update" ] && [ -L "$D/m/etc/rc.d/S99gl-update" ] && [ -L "$D/m/etc/rc.d/S19dnsmasq" ]'
expect "sysupgrade.conf: only implant line removed" 'grep -qx "/etc/my-own-file" "$D/m/etc/sysupgrade.conf" && ! grep -q "\.gl" "$D/m/etc/sysupgrade.conf"'
expect "custom rc.local kept in archive" 'tar -xzOf "$(ls "$D"/out/*.tar.gz)" evidence/files/merged/etc/rc.local | grep -q my-led-script'
umount "$D/m"

if [ -n "$KVM_LOWER" ]; then
echo; echo "=== 3. Variant without markers (vendor cleanup would miss it)"
D=$(mkscen nomark "$KVM_LOWER"); U=$D/u
mkdir -p "$U"/etc/crontabs "$U"/usr/bin
echo '*/5 * * * * /etc/config/.gl/gb' >"$U/etc/crontabs/root"
printf 'trojan\n' >"$U/usr/bin/netstat"
mnt "$D" "$KVM_LOWER"
run "$D" "$KVM_LOWER" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|PERSIST|REVIEW|INFO) |Summary|Verdict' "$D/check.txt"
expect "detected without markers (exit 1, IOC=2)" '[ $rc = 1 ] && grep -q "Summary: IOC=2 " "$D/check.txt"'
run "$D" "$KVM_LOWER" --fix >/dev/null; rc=$?
expect "fixed (exit 2)" '[ $rc = 2 ] && [ ! -e "$D/m/etc/crontabs/root" ] && [ -L "$D/m/usr/bin/netstat" ]'
umount "$D/m"

echo; echo "=== 4. Clean KVM"
D=$(mkscen clean "$KVM_LOWER"); mnt "$D" "$KVM_LOWER"
run "$D" "$KVM_LOWER" --check >"$D/check.txt"; rc=$?
grep -E 'Summary|Verdict' "$D/check.txt"
expect "clean: exit 0, IOC=0" '[ $rc = 0 ] && grep -q "Summary: IOC=0 " "$D/check.txt"'
run "$D" "$KVM_LOWER" --fix >"$D/fix.txt"; rc=$?
expect "fix on clean device changes nothing, exit 0" '[ $rc = 0 ] && grep -q "nothing to remediate" "$D/fix.txt" && [ -z "$(ls -A "$D/u")" ]'
run "$D" "$KVM_LOWER" --archive --stdout >"$D/stdout.tar.gz" 2>"$D/stdout.log"; rc=$?
expect "--archive --stdout gives valid tar.gz, log on stderr" '[ $rc = 0 ] && tar -tzf "$D/stdout.tar.gz" | grep -q evidence/report.txt && grep -q "Verdict" "$D/stdout.log"'
umount "$D/m"
else
	echo "=== 3./4. KVM: skipped (set KVM_LOWER)"
fi

echo; echo "=== 5. OpenWrt, netstat installed by a package (apk) -> INFO only"
D=$(mkscen pkg "$OWL"); U=$D/u
mkdir -p "$U/usr/bin" "$U/lib/apk/db"
printf 'real netstat\n' >"$U/usr/bin/netstat"
{ cat "$OWL/lib/apk/db/installed"; printf 'P:net-tools-netstat\nF:usr/bin\nR:netstat\n\n'; } >"$U/lib/apk/db/installed"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|PERSIST|REVIEW|INFO) |Summary' "$D/check.txt"
expect "package netstat is INFO, exit 0" '[ $rc = 0 ] && grep -q "installed by package net-tools-netstat" "$D/check.txt"'
umount "$D/m"

echo; echo "=== 6. OpenWrt with opkg (firmware 4.x), netstat installed by a package -> INFO only"
OWO=$BASE/openwrt-rom-opkg
cp -a "$OWL" "$OWO"; rm -rf "$OWO/lib/apk"; mkdir -p "$OWO/usr/lib/opkg/info"
D=$(mkscen opkg "$OWO"); U=$D/u
mkdir -p "$U/usr/bin" "$U/usr/lib/opkg/info"
printf 'real netstat\n' >"$U/usr/bin/netstat"
printf '/usr/bin/netstat\n' >"$U/usr/lib/opkg/info/net-tools-netstat.list"
mnt "$D" "$OWO"
run "$D" "$OWO" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|PERSIST|REVIEW|INFO) |Summary' "$D/check.txt"
expect "opkg package netstat is INFO, exit 0" '[ $rc = 0 ] && grep -q "installed by package net-tools-netstat" "$D/check.txt"'
expect "no stray heading in the report" '! grep -q -- "== -n" "$D/check.txt"'
umount "$D/m"

echo; echo "=== 7. OpenWrt, firewall config changed and a new nftables include"
mkdir -p "$OWL/etc/config"
printf "config defaults\n\toption input 'REJECT'\n" >"$OWL/etc/config/firewall"
D=$(mkscen fw "$OWL"); U=$D/u
mkdir -p "$U/etc/config" "$U/etc/nftables.d"
printf "config defaults\n\toption input 'REJECT'\n\nconfig redirect\n\toption name 'evil'\n\toption dest_ip '10.9.9.9'\n" >"$U/etc/config/firewall"
printf '# comment\nchain x { tcp dport 22 accept }\n' >"$U/etc/nftables.d/10-x.nft"
printf 'aa:bb:cc:dd:ee:ff 10.0.0.2 192.168.8.2\n' >"$U/etc/mp_ip_mapping_info"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
sed -n '/== Firewall/,/== Result/p' "$D/check.txt"
expect "changed firewall config = REVIEW with 3 new lines, exit 0" '[ $rc = 0 ] && grep -q "REVIEW  *fw-config  *\/etc\/config\/firewall" "$D/check.txt" && grep -q "3 lines that are not in it" "$D/check.txt"'
expect "new lines are listed, unchanged ones are not" 'grep -q "option dest_ip .10.9.9.9." "$D/check.txt" && ! grep -q "option input" "$D/check.txt"'
expect "new nftables include = REVIEW, comment not listed" 'grep -q "REVIEW  *fw-config  *\/etc\/nftables.d\/10-x.nft" "$D/check.txt" && grep -q "tcp dport 22 accept" "$D/check.txt" && ! grep -q "# comment" "$D/check.txt"'
expect "state file with entries = REVIEW with its time" 'grep -A1 "REVIEW  *state-file  *\/etc\/mp_ip_mapping_info" "$D/check.txt" | grep -q "written 20.* UTC, 39 bytes, AstroWarp off"'
run "$D" "$OWL" --archive >/dev/null
expect "firewall config is in the archive" 'tar -tzf "$(ls "$D"/out/*.tar.gz)" | grep -q "files/merged/etc/config/firewall"'
umount "$D/m"

echo; echo "=== 8. Pipe of the reported remote shell left in /tmp"
D=$(mkscen pipe "$OWL")
mnt "$D" "$OWL"
mkdir -p "$D/m/tmp"; mkfifo "$D/m/tmp/f"
# the owner's own autostart entries: this shell is not known to write files
echo '/usr/bin/my-watchdog &' >"$D/m/etc/rc.local"; echo '0 4 * * * /sbin/reboot' >"$D/m/etc/crontabs/root"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E -A1 '^ +IOC ' "$D/check.txt"
expect "pipe /tmp/f = IOC, exit 1" '[ $rc = 1 ] && grep -q "IOC  *pipe  *\/tmp\/f" "$D/check.txt" && grep -q "last data 20.* UTC" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "fix removes the pipe, exit 2" '[ $rc = 2 ] && [ ! -e "$D/m/tmp/f" ] && grep -q "removed the pipe" "$D/fix.txt"'
expect "fix leaves the owner's rc.local and crontab when only the shell's traces were found" 'grep -q my-watchdog "$D/m/etc/rc.local" && grep -q reboot "$D/m/etc/crontabs/root" && [ $(grep -c "left /etc/.* as it is" "$D/fix.txt") = 2 ]'
umount "$D/m"

echo; echo "=== 9. Stored SSH client keys and VPN credentials are listed, without their content"
C() { sed -n '/== Credentials/,/== Result/p' "$D/check.txt"; }   # the credentials section only
OWC=$BASE/openwrt-rom-creds
cp -a "$OWL" "$OWC"
# what the firmware ships without any secret: an empty ZeroTier secret, VPN configuration
# without keys, an empty ZeroTier directory (KVM)
mkdir -p "$OWC/etc/config" "$OWC/etc/kvmd/user/zerotier"
printf "config zerotier 'sample_config'\n\toption enabled '0'\n\toption secret ''\n" >"$OWC/etc/config/zerotier"
printf "config providers 'FromApp'\n\toption auth_type '1'\n" >"$OWC/etc/config/wireguard"
printf "config servers 'main_server'\n\toption port '51820'\n" >"$OWC/etc/config/wireguard_server"
printf '#!/bin/sh\necho "Public key portion is:"\necho "ssh-ed25519 AAAATESTPUB root@test"\necho "Fingerprint: SHA256:TESTFINGERPRINT"\n' >"$OWC/usr/bin/dropbearkey"; chmod 755 "$OWC/usr/bin/dropbearkey"
D=$(mkscen nocreds "$OWC")
mnt "$D" "$OWC"
run "$D" "$OWC" --check >"$D/check.txt"; rc=$?
expect "firmware defaults without secrets: no credentials section, exit 0" '[ $rc = 0 ] && ! grep -q "Credentials on this device" "$D/check.txt"'
umount "$D/m"

D=$(mkscen creds "$OWC"); U=$D/u
mkdir -p "$U/root/.ssh" "$U/etc/config" "$U/etc/openvpn/profiles/office/auth" "$U/etc/tailscale" "$U/etc/kvmd/user/zerotier" "$U/var/lib"
echo SECRETKEYDATA >"$U/root/.ssh/id_dropbear"; echo SECRETKEYDATA >"$U/root/.ssh/id_ed25519"
echo 'ssh-ed25519 AAAA root@test' >"$U/root/.ssh/id_ed25519.pub"
echo SECRETKEYDATA >"$U/root/.ssh/id_$(printf 'odd\tname')"
printf "config groups 'group_1'\n\toption private_key 'SECRETWGKEY1'\n\nconfig peers 'peer_2'\n\toption private_key 'SECRETWGKEY2'\n\nconfig peers 'peer_3'\n\toption group_id '1'\n" >"$U/etc/config/wireguard"
printf "config servers 'main_server'\n\toption private_key 'SECRETWGKEY3'\n" >"$U/etc/config/wireguard_server"
echo SECRETOVPN >"$U/etc/openvpn/profiles/office/a.ovpn"; echo SECRETOVPN >"$U/etc/openvpn/profiles/office/b.ovpn"
echo SECRETLOGIN >"$U/etc/openvpn/profiles/office/auth/username_password.txt"
printf "config zerotier 'gl'\n\toption enabled '1'\n\toption secret 'SECRETZTID'\n" >"$U/etc/config/zerotier"
echo SECRETZTID >"$U/etc/kvmd/user/zerotier/identity.secret"; ln -s ../../etc/kvmd/user/zerotier "$U/var/lib/zerotier-one"
echo SECRETSTATE >"$U/etc/tailscale/tailscaled.state"
mnt "$D" "$OWC"
run "$D" "$OWC" --check >"$D/check.txt"; rc=$?
C
expect "credentials alone are no indicator: exit 0, IOC=0 PERSIST=0" '[ $rc = 0 ] && grep -q "Summary: IOC=0 PERSIST=0 " "$D/check.txt"'
expect "three SSH client keys with fingerprint, .pub not listed" '[ $(C | grep -c "SSH client key") = 3 ] && C | grep -q "/root/.ssh/id_dropbear" && [ $(C | grep -c "SHA256:TESTFINGERPRINT") = 3 ] && ! C | grep -q "id_ed25519.pub"'
expect "a key name with a tab in it is printed with plain characters only" 'C | grep -q "/root/.ssh/id_odd?name$" && ! C | grep -q "$(printf "\\t")"'
expect "WireGuard: 2 client keys, 1 server key" 'C | grep -A1 "WireGuard client  */etc/config/wireguard$" | grep -q "2 private key" && C | grep -A1 "WireGuard server" | grep -q "1 private key"'
expect "OpenVPN: 2 client profiles" 'C | grep -A1 "OpenVPN client" | grep -q "2 profile"'
expect "ZeroTier identity listed once, from the configuration" '[ $(C | grep -c "^ *ZeroTier") = 1 ] && C | grep -q "ZeroTier  */etc/config/zerotier"'
expect "Tailscale state of the router" 'C | grep -q "Tailscale  */etc/tailscale/tailscaled.state"'
expect "no key content or public key anywhere in the output" '! grep -q "SECRET\|AAAATESTPUB" "$D/check.txt"'
expect "no advice to revoke without indicators" '! grep -q "listed above under" "$D/check.txt" && ! grep -q "treat all of these as copied" "$D/check.txt"'
mkdir -p "$D/m/tmp"; mkfifo "$D/m/tmp/f"
run "$D" "$OWC" --check >"$D/check2.txt"; rc=$?
expect "with an indicator: exit 1, the advice to revoke and a pointer to the list" '[ $rc = 1 ] && grep -q "treat all of these as copied" "$D/check2.txt" && grep -q "listed above under" "$D/check2.txt"'
umount "$D/m"

D=$(mkscen kvmcreds "$OWL"); U=$D/u
mkdir -p "$U/root/.ssh" "$U/etc/kvmd/user/zerotier" "$U/var/lib"
echo SECRETKEYDATA >"$U/root/.ssh/id_rsa"
echo SECRETZTID >"$U/etc/kvmd/user/zerotier/identity.secret"; ln -s ../../etc/kvmd/user/zerotier "$U/var/lib/zerotier-one"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
C
expect "KVM layout: identity file listed once" '[ $(C | grep -c "^ *ZeroTier") = 1 ] && C | grep -q "ZeroTier  */etc/kvmd/user/zerotier/identity.secret"'
expect "no dropbearkey in the base image: key listed without fingerprint" 'C | grep -A1 "SSH client key  */root/.ssh/id_rsa" | grep -q "fingerprint not available"'
umount "$D/m"

echo "=== older backdoor (urandom_seed / ulogd / monitord)"
backdoor() { # upper dir
	mkdir -p "$1/etc/init.d" "$1/bin" "$1/usr/bin" "$1/lib/upgrade/keep.d"
	printf '#!/bin/sh /etc/rc.common\ncp /usr/bin/lua /usr/bin/monitord\ncp /bin/ulogd /var/run/monitord.pid\n/usr/bin/monitord /var/run/monitord.pid &\nSTART=99\n' >"$1/etc/init.d/urandom_seed"
	echo bytecode >"$1/bin/ulogd"; echo lua-interpreter >"$1/usr/bin/monitord"
	printf '/etc/config/network\n/bin/ulogd\n/etc/init.d/urandom_seed\n' >"$1/lib/upgrade/keep.d/netifd"
}
D=$(mkscen bd "$OWL"); U=$D/u
backdoor "$U"
mkdir -p "$U/etc/AdGuardHome/data"; echo '{"QH":"up.adguardns.org"}' >"$U/etc/AdGuardHome/data/querylog.json"
echo '1.2.3.4 cdn.lede-openproject.org' >"$U/etc/hosts"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "backdoor only: exit 1 and its own verdict" '[ $rc = 1 ] && grep -q "Verdict: INFECTED - older backdoor" "$D/check.txt" && grep -q "no gl-helper indicators found" "$D/check.txt"'
expect "init script, loader, renamed Lua and keep list are IOC" 'grep -q "IOC  *backdoor-init  */etc/init.d/urandom_seed" "$D/check.txt" && grep -q "IOC  *backdoor-file  */bin/ulogd" "$D/check.txt" && grep -q "IOC  *backdoor-file  */usr/bin/monitord" "$D/check.txt" && grep -q "IOC  *backdoor-keep  */lib/upgrade/keep.d/netifd" "$D/check.txt"'
expect "server name in the configuration is IOC, in the query log REVIEW" 'grep -q "IOC  *backdoor-host  */etc/hosts" "$D/check.txt" && grep -q "REVIEW  *backdoor-dns" "$D/check.txt"'
expect "no second finding for the same path" '[ $(grep -c " /bin/ulogd$" "$D/check.txt") = 1 ] && [ $(grep -c " /etc/init.d/urandom_seed$" "$D/check.txt") = 1 ]'
expect "advice is a reflash without keeping settings" 'grep -q "keep settings.* OFF" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix changes nothing and says so: exit 1, files still there" '[ $rc = 1 ] && grep -q "does not remove the older backdoor" "$D/fix.txt" && [ -f "$D/m/bin/ulogd" ] && grep -q monitord "$D/m/etc/init.d/urandom_seed"'
expect "the loader is in the archive" 'tar -tzf "$(ls "$D"/out/*.tar.gz | head -n 1)" | grep -q "bin/ulogd"'
umount "$D/m"

D=$(mkscen bdboth "$OWL"); U=$D/u
backdoor "$U"
mkdir -p "$U/etc/config/.gl"; echo payload >"$U/etc/config/.gl/gl-helper"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"
expect "both: one verdict that names both" 'grep -q "Verdict: INFECTED - gl-helper indicators and the older backdoor" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "both: --fix removes gl-helper, leaves the backdoor, exit 3" '[ $rc = 3 ] && [ ! -e "$D/m/etc/config/.gl" ] && [ -f "$D/m/bin/ulogd" ] && grep -q "older backdoor is STILL THERE" "$D/fix.txt"'
umount "$D/m"

D=$(mkscen bdclean "$OWL"); U=$D/u
mkdir -p "$U/usr/sbin" "$U/etc/init.d" "$U/lib/apk/db" "$U/lib/upgrade/keep.d" "$U/usr/bin"
echo real >"$U/usr/sbin/ulogd"; printf '#!/bin/sh\n/usr/sbin/ulogd -d\n' >"$U/etc/init.d/ulogd"
printf 'P:busybox\nF:bin\nR:busybox\n\nP:ulogd\nF:usr/sbin\nR:ulogd\nF:etc/init.d\nR:ulogd\n\n' >"$U/lib/apk/db/installed"
echo /etc/my-own-file >"$U/lib/upgrade/keep.d/mine"; echo something-else >"$U/usr/bin/monitord"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "the ulogd package, an own keep list and another monitord are no indicator" '[ $rc = 0 ] && ! grep -q "backdoor-" "$D/check.txt"'
umount "$D/m"

echo "=== base files are package-owned too: a changed one must still be seen (issue 4)"
OWP=$BASE/openwrt-rom-pkg
cp -a "$OWL" "$OWP"
printf 'P:busybox\nF:bin\nR:busybox\n\nP:urandom-seed\nF:etc/init.d\nR:urandom_seed\n\nP:netifd\nF:lib/upgrade/keep.d\nR:netifd\nF:etc/init.d\nR:dnsmasq\n\n' >"$OWP/lib/apk/db/installed"
D=$(mkscen bdpkg "$OWP"); U=$D/u
backdoor "$U"
mkdir -p "$U/etc/glinet/.cache"; echo '#!/bin/sh' >"$U/etc/glinet/.cache/watch.sh"
printf '#!/bin/sh\n# my own change\n' >"$U/etc/init.d/dnsmasq"
mnt "$D" "$OWP"
run "$D" "$OWP" --check >"$D/check.txt"; rc=$?
expect "package-owned urandom_seed and keep list with the backdoor's lines are IOC" 'grep -q "IOC  *backdoor-init  */etc/init.d/urandom_seed" "$D/check.txt" && grep -q "IOC  *backdoor-keep  */lib/upgrade/keep.d/netifd" "$D/check.txt"'
expect "another changed package-owned base file is REVIEW, not skipped" 'grep -q "REVIEW  *changed  */etc/init.d/dnsmasq" "$D/check.txt"'
expect "watch.sh in the malware's directory is a marker" 'grep -q "IOC  *marker  */etc/glinet/.cache/watch.sh" "$D/check.txt"'
umount "$D/m"

echo "=== archive without secrets (issue 3)"
D=$(mkscen scrub "$OWL"); U=$D/u
mkdir -p "$U/root/.ssh" "$U/etc/config" "$U/etc/dropbear" "$U/etc/openvpn" "$U/tmp"
printf 'root:$1$SECRETHASH:19000:0:99999:7:::\n' >"$U/etc/shadow"
echo SECRETSSHKEY >"$U/root/.ssh/id_rsa"; echo 'ssh-ed25519 AAAAATTACKER evil' >"$U/root/.ssh/authorized_keys"
echo SECRETHOSTKEY >"$U/etc/dropbear/dropbear_rsa_host_key"; echo SECRETOVPN >"$U/etc/openvpn/client.ovpn"
printf "config peers\n\toption private_key 'SECRETWGKEY'\n\toption public_key 'PEERPUBLIC'\n\toption end_point '1.2.3.4:51820'\n" >"$U/etc/config/wireguard"
printf "config wifi-iface\n\toption ssid 'home'\n\toption key 'SECRETWIFI'\n" >"$U/etc/config/wireless"
mnt "$D" "$OWL"
run "$D" "$OWL" --archive >/dev/null; A=$(ls "$D"/out/*.tar.gz); mkdir "$D/x"; tar -xzf "$A" -C "$D/x"
expect "no password hash, private key, host key or VPN profile in the archive" '! grep -rq "SECRETHASH\|SECRETSSHKEY\|SECRETHOSTKEY\|SECRETOVPN" "$D/x"'
expect "key values replaced, the peer stays visible" '! grep -rq "SECRETWGKEY\|SECRETWIFI" "$D/x" && grep -rq "PEERPUBLIC" "$D/x/evidence/files" && grep -rq "1.2.3.4:51820" "$D/x/evidence/files" && grep -rq "option private_key .REDACTED." "$D/x/evidence/files"'
expect "authorized_keys is kept: an added key is evidence" 'grep -rq "AAAAATTACKER" "$D/x/evidence/files"'
expect "REDACTED.txt lists what was left out, and is in the manifest" 'grep -q "/etc/shadow" "$D/x/evidence/REDACTED.txt" && grep -q "/root/.ssh/id_rsa" "$D/x/evidence/REDACTED.txt" && grep -q "REDACTED.txt" "$D/x/evidence/MANIFEST.sha256"'
expect "shadow summary is written when the base image has no shadow file" 'grep -q "^root.*hash set" "$D/x/evidence/etc/shadow-summary.txt"'
expect "the device itself is untouched" 'grep -q SECRETSSHKEY "$D/m/root/.ssh/id_rsa" && grep -q SECRETHASH "$D/m/etc/shadow" && grep -q SECRETWGKEY "$D/m/etc/config/wireguard"'
rm -rf "$D/x" "$D"/out/*; run "$D" "$OWL" --archive --with-secrets >/dev/null; mkdir "$D/x"; tar -xzf "$(ls "$D"/out/*.tar.gz)" -C "$D/x"
expect "--with-secrets keeps keys, never the password hash" 'grep -rq SECRETSSHKEY "$D/x" && grep -rq SECRETWGKEY "$D/x" && ! grep -rq SECRETHASH "$D/x"'
umount "$D/m"

echo "=== the handler's empty state file: a command ran, also after a restart"
D=$(mkscen cmd "$OWL"); U=$D/u
mkdir -p "$U/etc/config"; : >"$U/etc/mp_ip_mapping_info"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "empty, written since the attack, AstroWarp off = IOC, verdict ATTACKED, exit 1" '[ $rc = 1 ] && grep -q "IOC  *cloud-command  */etc/mp_ip_mapping_info" "$D/check.txt" && grep -q "Verdict: ATTACKED" "$D/check.txt" && ! grep -q "Verdict: INFECTED" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix has nothing to remove, leaves the file, exit 1" '[ $rc = 1 ] && grep -q "Nothing to remove" "$D/fix.txt" && [ -f "$D/m/etc/mp_ip_mapping_info" ]'
touch -d '2026-10-01 12:00:00 UTC' "$D/m/etc/mp_ip_mapping_info"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "empty but written before the attack = REVIEW, exit 0" '[ $rc = 0 ] && grep -q "REVIEW  *state-file" "$D/check.txt"'
touch "$D/m/etc/mp_ip_mapping_info"; printf "config mptun 'global'\n\toption enable '1'\n" >"$D/m/etc/config/mptun"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "empty and recent, but AstroWarp is on = REVIEW, exit 0" '[ $rc = 0 ] && grep -q "REVIEW  *state-file.*" "$D/check.txt" && grep -q "AstroWarp on" "$D/check.txt"'
printf "config mptun 'global'\n\toption enable '0'\n\nconfig other 'x'\n\toption enable '1'\n" >"$D/m/etc/config/mptun"
mkdir -p "$D/m/etc/config/.gl"; echo payload >"$D/m/etc/config/.gl/gl-helper"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "with malware files as well the verdict is INFECTED, and enable in another section does not count" '[ $rc = 1 ] && grep -q "Verdict: INFECTED - gl-helper" "$D/check.txt" && grep -q "IOC  *cloud-command" "$D/check.txt"'
umount "$D/m"

echo "=== an updated program that replaces a link of the base image is no hijack"
OWT=$BASE/openwrt-rom-ts
cp -a "$OWL" "$OWT"; mkdir -p "$OWT/usr/sbin"; echo tailscaled >"$OWT/usr/sbin/tailscaled"; ln -s tailscaled "$OWT/usr/sbin/tailscale"
printf 'P:busybox\nF:bin\nR:busybox\n\nP:tailscale\nF:usr/sbin\nR:tailscale\nR:tailscaled\n\n' >"$OWT/lib/apk/db/installed"
D=$(mkscen ts "$OWT"); U=$D/u
mkdir -p "$U/usr/sbin" "$U/bin"; echo combined >"$U/usr/sbin/tailscale"; echo combined >"$U/usr/sbin/tailscaled"
mnt "$D" "$OWT"
run "$D" "$OWT" --check >"$D/check.txt"; rc=$?
expect "Tailscale's own binary over the base link = REVIEW, exit 0" '[ $rc = 0 ] && grep -q "REVIEW  *replaced-link  */usr/sbin/tailscale" "$D/check.txt" && ! grep -q "applet-hijack" "$D/check.txt"'
rm "$D/m/bin/login"; echo fake >"$D/m/bin/login"
run "$D" "$OWT" --check >"$D/check.txt"; rc=$?
expect "a file over a busybox link is still IOC" '[ $rc = 1 ] && grep -q "IOC  *applet-hijack  */bin/login" "$D/check.txt"'

echo; echo "=== the owner blocks the older backdoor's server names: not an indicator"
D=$(mkscen bdblock "$OWL"); U=$D/u
mkdir -p "$U/etc/dnsmasq.d" "$U/etc/config"
printf '127.0.0.1 localhost\n0.0.0.0 cdn.adguardns.com\n:: up.adguardns.org\n' >"$U/etc/hosts"
printf 'address=/lede-openproject.org/\nserver=/adxinsight.com/\naddress=/openwrt-project.org/0.0.0.0\n' >"$U/etc/dnsmasq.d/block.conf"
printf "config dnsmasq\n\tlist address '/adguardns.org/0.0.0.0'\n" >"$U/etc/config/dhcp"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E -A1 'backdoor' "$D/check.txt"
expect "block entries: exit 0, INFO, no IOC" '[ $rc = 0 ] && [ $(grep -c "INFO  *backdoor-block" "$D/check.txt") = 3 ] && ! grep -q "IOC  *backdoor" "$D/check.txt"'
umount "$D/m"
# a line that points the name somewhere else is still an indicator, block entries beside it or not
echo '203.0.113.7 cdn.adxinsight.com' >>"$U/etc/hosts"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "a name with a real address beside block entries = IOC, and only that name is listed" '[ $rc = 1 ] && grep -A1 "IOC  *backdoor-host  *\/etc\/hosts" "$D/check.txt" | grep -q "(cdn.adxinsight.com)"'
umount "$D/m"

echo; echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
