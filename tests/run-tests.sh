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
: >"$U/etc/mp_ip_mapping_info"
mnt "$D" "$OWL"
run "$D" "$OWL" --check >"$D/check.txt"; rc=$?
sed -n '/== Firewall/,/== Result/p' "$D/check.txt"
expect "changed firewall config = REVIEW with 3 new lines, exit 0" '[ $rc = 0 ] && grep -q "REVIEW  *fw-config  *\/etc\/config\/firewall" "$D/check.txt" && grep -q "3 lines that are not in it" "$D/check.txt"'
expect "new lines are listed, unchanged ones are not" 'grep -q "option dest_ip .10.9.9.9." "$D/check.txt" && ! grep -q "option input" "$D/check.txt"'
expect "new nftables include = REVIEW, comment not listed" 'grep -q "REVIEW  *fw-config  *\/etc\/nftables.d\/10-x.nft" "$D/check.txt" && grep -q "tcp dport 22 accept" "$D/check.txt" && ! grep -q "# comment" "$D/check.txt"'
expect "state file of the cloud handler = REVIEW with its time" 'grep -A1 "REVIEW  *state-file  *\/etc\/mp_ip_mapping_info" "$D/check.txt" | grep -q "written 20.* UTC, 0 bytes"'
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

echo; echo "=== 8b. Reported second implant: files with the reported content are IOC"
OW2=$BASE/openwrt-rom-second
cp -a "$OWL" "$OW2"; mkdir -p "$OW2/lib/upgrade/keep.d"
printf '#!/bin/sh /etc/rc.common\nSTART=99\nboot() { :; }\n' >"$OW2/etc/init.d/urandom_seed"
printf '/etc/config/network\n/etc/config/wireless\n' >"$OW2/lib/upgrade/keep.d/netifd"
printf 'lua interpreter\n' >"$OW2/usr/bin/lua"
printf 'root:$1$SALT$BASEHASH:19000:0:99999:7:::\ndaemon:*:0:0:99999:7:::\n' >"$OW2/etc/shadow"
# as on a real device, both files belong to a package of the base image
printf 'P:base-files\nF:etc/init.d\nR:urandom_seed\n\nP:netifd\nF:lib/upgrade/keep.d\nR:netifd\n\n' >>"$OW2/lib/apk/db/installed"
D=$(mkscen second "$OW2"); U=$D/u
mkdir -p "$U"/etc/init.d "$U"/bin "$U"/usr/bin "$U"/lib/upgrade/keep.d "$U"/etc/glinet/.cache
printf '#!/bin/sh /etc/rc.common\n/usr/bin/monitord /bin/ulogd &\nSTART=99\nboot() { :; }\n' >"$U/etc/init.d/urandom_seed"
printf '\033Lua\121\000\001\004' >"$U/bin/ulogd"
cp "$OW2/usr/bin/lua" "$U/usr/bin/monitord"
printf '/etc/config/network\n/etc/config/wireless\n/bin/ulogd\n/etc/init.d/urandom_seed\n' >"$U/lib/upgrade/keep.d/netifd"
printf '#!/bin/sh\n' >"$U/etc/glinet/.cache/watch.sh"
# a keep list that the base image does not have: a line of the owner and one of each implant
printf '/etc/my-own-file\n/etc/config/.gl/\n/bin/ulogd\n' >"$U/etc/sysupgrade.conf"
mnt "$D" "$OW2"
run "$D" "$OW2" --check >"$D/check.txt"; rc=$?
grep -E -A1 '^ +(IOC|PERSIST|REVIEW) ' "$D/check.txt"; grep -E 'Summary|Verdict' "$D/check.txt"
expect "check exit 1, 6 IOC" '[ $rc = 1 ] && grep -q "Summary: IOC=6 " "$D/check.txt"'
expect "keep list that is not in the base image: one IOC row" '[ $(grep -c " \/etc\/sysupgrade.conf$" "$D/check.txt") = 1 ] && grep -q "IOC  *keep-ref  *\/etc\/sysupgrade.conf" "$D/check.txt"'
expect "KVM watch.sh = marker" 'grep -q "IOC  *marker  *\/etc\/glinet\/.cache\/watch.sh" "$D/check.txt"'
expect "Lua bytecode at /bin/ulogd + copy of lua at /usr/bin/monitord = marker" 'grep -A1 "IOC  *marker  *\/bin\/ulogd" "$D/check.txt" | grep -q "Lua bytecode" && grep -A1 "IOC  *marker  *\/usr\/bin\/monitord" "$D/check.txt" | grep -q "identical to /usr/bin/lua"'
expect "each of the two files is listed once" '[ $(grep -c "^ *[A-Z][A-Z]*  *[a-z-][a-z-]*  *\/bin\/ulogd$" "$D/check.txt") = 1 ] && [ $(grep -c "^ *[A-Z][A-Z]*  *[a-z-][a-z-]*  *\/usr\/bin\/monitord$" "$D/check.txt") = 1 ]'
expect "urandom_seed that starts them = IOC although a package owns it" 'grep -q "IOC  *persist-ref  *\/etc\/init.d\/urandom_seed" "$D/check.txt"'
expect "keep list with /bin/ulogd = IOC although a package owns it" 'grep -q "IOC  *keep-ref  *\/lib\/upgrade\/keep.d\/netifd" "$D/check.txt"'
run "$D" "$OW2" --fix >"$D/fix.txt"; rc=$?
sed -n '/== Remediation/,$p' "$D/fix.txt"
expect "fix exit 2" '[ $rc = 2 ]'
expect "sysupgrade.conf: only the owner's line is left" '[ "$(cat "$D/m/etc/sysupgrade.conf")" = /etc/my-own-file ]'
expect "urandom_seed and keep list are those of the base image again" 'cmp -s "$D/m/etc/init.d/urandom_seed" "$OW2/etc/init.d/urandom_seed" && cmp -s "$D/m/lib/upgrade/keep.d/netifd" "$OW2/lib/upgrade/keep.d/netifd"'
expect "implant files and watch.sh gone, lua kept" '[ ! -e "$D/m/bin/ulogd" ] && [ ! -e "$D/m/usr/bin/monitord" ] && [ ! -e "$D/m/etc/glinet/.cache" ] && [ -f "$D/m/usr/bin/lua" ]'
expect "the removed files are in the archive" 'tar -tzf "$(ls "$D"/out/*.tar.gz | head -1)" | grep -q "files/upper/bin/ulogd"'
run "$D" "$OW2" --check >/dev/null; rc=$?
expect "re-check after fix: exit 0" '[ $rc = 0 ]'
umount "$D/m"

echo; echo "=== 8c. The same paths without the reported content are REVIEW, never changed"
D=$(mkscen secondname "$OW2"); U=$D/u
mkdir -p "$U"/etc/init.d "$U"/bin "$U"/usr/bin "$U"/lib/upgrade/keep.d
printf '#!/bin/sh /etc/rc.common\nSTART=99\nboot() { :; }\n# my own change\n' >"$U/etc/init.d/urandom_seed"
printf '\177ELF a real log daemon\n' >"$U/bin/ulogd"
printf 'my monitor\n' >"$U/usr/bin/monitord"
printf '/etc/config/network\n/etc/config/wireless\n/etc/init.d/urandom_seed\n' >"$U/lib/upgrade/keep.d/netifd"
mnt "$D" "$OW2"
run "$D" "$OW2" --check >"$D/check.txt"; rc=$?
grep -E -A1 '^ +(IOC|PERSIST|REVIEW) ' "$D/check.txt"; grep -E 'Summary|Verdict' "$D/check.txt"
expect "names alone: exit 0, IOC=0" '[ $rc = 0 ] && grep -q "Summary: IOC=0 " "$D/check.txt"'
expect "changed urandom_seed = REVIEW although a package owns it" 'grep -A1 "REVIEW  *changed  *\/etc\/init.d\/urandom_seed" "$D/check.txt" | grep -q "1 lines that are not in it"'
expect "ulogd + monitord = REVIEW with a note" '[ $(grep -A1 "REVIEW  *new-binary  *\/\(bin\/ulogd\|usr\/bin\/monitord\)$" "$D/check.txt" | grep -c "content is not what they describe") = 2 ]'
expect "keep list that keeps only the init script = REVIEW" 'grep -q "REVIEW  *changed  *\/lib\/upgrade\/keep.d\/netifd" "$D/check.txt"'
run "$D" "$OW2" --fix >"$D/fix.txt"; rc=$?
expect "fix changes nothing, exit 0" '[ $rc = 0 ] && grep -q "nothing to remediate" "$D/fix.txt" && grep -q "my own change" "$D/m/etc/init.d/urandom_seed" && [ -f "$D/m/bin/ulogd" ] && [ -f "$D/m/usr/bin/monitord" ] && grep -q urandom_seed "$D/m/lib/upgrade/keep.d/netifd"'
umount "$D/m"

echo; echo "=== 8d. shadow-summary.txt in the archive, with and without a password file in the base image"
S() { tar -xzOf "$(ls "$D"/out/*.tar.gz | head -1)" evidence/etc/shadow-summary.txt; }
D=$(mkscen shadownobase "$OWL"); U=$D/u
mkdir -p "$U/etc"
printf 'root:$1$SALT$NEWHASH:19000:0:99999:7:::\ndaemon:*:0:0:99999:7:::\n' >"$U/etc/shadow"
mnt "$D" "$OWL"
run "$D" "$OWL" --archive >/dev/null
S
expect "no password file in the base image: summary is not empty" '[ $(S | wc -l) = 2 ] && S | grep -q "^root.hash set, not in base.lastchg=19000$" && S | grep -q "^daemon.locked/empty"'
expect "the summary never holds a hash" '! S | grep -q NEWHASH'
umount "$D/m"
D=$(mkscen shadowbase "$OW2"); U=$D/u
mkdir -p "$U/etc"
printf 'root:$1$SALT$NEWHASH:19000:0:99999:7:::\ndaemon:*:0:0:99999:7:::\nsupport:$1$SALT$NEWHASH:19000:0:99999:7:::\n' >"$U/etc/shadow"
mnt "$D" "$OW2"
run "$D" "$OW2" --archive >/dev/null
S
expect "with a base password file: changed and new hashes are told apart" 'S | grep -q "^root.hash set, CHANGED vs base" && S | grep -q "^support.hash set, not in base" && [ $(S | wc -l) = 3 ]'
umount "$D/m"

echo; echo "=== 8e. Live checks on this machine (read-only): process named ujaild, connection to the reported relay"
# Process and connection checks only run on a live system, so this run has no --root: the
# script reads /proc of the machine the tests run on, with an empty overlay. Findings about
# the machine itself are not looked at, only the two decoys and the connection.
D=$(mkscen live "$OW2")
# the decoys are bash under another name (a busybox sleep would refuse the name)
cp "$(command -v bash)" "$BASE/payload"
(exec -a /usr/sbin/ujaild "$BASE/payload" -c 'while :; do sleep 1; done') & P1=$!
(exec -a ujaild bash -c 'while :; do sleep 1; done') & P2=$!
sleep 1; rm -f "$BASE/payload"
cat >"$BASE/relay.py" <<'EOF'
import socket, time
s = socket.socket(); s.bind(("65.20.71.131", 5912)); s.listen(1)
c = socket.create_connection(("65.20.71.131", 5912)); a = s.accept()
time.sleep(300)
EOF
NETNS=0
# the relay address on the loopback interface of a network namespace of our own
command -v python3 >/dev/null && command -v ip >/dev/null && unshare -n true 2>/dev/null && NETNS=1
if [ "$NETNS" = 1 ]; then
	unshare -n sh -c 'ip link set lo up && ip addr add 65.20.71.131/32 dev lo || exit 9
		python3 "$1" & sleep 1
		sh "$2" --upper "$3/u" --lower "$4" --check --no-report; rc=$?
		kill $!; exit $rc' sh "$BASE/relay.py" "$T" "$D" "$OW2" >"$D/check.txt" 2>/dev/null; rc=$?
	[ $rc = 9 ] && NETNS=0   # no address in the namespace: run again without the connection
fi
if [ "$NETNS" = 0 ]; then
	sh "$T" --upper "$D/u" --lower "$OW2" --check --no-report >"$D/check.txt" 2>/dev/null; rc=$?
fi
grep -E -A1 "^ +(IOC|REVIEW) +(process +($P1|$P2)|connection +65)" "$D/check.txt"
expect "ujaild running from a deleted binary = IOC, exit 1" '[ $rc = 1 ] && grep -A1 "IOC  *process  *$P1$" "$D/check.txt" | grep -q "payload of the reported second implant.*(deleted)"'
expect "the name ujaild on a program that is still on disk = REVIEW" 'grep -A1 "REVIEW  *process  *$P2$" "$D/check.txt" | grep -q "named ujaild.*exe=[^ ]*/bash "'
if [ "$NETNS" = 1 ]; then
	expect "connection to 65.20.71.131 = REVIEW" 'grep -A1 "REVIEW  *connection  *65.20.71.131$" "$D/check.txt" | grep -q ":5912 "'
else
	echo "  connection to the relay: skipped (needs python3, ip and unshare -n)"
fi
kill "$P1" "$P2" 2>/dev/null

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

echo; echo "=== 10. Archive: no password file, private keys only with --with-secrets"
D=$(mkscen scrub "$OWL"); U=$D/u
mkdir -p "$U/root/.ssh" "$U/etc/config" "$U/etc/dropbear" "$U/etc/openvpn/profiles/p1" "$U/etc/tailscale" "$U/etc/kvmd/user/zerotier" "$U/var/lib" "$D/live"
printf 'root:$1$SALT$HASHHASHHASH:19000:0:99999:7:::\n' >"$U/etc/shadow"; cp "$U/etc/shadow" "$U/etc/shadow-"
echo SECRETKEYDATA >"$U/root/.ssh/id_ed25519"; echo 'ssh-ed25519 AAAA me' >"$U/root/.ssh/id_ed25519.pub"
echo 'ssh-ed25519 AAAA attacker' >"$U/root/.ssh/authorized_keys"
echo SECRETHOSTKEY >"$U/etc/dropbear/dropbear_ed25519_host_key"
printf "config peers 'peer_1'\n\toption private_key 'SECRETWGKEY='\n\toption preshared_key \"SECRETPSK=\"\n\toption end_point '198.51.100.7:51820'\n" >"$U/etc/config/wireguard"
echo SECRETOVPN >"$U/etc/openvpn/profiles/p1/client.ovpn"
echo SECRETTS >"$U/etc/tailscale/tailscaled.state"
echo SECRETZTID >"$U/etc/kvmd/user/zerotier/identity.secret"
# a link out of the overlay to a "live" secret: the scrub must not follow it
echo LIVESECRET >"$D/live/identity.secret"; ln -s "$D/live" "$U/var/lib/zerotier-one"
printf '#!/bin/sh\nled on # my-own-line\n' >"$U/etc/rc.local"
mnt "$D" "$OWL"
run "$D" "$OWL" --archive >"$D/arch.txt"; rc=$?
A=$(ls "$D"/out/gl-triage-*.tar.gz | head -1); mkdir -p "$D/x"; tar -C "$D/x" -xzf "$A"; X=$D/x/evidence
expect "archive written, exit 0" '[ $rc = 0 ] && [ -f "$X/report.txt" ]'
expect "upper layer was copied in full" 'grep -q "complete copy" "$X/overlay/README.txt" && [ -f "$X/files/upper/etc/rc.local" ]'
expect "no shadow file in any copy, summary still there" '[ -z "$(find "$X" -name "shadow*" ! -name shadow-summary.txt)" ] && [ -f "$X/etc/shadow-summary.txt" ]'
expect "no secret value anywhere in the archive" '! grep -rqE "SECRET|HASHHASH" "$X"'
expect "public key, authorized_keys and rc.local kept" '[ -f "$X/files/upper/root/.ssh/id_ed25519.pub" ] && grep -q attacker "$X/files/merged/root/.ssh/authorized_keys" && grep -q my-own-line "$X/files/upper/etc/rc.local"'
expect "wireguard config kept, key values replaced, peer visible" '[ $(grep -c "REDACTED" "$X/files/upper/etc/config/wireguard") = 2 ] && grep -q "198.51.100.7" "$X/files/upper/etc/config/wireguard"'
expect "REDACTED.txt lists what was left out" 'grep -q "removed.*files/upper/etc/shadow$" "$X/REDACTED.txt" && grep -q "removed.*files/upper/root/.ssh/id_ed25519$" "$X/REDACTED.txt" && grep -q "key values replaced.*files/upper/etc/config/wireguard$" "$X/REDACTED.txt"'
expect "the run says so" 'grep -q "Left out: the password file and private keys" "$D/arch.txt"'
expect "MANIFEST verifies after the scrub" '(cd "$X" && sha256sum -c MANIFEST.sha256 >/dev/null)'
expect "device untouched: secrets and the linked file still there" 'grep -q SECRETKEYDATA "$D/m/root/.ssh/id_ed25519" && grep -q HASHHASH "$D/m/etc/shadow" && grep -q SECRETWGKEY "$D/m/etc/config/wireguard" && grep -q LIVESECRET "$D/live/identity.secret"'
rm -rf "$D/out"/* "$D/x"
run "$D" "$OWL" --archive --with-secrets >"$D/arch2.txt"; rc=$?
A=$(ls "$D"/out/gl-triage-*.tar.gz | head -1); mkdir -p "$D/x"; tar -C "$D/x" -xzf "$A"
expect "--with-secrets: keys kept and a warning printed" 'grep -q SECRETKEYDATA "$X/files/upper/root/.ssh/id_ed25519" && grep -q SECRETWGKEY "$X/files/upper/etc/config/wireguard" && grep -q "Do not pass it on" "$D/arch2.txt"'
expect "--with-secrets: still no shadow file" '[ -z "$(find "$X" -name "shadow*" ! -name shadow-summary.txt)" ] && ! grep -rq HASHHASH "$X"'
umount "$D/m"

echo; echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
