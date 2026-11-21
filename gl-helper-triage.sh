#!/bin/sh
# shellcheck shell=sh disable=SC3043
#
# gl-helper-triage.sh - triage for the "gl-helper" implant (GL.iNet incident 2026-11-20)
#
# Runs ON the device as root: GL.iNet KVMs (buildroot) and GL.iNet / OpenWrt routers.
# Needs only busybox sh/ash or bash.
#
#   sh gl-helper-triage.sh [--check]            read-only detection (default)
#   sh gl-helper-triage.sh --archive [-o DIR]   collect evidence into DIR (default /tmp)
#   sh gl-helper-triage.sh --archive --stdout   stream the evidence tar.gz to stdout
#   sh gl-helper-triage.sh --fix [-o DIR]       archive first (mandatory), then remediate
#
# The archive leaves out the password file (/etc/shadow) always, and private keys (SSH,
# WireGuard, OpenVPN profiles, ZeroTier, Tailscale) unless --with-secrets is given. What
# was left out is listed in REDACTED.txt inside the archive.
#
# At the end the script offers to send a short anonymous report (model, firmware, which
# indicators, when) to the community, also from a device without indicators, so that we
# see which devices were not hit. It shows the report and sends it only
# after "y". --report sends it without asking, --no-report never asks, --show-report
# prints the complete report and sends nothing. The report carries a device ID so that
# several reports from one device count once: a hash of a hardware address, never the
# address itself, and the server hashes it again with a secret before it stores it.
# --no-device-id leaves it out.
#
# Output is coloured on a terminal. --color forces colours (e.g. through ssh without a
# tty), --no-color or NO_COLOR=1 turns them off. The report in the archive is plain text.
#
# From a PC (or use triage-remote.sh, which pulls and verifies the evidence before fixing):
#   ssh root@DEVICE 'sh -s -- --check' < gl-helper-triage.sh
#   ssh root@DEVICE 'sh -s -- --archive --stdout' < gl-helper-triage.sh > evidence.tar.gz
#
# The overlay is detected automatically: upper /userdata/overlay/upper (KVM) or
# /overlay/upper (OpenWrt), read-only base image /rom.
# Test options: --root DIR (merged root, default /), --upper DIR, --lower DIR.
#
# Exit codes: 0 clean | 1 IOC found | 2 fixed, no IOC left | 3 fix incomplete | 4 error
#
# The IOCs come from GL.iNet's own boot cleanup in RM1PE firmware 1.10.2
# (/etc/init.d/S08overlayfs). That cleanup only fires when one of four marker files
# exists and only removes a fixed set. This script also flags busybox applets replaced
# by foreign binaries, IOC processes and other overlay changes worth reviewing. It also
# runs GL.iNet's quick check for routers (a process "crond -i /tmp/.log") and looks for a
# remote shell that users reported in GL.iNet's forum.
# --fix only touches IOC items and their persistence. REVIEW items are archived and
# reported, never changed. This is a stopgap: a factory reset is still recommended.

VERSION=2.13

MARKERS="etc/glinet/.cache/gl-helper etc/glinet/.cache/gb etc/config/.gl/gl-helper etc/config/.gl/gb"
MARKER_DIRS="etc/glinet/.cache etc/config/.gl"
PERSIST="etc/rc.local etc/crontabs/root"
APPLET_DIRS="bin sbin usr/bin usr/sbin"
REVIEW_PATHS="etc/init.d etc/rc.d etc/inittab etc/profile etc/profile.d etc/hotplug.d
etc/uci-defaults etc/kvmd/user/scripts etc/crontabs root/.ssh etc/dropbear
etc/sysupgrade.conf lib/upgrade/keep.d"
IOC_RE='gl-helper|/\.gl/|/\.cache/gb'
# Firewall configuration: files that fw3/fw4 and GL.iNet's scripts build the rules from.
FW_PATHS="etc/config/firewall etc/firewall.user etc/firewall.d etc/nftables.d usr/share/nftables.d"
# The command users found started with this rule (see SHELL_RE below): it is what is left
# in the firewall after that command ran.
FW_RULE_RE='^-A SDWAN_IP_MAPPING .*-d 127\.0\.0\.1(/32)? .*--to-destination 127\.0\.0\.1'
# Running processes. PROC_RE is GL.iNet's own quick check for routers (forum, 2026-11-21):
# "ps | grep tmp" shows "crond -i /tmp/.log". SHELL_RE is a remote root shell that users
# reported in the same thread (a loop around a pipe at /tmp/f and nc to SHELL_IP). GL.iNet
# staff recommends checking for it and for the tools in TOOL_RE, with
#   ps ww | grep -E '[n]c |[n]etcat|[s]ocat|[/]bin/sh -i|[m]kfifo'
# and for connections held by a shell or by such a tool (netstat -tnp).
PROC_RE='crond -i /tmp/\.log'
SHELL_IP='170.39.226.219'
# Three reports so far, the same address with a different port each. Connections are
# matched against the whole /24 in case the other end moves.
SHELL_NET='170.39.226.'
TOOL_RE='(^|[ /])(nc|netcat|socat) |/bin/sh -i|mkfifo'
CONN_RE='/(nc|netcat|socat|sh|ash|bash)$'
SHELL_RE="170\\.39\\.226\\.|/tmp/f([ ;|>]|\$)"
FULL_UPPER_MAX_KB=65536
TAB=$(printf '\t')

MODE=check STDOUT=0 SECRETS=0 OUTDIR=/tmp ROOT=/ UPPER='' LOWER='' UPPER_SET=0 LOWER_SET=0 COLOR=auto REPORT=ask DEVICE_ID=1
REPORT_URL=${GL_TRIAGE_REPORT_URL:-https://app.gl-i.net/csa-2026-01-report}

usage() {
	cat <<'EOF'
gl-helper-triage.sh - check, archive and remediate the GL.iNet "gl-helper" implant
(GL.iNet KVMs and GL.iNet / OpenWrt routers)

  --check              read-only detection (default)
  --archive            collect evidence as tar.gz into -o DIR (default /tmp)
  --stdout             with --archive: write the tar.gz to stdout, log to stderr
  --with-secrets       keep private keys (SSH, VPN) in the archive; by default they are
                       left out. The password file /etc/shadow is never included.
  --fix                archive (mandatory), kill IOC processes, remove IOC persistence,
                       restore replaced base files from the read-only image
  -o, --out DIR        output directory for the archive
  --color, --no-color  force or disable coloured output (default: only on a terminal)
  --report             send the short anonymous report without asking (it is shown first)
  --no-report          never offer to send a report
  --show-report        print the complete report and send nothing
  --no-device-id       leave the device ID out of the report
  --root/--upper/--lower DIR   override merged root, overlay upper and base image
  -V, --version        print version

Exit: 0 clean, 1 IOC found, 2 fixed, 3 fix incomplete, 4 error
EOF
}

# Colours: empty strings unless switched on, so every message works both ways.
palette() {
	if [ "$1" = 1 ]; then
		ESC=$(printf '\033')
		N="$ESC[0m" B="$ESC[1m" D="$ESC[2m"
		RED="$ESC[1;31m" YEL="$ESC[33m" CYA="$ESC[36m" GRN="$ESC[32m"
	else
		N='' B='' D='' RED='' YEL='' CYA='' GRN=''
	fi
}
palette 0
die() { printf '%sERROR:%s %s\n' "$RED" "$N" "$*" >&2; exit 4; }

while [ $# -gt 0 ]; do
	case $1 in
	--check) MODE=check ;;
	--archive) MODE=archive ;;
	--fix) MODE=fix ;;
	--stdout) STDOUT=1 ;;
	--with-secrets) SECRETS=1 ;;
	--color) COLOR=1 ;;
	--no-color) COLOR=0 ;;
	--report) REPORT=yes ;;
	--no-report) REPORT=no ;;
	--show-report) REPORT=show ;;
	--no-device-id) DEVICE_ID=0 ;;
	-o | --out) [ $# -ge 2 ] || die "$1 needs a directory"; OUTDIR=$2; shift ;;
	--root) [ $# -ge 2 ] || die "$1 needs a directory"; ROOT=$2; shift ;;
	--upper) [ $# -ge 2 ] || die "$1 needs a directory"; UPPER=$2; UPPER_SET=1; shift ;;
	--lower) [ $# -ge 2 ] || die "$1 needs a directory"; LOWER=$2; LOWER_SET=1; shift ;;
	-h | --help) usage; exit 0 ;;
	-V | --version) echo "$VERSION"; exit 0 ;;
	*) die "unknown option: $1 (see --help)" ;;
	esac
	shift
done
[ "$STDOUT" = 1 ] && [ "$MODE" != archive ] && die "--stdout only works together with --archive"

# Log goes to fd 3: stdout normally, stderr when the archive itself goes to stdout.
if [ "$STDOUT" = 1 ]; then exec 3>&2; else exec 3>&1; fi
say() { printf '%s\n' "$*" >&3; }
if [ "$COLOR" = auto ]; then
	COLOR=0
	[ -t 3 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ] && COLOR=1
fi
palette "$COLOR"
# Not called "head": that would hide the command of that name.
section() { say ""; say "${B}== $*${N}"; }
kv() { printf '   %s%-14s%s %s\n' "$D" "$1" "$N" "$2" >&3; }
act() { say "   ${GRN}$*${N}"; }
# Progress while the checks run, so the screen is not empty until the report is ready.
# On a terminal one line is overwritten and removed at the end; otherwise (pipe, ssh
# without a terminal) each step is a line of its own.
STEPS=9
TTY=0
[ -t 3 ] && [ "${TERM:-dumb}" != dumb ] && TTY=1
progress() {
	STEP=$((STEP + 1))
	if [ "$TTY" = 1 ]; then
		printf '\r\033[K   %sChecking %s/%s: %s ...%s' "$D" "$STEP" "$STEPS" "$1" "$N" >&3
	else
		say "   ${D}checking $STEP/$STEPS: $1${N}"
	fi
}
progress_end() { [ "$TTY" = 1 ] && printf '\r\033[K' >&3; return 0; }
umask 077

TMP=${TMPDIR:-/tmp}/.gl-triage.$$
mkdir -m 700 "$TMP" 2>/dev/null || die "cannot create work dir $TMP"
trap 'rm -rf "$TMP"' EXIT
trap 'exit 4' INT TERM HUP

LIVE=0
[ "$ROOT" = / ] && LIVE=1
[ -d "$ROOT" ] || die "root not found: $ROOT"
if [ "$UPPER_SET" = 0 ] && [ "$LIVE" = 1 ]; then
	for d in /userdata/overlay/upper /overlay/upper; do
		[ -d "$d" ] && { UPPER=$d; break; }
	done
fi
if [ "$LOWER_SET" = 0 ] && [ "$LIVE" = 1 ] && [ -d /rom/bin ]; then LOWER=/rom; fi
[ -z "$UPPER" ] || [ -d "$UPPER" ] || die "upper dir not found: $UPPER"
[ -z "$LOWER" ] || [ -d "$LOWER" ] || die "lower dir not found: $LOWER"

r() { if [ "$ROOT" = / ]; then printf '/%s' "$1"; else printf '%s/%s' "${ROOT%/}" "$1"; fi; }
u() { printf '%s/%s' "${UPPER%/}" "$1"; }
l() { printf '%s/%s' "${LOWER%/}" "$1"; }
exists() { [ -e "$1" ] || [ -L "$1" ]; }

# The implant replaced at least /usr/bin/netstat. Use the busybox from the read-only
# base image for every tool this script calls, so a replaced applet cannot lie to us.
TRUSTED=no
if [ -n "$LOWER" ] && [ -x "$(l bin/busybox)" ] && "$(l bin/busybox)" true 2>/dev/null; then
	TBB=$(l bin/busybox)
	mkdir "$TMP/bin"
	for a in $("$TBB" --list 2>/dev/null); do ln -s "$TBB" "$TMP/bin/$a" 2>/dev/null; done
	PATH="$TMP/bin:$PATH"
	export PATH
	TRUSTED="yes ($TBB)"
fi

if [ -f "$(r etc/openwrt_release)" ]; then
	PLATFORM=openwrt
elif grep -q '^RK_MODEL=' "$(r etc/version)" 2>/dev/null; then
	PLATFORM="glkvm-$(sed -n 's/^RK_MODEL=//p' "$(r etc/version)")"
else
	PLATFORM=unknown
fi

if [ "$LIVE" = 1 ]; then
	HOST=$(cat /proc/sys/kernel/hostname 2>/dev/null)
else
	HOST=$(cat "$(r etc/hostname)" 2>/dev/null)
fi
HOST=$(printf '%s' "${HOST:-unknown}" | tr -c 'A-Za-z0-9._-' '_')
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WHEN=$(printf '%s' "$STAMP" | sed 's/^\(....\)\(..\)\(..\)T\(..\)\(..\)\(..\)Z$/\1-\2-\3 \4:\5:\6 UTC/')

filecmp() {
	if command -v cmp >/dev/null 2>&1; then cmp -s "$1" "$2"; return; fi
	[ "$(cat "$1" 2>/dev/null | sha256sum)" = "$(cat "$2" 2>/dev/null | sha256sum)" ] && [ -r "$1" ] && [ -r "$2" ]
}

# ---------------------------------------------------------------- findings
# One line per finding: LEVEL<TAB>KIND<TAB>PATH<TAB>DETAIL
#   IOC      known indicator; remediated by --fix
#   PERSIST  persistence file; removed by --fix only when an IOC is present
#   REVIEW   unusual overlay change; archived and reported, never changed
#   INFO     context
add() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >>"$FIND"; }

# Package that installed a file: apk (OpenWrt 24.10+), opkg (older OpenWrt / GL 4.x).
pkg_owner() {
	local p db info
	p=${1#/}
	db=$(r lib/apk/db/installed)
	if [ -f "$db" ]; then
		awk -v t="$p" '/^P:/{pk=substr($0,3)} /^F:/{d=substr($0,3)}
			/^R:/{f = (d == "" ? "" : d "/") substr($0,3); if (f == t) {print pk; exit}}' "$db"
		return
	fi
	info=$(r usr/lib/opkg/info)
	[ -d "$info" ] && grep -lxF "/$p" "$info"/*.list 2>/dev/null | head -n 1 | sed 's#.*/##; s#\.list$##'
}

# Where a file of the overlay lives: the upper layer if we know it, else the merged view.
src() { if [ -n "$UPPER" ]; then u "$1"; else r "$1"; fi; }

# Absolute, normalized target of a symlink: $1 = relative path of the link, $2 = raw target.
# "busybox" and "/bin/busybox" for /bin/login are the same target.
link_target() {
	local t
	case $2 in /*) t=$2 ;; *) t="/${1%/*}/$2" ;; esac
	printf '%s\n' "$t" | awk -F/ '{n=0; for (i=1; i<=NF; i++) { if ($i=="" || $i==".") continue;
		if ($i=="..") { if (n>0) n--; continue } s[++n]=$i }
		o=""; for (i=1; i<=n; i++) o=o "/" s[i]; print (o=="" ? "/" : o)}'
}

# Overlay whiteout (char device 0/0): the file was deleted, e.g. a uci-defaults script
# after first boot or a disabled service link. Not a change we need to look at.
whiteout() { [ -c "$1" ]; }

same_as_lower() {
	[ -n "$LOWER" ] || return 1
	local a b
	a=$(src "$1") b=$(l "$1")
	if [ -L "$a" ]; then
		[ -L "$b" ] && [ "$(link_target "$1" "$(readlink "$a")")" = "$(link_target "$1" "$(readlink "$b")")" ]
		return
	fi
	[ -f "$a" ] && [ -f "$b" ] && [ ! -L "$b" ] && filecmp "$a" "$b"
}

check_markers() {
	local p hit d
	for p in $MARKERS; do
		hit=
		[ -n "$UPPER" ] && exists "$(u "$p")" && hit=upper
		exists "$(r "$p")" && hit=${hit:+$hit+}merged
		[ -n "$hit" ] && add IOC marker "/$p" "present ($hit)"
	done
	for d in $MARKER_DIRS; do
		if exists "$(src "$d")" && ! grep -q "${TAB}/$d/" "$FIND" && { [ -z "$LOWER" ] || ! exists "$(l "$d")"; }; then
			add REVIEW hidden-dir "/$d" "hidden directory not in base image, no known marker inside"
		fi
	done
}

# Relative paths below the applet dirs that the overlay changed.
applet_candidates() {
	local d base
	if [ -n "$UPPER" ]; then base=$UPPER; elif [ -n "$LOWER" ]; then base=${ROOT%/}; else return 0; fi
	for d in $APPLET_DIRS; do
		[ -d "$base/$d" ] || continue
		find "$base/$d" -xdev ! -type d 2>/dev/null | sed "s#^${base%/}/##"
	done
}

check_applets() {
	local p up lp owner
	applet_candidates >"$TMP/cand"
	while IFS= read -r p; do
		up=$(src "$p") lp=
		[ -n "$LOWER" ] && lp=$(l "$p")
		same_as_lower "$p" && continue
		# without an upper layer only files that differ from an existing base file count
		if [ -z "$UPPER" ] && ! exists "$lp"; then continue; fi
		if [ -L "$up" ]; then
			[ -n "$lp" ] && exists "$lp" &&
				add REVIEW symlink "/$p" "-> $(readlink "$up") (base: $(readlink "$lp" 2>/dev/null || echo file))"
			continue
		fi
		[ -f "$up" ] || continue
		owner=$(pkg_owner "/$p")
		if [ -n "$owner" ]; then
			add INFO package-file "/$p" "installed by package $owner"
		elif [ -n "$lp" ] && [ -L "$lp" ]; then
			add IOC applet-hijack "/$p" "regular file shadows base symlink -> $(readlink "$lp")"
		elif [ "${p##*/}" = netstat ]; then
			add IOC applet-hijack "/$p" "netstat replaced by a foreign regular file"
		elif [ -n "$lp" ] && [ -f "$lp" ]; then
			add REVIEW modified-binary "/$p" "differs from base image"
		else
			add REVIEW new-binary "/$p" "not in base image, not owned by a package"
		fi
	done <"$TMP/cand"
	# Without any base image, at least look at netstat itself.
	if [ -z "$LOWER" ] && [ -z "$UPPER" ]; then
		for p in usr/bin/netstat bin/netstat; do
			[ -f "$(r "$p")" ] && [ ! -L "$(r "$p")" ] && [ -z "$(pkg_owner "/$p")" ] &&
				add REVIEW netstat "/$p" "regular file instead of busybox symlink (no base image to compare)"
		done
	fi
}

check_persist() {
	local p f
	for p in $PERSIST; do
		f=$(src "$p")
		exists "$f" || continue
		same_as_lower "$p" && continue
		if grep -qE "$IOC_RE" "$f" 2>/dev/null; then
			add IOC persist-ref "/$p" "references gl-helper paths"
		else
			add PERSIST persistence "/$p" "present in overlay ($(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null) active lines)"
		fi
	done
}

# rc.d symlink to an init script from the base image or a package: normal service enable
known_service_link() {
	local t n
	[ -L "$1" ] || return 1
	t=$(readlink "$1") n=${t##*/}
	case $t in ../init.d/* | /etc/init.d/*) ;; *) return 1 ;; esac
	{ [ -n "$LOWER" ] && exists "$(l "etc/init.d/$n")"; } || [ -n "$(pkg_owner "/etc/init.d/$n")" ]
}

check_review() {
	local p e base
	if [ -n "$UPPER" ]; then base=$UPPER; elif [ -n "$LOWER" ]; then base=${ROOT%/}; else base=; fi
	if [ -n "$base" ]; then
		for p in $REVIEW_PATHS; do
			e="$base/$p"
			exists "$e" || continue
			find "$e" -xdev ! -type d 2>/dev/null | while IFS= read -r f; do
				rel=${f#"${base%/}"/}
				case $rel in
				etc/crontabs/root) continue ;;
				etc/dropbear/dropbear_*_host_key | etc/dropbear/dropbear_*_host_key.pub) continue ;;
				esac
				whiteout "$f" && continue
				same_as_lower "$rel" && continue
				grep -q "${TAB}/$rel${TAB}" "$FIND" && continue
				[ -n "$(pkg_owner "/$rel")" ] && continue
				case $rel in etc/rc.d/*) known_service_link "$f" && continue ;; esac
				# any autostart/config file that starts the implant is persistence too
				if [ -f "$f" ] && [ ! -L "$f" ] && grep -qE "$IOC_RE" "$f" 2>/dev/null; then
					case $rel in
					etc/sysupgrade.conf | lib/upgrade/keep.d/*)
						add IOC keep-ref "/$rel" "keeps gl-helper paths across firmware updates" ;;
					*) add IOC persist-ref "/$rel" "references gl-helper paths" ;;
					esac
					continue
				fi
				if [ -n "$LOWER" ] && exists "$(l "$rel")"; then
					add REVIEW changed "/$rel" "differs from base image"
				elif [ -n "$UPPER" ]; then
					add REVIEW new "/$rel" "not in base image"
				fi
			done
		done
	fi
	# accounts
	awk -F: '$3 == 0 && $1 != "root" {print $1}' "$(r etc/passwd)" 2>/dev/null | while IFS= read -r a; do
		add REVIEW uid0-account "/etc/passwd" "second uid 0 account: $a"
	done
	if [ -n "$LOWER" ] && [ -f "$(l etc/passwd)" ]; then
		awk -F: 'NR==FNR {seen[$1]=1; next} !($1 in seen) {print $1 " (shell " $7 ")"}' \
			"$(l etc/passwd)" "$(r etc/passwd)" 2>/dev/null | while IFS= read -r a; do
			add REVIEW new-account "/etc/passwd" "account not in base image: $a"
		done
	fi
	# other hidden files and dirs in the overlay
	if [ -n "$UPPER" ]; then
		find "$UPPER" -xdev -name '.*' 2>/dev/null | sed "s#^${UPPER%/}/##" | while IFS= read -r rel; do
			case $rel in
			etc/glinet/.cache* | etc/config/.gl*) continue ;;
			root/.ash_history | root/.bash_history | root/.ssh | root/.ssh/*) continue ;;
			*/.uci | */.uci/* | etc/.extroot-uuid | .fs_state | etc/luci-uploads/.placeholder) continue ;;
			esac
			add REVIEW hidden "/$rel" "hidden file in overlay"
		done
	fi
}

# Credentials stored on the device. Whoever had a root shell on it could copy them, and
# neither --fix nor a firmware update nor a factory reset takes them back: they stay valid
# at the other end until they are revoked there. They are listed so the owner knows what
# to revoke: root's SSH client keys and what the VPN clients and the WireGuard server of
# GL.iNet firmware keep. Names and counts only, never the content; for an
# SSH key the fingerprint of its public half. This goes to its own file, not to the
# findings, so none of it is in the anonymous report. Other passwords and tokens in the
# configuration are not looked for.
cred() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$TMP/creds"; }

# Number of lines "option <name> <value>" with a value that is not empty. $1 file, $2 name
uci_count() {
	grep -cE "^[[:space:]]*option[[:space:]]+$2[[:space:]]+['\"]?[^'\"[:space:]]" "$1" 2>/dev/null </dev/null
}

check_credentials() {
	local f n dk fp zt
	: >"$TMP/creds"
	# dropbearkey from the read-only image, for the same reason as busybox above
	dk=
	[ -n "$LOWER" ] && [ -x "$(l usr/bin/dropbearkey)" ] && dk=$(l usr/bin/dropbearkey)
	# SSH client keys of root: ~/.ssh/id_dropbear is the name dropbear's help recommends
	# for client keys, the others are the usual OpenSSH names. The file name comes from
	# the device, so only its plain characters are printed.
	for f in "$(r root/.ssh)"/id_*; do
		[ -f "$f" ] || continue
		case $f in *.pub) continue ;; esac
		fp=
		[ -n "$dk" ] && fp=$("$dk" -y -f "$f" 2>/dev/null </dev/null | sed -n 's/^Fingerprint: *//p' | head -n 1)
		cred "SSH client key" "$(printf '%s' "${f#"${ROOT%/}"}" | tr -c 'A-Za-z0-9._/@+=,:-' '?')" "${fp:-fingerprint not available}"
	done
	# WireGuard and AmneziaWG on GL.iNet firmware: the client keys are in
	# /etc/config/wireguard (in a profile or once for a group of profiles), the server
	# key is in /etc/config/wireguard_server
	for f in etc/config/wireguard etc/config/wireguard_server; do
		n=$(uci_count "$(r "$f")" private_key)
		[ "${n:-0}" -gt 0 ] || continue
		case $f in
		*/wireguard) cred "WireGuard client" "/$f" "$n private key(s)" ;;
		*) cred "WireGuard server" "/$f" "$n private key(s)" ;;
		esac
	done
	# OpenVPN client on GL.iNet firmware: profiles are .ovpn files below /etc/openvpn/profiles
	f=$(r etc/openvpn/profiles)
	if [ -d "$f" ]; then
		n=$(find "$f" -type f -name '*.ovpn' 2>/dev/null | wc -l | tr -d ' ')
		[ "${n:-0}" -gt 0 ] && cred "OpenVPN client" /etc/openvpn/profiles "$n profile(s)"
	fi
	# ZeroTier: OpenWrt's init script keeps the identity in /etc/config/zerotier and writes
	# identity.secret to a RAM disk at every start; the KVM firmware keeps the file itself.
	# One identity, so one line.
	zt=
	n=$(uci_count "$(r etc/config/zerotier)" secret)
	[ "${n:-0}" -gt 0 ] && zt=etc/config/zerotier
	for f in etc/kvmd/user/zerotier/identity.secret var/lib/zerotier-one/identity.secret; do
		[ -z "$zt" ] && [ -s "$(r "$f")" ] && zt=$f
	done
	[ -n "$zt" ] && cred "ZeroTier" "/$zt" "identity of this node"
	# Tailscale on GL.iNet routers: the state file
	f=etc/tailscale/tailscaled.state
	[ -s "$(r "$f")" ] && cred "Tailscale" "/$f" "state of this node, with its key once it was signed in"
	return 0
}

# When a process started, in UTC, from its start tick in /proc/<pid>/stat and the boot
# time. The reported shells all started at about the same time (21:40 UTC, 2026-11-20).
proc_start() {
	local bt tk
	bt=$(awk '/^btime /{print $2}' /proc/stat 2>/dev/null)
	tk=$(sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}')
	[ -n "$bt" ] && [ -n "$tk" ] || return 0
	date -u -d "@$((bt + tk / 100))" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null
}

# Time a file was last written, in UTC.
file_time() { date -u -r "$1" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null; }

# Time the kernel last changed a file's entry (ctime), in UTC. Unlike the time above it
# cannot be set back by touch or by unpacking an archive, so the two together show whether
# a file brought its time along. Empty where neither stat nor ls can tell.
file_ctime() {
	local t
	t=$(stat -c %Z "$1" 2>/dev/null)
	case $t in
	'' | *[!0-9]*) ;;
	*) date -u -d "@$t" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null && return 0 ;;
	esac
	TZ=UTC0 ls -lcd --full-time "$1" 2>/dev/null |
		sed -n 's/.* \([0-9]\{4\}-[0-9][0-9]-[0-9][0-9]\) \([0-9][0-9]:[0-9][0-9]:[0-9][0-9]\)[.0-9]* +0000 .*/\1 \2 UTC/p' | head -n 1
}

# Process scan (live system only). Also maps socket inodes to pids for the net output.
check_procs() {
	[ "$LIVE" = 1 ] && [ -r /proc/1/cmdline ] || return 0
	: >"$TMP/procs"
	: >"$TMP/sockets"
	: >"$TMP/exes"
	local d pid exe comm cmd
	for d in /proc/[0-9]*; do
		pid=${d#/proc/}
		[ "$pid" = $$ ] && continue
		# A process can end between the listing and these reads (this script's own helpers
		# do all the time). Read through cat, whose error can be silenced; with "<file" the
		# shell itself reports a missing file. A process that is gone is skipped.
		comm=$(cat "$d/comm" 2>/dev/null)
		[ -n "$comm" ] || continue
		exe=$(readlink "$d/exe" 2>/dev/null)
		cmd=$(cat "$d/cmdline" 2>/dev/null | tr '\0' ' ')
		printf '%s\t%s\t%s\t%s\n' "$pid" "$comm" "$exe" "$cmd" >>"$TMP/procs"
		# shellcheck disable=SC2012 # fd names are numbers
		ls -l "$d/fd" 2>/dev/null | awk -v p="$pid" -v c="$comm" \
			'/socket:\[/ {s=$NF; gsub(/[^0-9]/,"",s); print s "\t" p "\t" c}' >>"$TMP/sockets"
		case "$cmd" in *gl-helper-triage*) continue ;; esac
		if printf '%s\n%s\n%s\n' "$exe" "$cmd" "$comm" | grep -qE "$IOC_RE"; then
			add IOC process "$pid" "comm=$comm exe=$exe cmd=$cmd"
			continue
		fi
		if printf '%s\n' "$cmd" | grep -qE "$PROC_RE"; then
			add IOC process "$pid" "GL.iNet's quick check (crond -i /tmp/.log): started $(proc_start "$pid") comm=$comm exe=$exe cmd=$cmd"
			continue
		fi
		if printf '%s\n' "$cmd" | grep -qE "$SHELL_RE"; then
			add IOC process "$pid" "remote shell reported by users (GL.iNet staff: treat the router as compromised): started $(proc_start "$pid") comm=$comm cmd=$cmd"
			continue
		fi
		if printf '%s\n' "$cmd" | grep -qE "$TOOL_RE"; then
			add REVIEW process "$pid" "tool that remote shells use (GL.iNet staff's process check): started $(proc_start "$pid") comm=$comm cmd=$cmd"
		fi
		if [ -n "$exe" ] && grep -q "^IOC${TAB}applet-hijack${TAB}${exe}${TAB}" "$FIND"; then
			add IOC process "$pid" "runs replaced applet: comm=$comm exe=$exe cmd=$cmd"
			continue
		fi
		case "$exe" in
		*' (deleted)') add REVIEW deleted-exe "$pid" "running from deleted binary: comm=$comm exe=$exe" ;;
		/*) printf '%s\t%s\n' "$exe" "$pid" >>"$TMP/exes" ;;
		esac
	done
	check_exes
}

# Where does every running program come from? Anything that is not the unchanged file
# from the read-only base image is listed: programs started from a RAM disk (they are in
# neither the base image nor the overlay, so the file checks cannot see them), programs
# that are not in the base image and programs that differ from it. Packages are INFO.
# A script run by a shell from the base image is not caught here; the patterns above are.
check_exes() {
	local exe rel pids owner
	cut -f1 "$TMP/exes" | sort -u | while IFS= read -r exe; do
		pids=$(awk -F '\t' -v e="$exe" '$1==e {printf "%s%s", sep, $2; sep=","}' "$TMP/exes")
		grep -q "^IOC${TAB}applet-hijack${TAB}${exe}${TAB}" "$FIND" && continue
		case $exe in
		/tmp/* | /var/* | /run/* | /dev/shm/*)
			add REVIEW running "$exe" "started from a RAM disk, in neither the base image nor the overlay (pid $pids)"
			continue ;;
		esac
		[ -n "$LOWER" ] || continue
		case $exe in "${LOWER%/}"/*) continue ;; esac
		rel=${exe#/}
		if exists "$(l "$rel")"; then
			[ -f "$exe" ] && [ -f "$(l "$rel")" ] && filecmp "$exe" "$(l "$rel")" && continue
			owner=$(pkg_owner "$exe")
			if [ -n "$owner" ]; then
				add INFO running "$exe" "differs from the base image, installed by package $owner (pid $pids)"
			else
				add REVIEW running "$exe" "differs from the base image, not owned by a package (pid $pids)"
			fi
		else
			owner=$(pkg_owner "$exe")
			if [ -n "$owner" ]; then
				add INFO running "$exe" "not in the base image, installed by package $owner (pid $pids)"
			else
				add REVIEW running "$exe" "not in the base image, not owned by a package (pid $pids)"
			fi
		fi
	done
}

# Files that belong to the process indicators. /tmp is RAM, so these are gone after a
# restart. The pipe /tmp/f stays after the shell was stopped: it shows that the shell ran
# since the last boot, and its time is the last data that went through it.
# /etc/mp_ip_mapping_info is the state file of the cloud handler (SD-WAN IP mapping) that
# the reported command came through; the handler rewrites it each time it runs.
check_tmp() {
	local f
	exists "$(r tmp/.log)" && add REVIEW tmp-file /tmp/.log "path from GL.iNet's quick check (crond -i /tmp/.log) exists"
	f=$(r tmp/f)
	[ -p "$f" ] && add IOC pipe /tmp/f "named pipe of the reported remote shell: the shell ran since the last boot, last data $(file_time "$f")"
	f=$(r etc/mp_ip_mapping_info)
	if [ -f "$f" ]; then
		add REVIEW state-file /etc/mp_ip_mapping_info "written $(file_time "$f"), $(cat "$f" 2>/dev/null | wc -c | tr -d ' ') bytes: the cloud handler for SD-WAN IP mapping ran then. The reported attack came through it; normal if you use AstroWarp"
	fi
	return 0
}

# Firewall. The running rules are generated from configuration, so no rule "comes from
# the firmware image" as such. What can be compared with the image is that configuration:
# every line of it that the image does not contain is listed. The running rules are
# saved for the archive, and the ones that redirect traffic are shown in the report.
check_firewall() {
	local base p e f rel n
	: >"$TMP/fw-added"
	: >"$TMP/fw-ioc"
	if [ -n "$UPPER" ]; then base=$UPPER; elif [ -n "$LOWER" ]; then base=${ROOT%/}; else base=; fi
	if [ -n "$base" ]; then
		for p in $FW_PATHS; do
			e="$base/$p"
			exists "$e" || continue
			find "$e" -xdev -type f 2>/dev/null | while IFS= read -r f; do
				rel=${f#"${base%/}"/}
				same_as_lower "$rel" && continue
				[ -n "$(pkg_owner "/$rel")" ] && continue
				if [ -n "$LOWER" ] && [ -f "$(l "$rel")" ]; then
					grep -vxFf "$(l "$rel")" "$f" 2>/dev/null | grep -v '^[[:space:]]*\(#.*\)\{0,1\}$' >"$TMP/fw-lines"
					n=$(wc -l <"$TMP/fw-lines" | tr -d ' ')
					add REVIEW fw-config "/$rel" "differs from the firmware image: $n lines that are not in it (listed under Firewall)"
				else
					grep -v '^[[:space:]]*\(#.*\)\{0,1\}$' "$f" >"$TMP/fw-lines" 2>/dev/null
					add REVIEW fw-config "/$rel" "not in the firmware image (content listed under Firewall)"
				fi
				{ echo "/$rel"; sed 's/^/    /' "$TMP/fw-lines"; } >>"$TMP/fw-added"
			done
		done
	fi
	[ "$LIVE" = 1 ] || return 0
	: >"$TMP/fw-redirect"
	if command -v iptables-save >/dev/null 2>&1 && iptables-save >"$TMP/iptables-save.txt" 2>/dev/null; then
		command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save >"$TMP/ip6tables-save.txt" 2>/dev/null
		awk '/^\*/ {t=substr($0,2); next} /^-A / {print t "\t" $0}' "$TMP/iptables-save.txt" >"$TMP/fw-rules"
		awk -F '\t' '$2 ~ /-j (DNAT|REDIRECT)/ || $2 ~ /^-A SDWAN_IP_MAPPING / {print $1 ": " $2}' "$TMP/fw-rules" >>"$TMP/fw-redirect"
		awk -F '\t' -v re="$FW_RULE_RE" '$2 ~ re' "$TMP/fw-rules" >"$TMP/fw-ioc"
		while IFS="$TAB" read -r p f; do
			add IOC fw-rule "$p:SDWAN_IP_MAPPING" "rule left by the command of the reported remote shell: $f"
		done <"$TMP/fw-ioc"
	fi
	if command -v nft >/dev/null 2>&1 && nft list ruleset >"$TMP/nft-ruleset.txt" 2>/dev/null; then
		# with iptables-nft the same rules appear in both; show the nft view only without iptables
		[ -s "$TMP/iptables-save.txt" ] || grep -E 'dnat|redirect|SDWAN_IP_MAPPING' "$TMP/nft-ruleset.txt" | sed 's/^[[:space:]]*/nft: /' >>"$TMP/fw-redirect"
		if [ ! -s "$TMP/fw-ioc" ] && grep -qE 'daddr 127\.0\.0\.1 .*dnat to 127\.0\.0\.1' "$TMP/nft-ruleset.txt"; then
			add REVIEW fw-rule "nft" "a rule redirects 127.0.0.1 to 127.0.0.1, like the command of the reported remote shell (see Firewall)"
		fi
	fi
	return 0
}

# Byte order of this machine, from the ELF header of the running shell (byte 5: 1 = little
# endian, 2 = big endian). /proc/net/tcp prints addresses in the machine's byte order, and
# some GL.iNet routers (MIPS) are big endian.
BIG_ENDIAN=0
case $(dd if=/proc/self/exe bs=1 skip=5 count=1 2>/dev/null | tr '\001\002' 'LB') in B) BIG_ENDIAN=1 ;; esac

decode_tcp() {
	# established IPv4 and IPv6 connections from /proc/net/tcp and tcp6 with the owning
	# process. Input: socket owners, then the tcp tables. An IPv6 address that only wraps
	# an IPv4 one (::ffff:a.b.c.d, a dual-stack socket) is shown as IPv4.
	local files=/proc/net/tcp
	[ -r /proc/net/tcp6 ] && files="$files /proc/net/tcp6"
	# shellcheck disable=SC2086 # $files is a list
	awk -v be="$BIG_ENDIAN" '
		function h(s,  i,n){n=0; s=toupper(s); for(i=1;i<=length(s);i++) n=n*16+index("0123456789ABCDEF",substr(s,i,1))-1; return n}
		# the four bytes of one 32-bit word in network order
		function word(x){return be ? x : substr(x,7,2) substr(x,5,2) substr(x,3,2) substr(x,1,2)}
		function ip4(w){return h(substr(w,1,2)) "." h(substr(w,3,2)) "." h(substr(w,5,2)) "." h(substr(w,7,2))}
		function ip(x,  i,w,o,g){
			if (length(x) == 8) return ip4(word(x))
			w = ""; for (i = 0; i < 4; i++) w = w word(substr(x, i*8+1, 8))
			w = tolower(w)
			if (substr(w,1,24) == "00000000000000000000ffff") return ip4(substr(w,25,8))
			o = ""; for (i = 0; i < 8; i++) { g = substr(w, i*4+1, 4); sub(/^0+/, "", g); o = o (i ? ":" : "") (g == "" ? "0" : g) }
			return "[" o "]"
		}
		FNR==1 {nfile++}
		nfile==1 {own[$1]=$2 "/" $3; next}
		FNR>1 && $4=="01" {split($2,a,":"); split($3,b,":");
			printf "%s:%d -> %s:%d  %s\n", ip(a[1]), h(a[2]), ip(b[1]), h(b[2]), ($10 in own ? own[$10] : "?")}' \
		"$TMP/sockets" $files 2>/dev/null
}

detect() {
	FIND=$1
	: >"$FIND"
	STEP=0
	progress "marker files of the malware"; check_markers
	progress "replaced system tools"; check_applets
	progress "autostart entries"; check_persist
	progress "running processes"; check_procs
	progress "files in /tmp"; check_tmp
	progress "firewall"; check_firewall
	progress "network connections"
	if [ "$LIVE" = 1 ] && [ -r /proc/net/tcp ]; then
		decode_tcp >"$TMP/conns"
		grep -F -- "-> $SHELL_NET" "$TMP/conns" | while IFS= read -r line; do
			add IOC connection "${SHELL_NET}0/24" "open connection to the network of the reported remote shell ($SHELL_IP): $line"
		done
		grep -vF -- "-> $SHELL_NET" "$TMP/conns" | grep -E "$CONN_RE" | while IFS= read -r line; do
			add REVIEW connection "${line##* }" "connection held by a shell or a netcat-like tool: $line"
		done
	fi
	progress "other changes in the overlay"; check_review
	progress "stored keys and VPN profiles"; check_credentials
	progress_end
}

count() { grep -c "^$1${TAB}" "$FIND"; }

level_color() {
	case $1 in IOC) printf '%s' "$RED" ;; PERSIST) printf '%s' "$YEL" ;; REVIEW) printf '%s' "$CYA" ;; *) printf '%s' "$D" ;; esac
}

# "IOC=3", coloured like its level unless the count is 0
tally() {
	local n
	n=$(count "$1")
	if [ "$n" -gt 0 ]; then printf '%s%s=%s%s' "$(level_color "$1")" "$1" "$n" "$N"; else printf '%s%s=0%s' "$D" "$1" "$N"; fi
}

# The head is printed before the checks start, the body when they are done.
report() { report_head; report_body; }

report_head() {
	say "${B}== gl-helper triage $VERSION${N}  ${D}(CSA-2026-01)${N}"
	kv Host "$HOST"
	kv Platform "$PLATFORM"
	kv Time "$WHEN"
	kv Mode "$MODE"
	kv Root "$ROOT"
	kv Overlay "${UPPER:-unknown}"
	kv "Base image" "${LOWER:-none}"
	kv "Trusted tools" "$TRUSTED"
	[ "$TRUSTED" = no ] && say "   ${YEL}WARNING: no usable busybox in a base image, tools come from \$PATH and could be tampered${N}"
	[ -z "$UPPER" ] && say "   ${YEL}NOTE: overlay upper layer unknown, results are less precise${N}"
	return 0
}

report_body() {
	local n_ioc lvl pat n_conn
	n_ioc=$(count IOC)
	if [ -s "$FIND" ]; then
		section "Findings"
		for lvl in IOC PERSIST REVIEW INFO; do
			[ "$(count "$lvl")" -gt 0 ] || continue
			say ""
			grep "^$lvl${TAB}" "$FIND" | awk -F '\t' -v c="$(level_color "$lvl")" -v n="$N" -v b="$B" -v d="$D" \
				'{printf "   %s%-8s%s %-15s %s%s%s\n   %24s %s%s%s\n", c, $1, n, $2, b, $3, n, "", d, $4, n}' >&3
		done
	fi
	if [ "$LIVE" = 1 ] && [ -r /proc/net/tcp ]; then
		decode_tcp >"$TMP/established"
		section "Network"
		n_conn=$(wc -l <"$TMP/established" | tr -d ' ')
		say "   Established TCP connections, IPv4 and IPv6: $n_conn ${D}(local -> remote, owning process)${N}"
		# aligned columns, connections to the reported shell address in red, at most 40 lines
		head -n 40 "$TMP/established" | awk -v ip="$SHELL_NET" -v red="$RED" -v n="$N" -v d="$D" \
			'{c = (index($3, ip) == 1) ? red : ""; printf "   %s%-21s -> %-21s%s %s%s%s\n", c, $1, $3, (c == "" ? "" : n), d, $4, n}' >&3
		[ "$n_conn" -gt 40 ] && say "   ${D}... $((n_conn - 40)) more in the archive${N}"
		pat=$(awk -F '\t' '$1=="IOC" && $2=="process" {printf "%s  %s/", sep, $3; sep="|"}' "$FIND")
		[ -n "$pat" ] && grep -E "$pat" "$TMP/established" | sed "s/^/   ${RED}IOC process connection:${N} /" >&3
	fi
	if [ -s "$TMP/fw-added" ] || [ -s "$TMP/fw-redirect" ]; then
		section "Firewall"
		if [ -s "$TMP/fw-added" ]; then
			say "   Configuration that is not in the firmware image ${D}(your own port forwards and rules are here too)${N}"
			head -n 60 "$TMP/fw-added" | awk -v b="$B" -v n="$N" '{ if ($0 ~ /^\//) printf "   %s%s%s\n", b, $0, n; else printf "   %s\n", $0 }' >&3
			[ "$(wc -l <"$TMP/fw-added")" -gt 60 ] && say "   ${D}... more in the archive${N}"
		fi
		if [ -s "$TMP/fw-redirect" ]; then
			[ -s "$TMP/fw-added" ] && say ""
			say "   Running rules that redirect traffic: $(wc -l <"$TMP/fw-redirect" | tr -d ' ') ${D}(all rules are in the archive)${N}"
			head -n 40 "$TMP/fw-redirect" | awk -v re="$FW_RULE_RE" -v red="$RED" -v n="$N" \
				'{ r = $0; sub(/^[^:]*: /, "", r); if (r ~ re) printf "   %s%s%s\n", red, $0, n; else printf "   %s\n", $0 }' >&3
			[ "$(wc -l <"$TMP/fw-redirect")" -gt 40 ] && say "   ${D}... more in the archive${N}"
		fi
	fi
	if [ -s "$TMP/creds" ]; then
		section "Credentials on this device"
		say "   Keys and VPN profiles stored here. Whoever had a shell on this device could copy them."
		say "   ${D}Not findings, and not in the anonymous report. Other passwords and tokens are not listed.${N}"
		awk -F '\t' -v b="$B" -v n="$N" -v d="$D" \
			'{printf "   %-16s %s%s%s\n   %16s %s%s%s\n", $1, b, $2, n, "", d, $3, n}' "$TMP/creds" >&3
		[ "$n_ioc" -gt 0 ] && say "   ${YEL}Indicators were found: treat all of these as copied and revoke them where they are trusted.${N}"
	fi
	section "Result"
	say "   Summary: $(tally IOC) $(tally PERSIST) $(tally REVIEW) $(tally INFO)"
	[ "$(count IOC)" -gt 0 ] && say "   ${RED}IOC${N}      a known trace of the implant. --fix removes it."
	[ "$(count PERSIST)" -gt 0 ] && say "   ${YEL}PERSIST${N}  a changed rc.local or root crontab. --fix resets it only when an IOC was found."
	[ "$(count REVIEW)" -gt 0 ] && say "   ${CYA}REVIEW${N}   an unusual change, not proof of an infection. Check whether it is yours. Never modified."
	[ "$(count INFO)" -gt 0 ] && say "   ${D}INFO     context, for example files installed by a package.${N}"
	say ""
	if [ "$n_ioc" -gt 0 ]; then
		say "   ${RED}Verdict: INFECTED - gl-helper indicators found${N}"
	else
		say "   ${GRN}${B}Verdict: no gl-helper indicators found${N}"
	fi
}

# ---------------------------------------------------------------- archive
ARCHIVE=
# Take passwords and private keys out of a copy made for the archive ($1, a directory
# below the work dir; $2, its name in the archive). The archive is meant to be handed to
# others, and none of this helps to understand the incident: /etc/shadow is summarised in
# etc/shadow-summary.txt, and the keys are listed by check_credentials. /etc/shadow goes
# always, the keys unless --with-secrets was given. UCI files keep everything but the
# value of the key options, so an added peer or profile is still visible. The hashes of
# the original files stay in overlay/upper-sha256.txt.
# find does not follow symlinks, so every path it prints is inside the copy: a link in
# the overlay that points to /etc/... can never lead this to a file of the live system.
scrub() {
	local d=${1%/} f rel
	[ -d "$d" ] || return 0
	find "$d" ! -type d 2>/dev/null | while IFS= read -r f; do
		rel=${f#"$d"/}
		case $rel in
		etc/shadow | etc/shadow[-.~]*)
			rm -f "$f" && printf 'removed\t%s/%s\n' "$2" "$rel" >>"$TMP/redacted" ;;
		esac
		[ "$SECRETS" = 1 ] && continue
		case $rel in
		root/.ssh/id_*.pub) ;;
		root/.ssh/id_* | etc/dropbear/dropbear_*_host_key | etc/openvpn/profiles/* | \
			etc/kvmd/user/zerotier/identity.secret | var/lib/zerotier-one/identity.secret | \
			etc/tailscale/tailscaled.state)
			rm -f "$f" && printf 'removed\t%s/%s\n' "$2" "$rel" >>"$TMP/redacted" ;;
		etc/config/wireguard | etc/config/wireguard_server | etc/config/zerotier)
			[ -f "$f" ] && [ ! -L "$f" ] || continue
			awk '$1 == "option" && ($2 == "private_key" || $2 == "preshared_key" || $2 == "secret") {
					print substr($0, 1, index($0, "option") - 1) "option " $2 " \047REDACTED\047"; n++; next }
				{ print }
				END { exit (n ? 0 : 1) }' "$f" >"$TMP/scrub" 2>/dev/null || continue
			cat "$TMP/scrub" >"$f" && printf 'key values replaced\t%s/%s\n' "$2" "$rel" >>"$TMP/redacted" ;;
		esac
	done
	rm -f "$TMP/scrub"
	return 0
}

collect() {
	local E list f pid size avail base_shadow
	E=$TMP/evidence
	mkdir -p "$E/meta" "$E/overlay" "$E/files" "$E/proc" "$E/net" "$E/logs" "$E/etc"
	cp "$FIND" "$E/findings.tsv"
	palette 0
	report 3>"$E/report.txt"
	palette "$COLOR"

	{
		echo "tool: gl-helper-triage $VERSION"
		echo "collected: $STAMP"
		echo "host: $HOST"
		echo "platform: $PLATFORM"
		echo "root=$ROOT upper=${UPPER:-none} lower=${LOWER:-none} trusted-busybox=$TRUSTED"
		uname -a 2>/dev/null
		if [ "$LIVE" = 1 ]; then
			echo "uptime: $(cat /proc/uptime 2>/dev/null)"
			echo "gl model: $(cat /proc/gl-hw-info/model 2>/dev/null)"
			id 2>/dev/null
		fi
	} >"$E/meta/info.txt"
	for f in etc/version etc/glversion etc/version.type etc/version.build etc/version.date etc/os-release etc/openwrt_release etc/openwrt_version etc/manifest; do
		[ -f "$(r "$f")" ] && cp "$(r "$f")" "$E/meta/$(echo "$f" | tr / _)"
	done
	if [ "$LIVE" = 1 ]; then
		cp /proc/mounts "$E/meta/mounts.txt" 2>/dev/null
		cp /proc/cmdline "$E/meta/kernel-cmdline.txt" 2>/dev/null
		df -k >"$E/meta/df.txt" 2>/dev/null
	fi

	# Overlay upper: listing with hashes always, complete copy if small and /tmp has room.
	if [ -n "$UPPER" ]; then
		find "$UPPER" -xdev -exec stat -c '%A %U:%G %s %y %N' {} + >"$E/overlay/upper-listing.txt" 2>/dev/null ||
			find "$UPPER" -xdev -exec ls -lad {} + >"$E/overlay/upper-listing.txt" 2>/dev/null
		find "$UPPER" -xdev -type f -size -51200k -exec sha256sum {} + >"$E/overlay/upper-sha256.txt" 2>/dev/null
		size=$(du -sk "$UPPER" 2>/dev/null | awk '{print $1}')
		avail=$(df -k "$TMP" 2>/dev/null | tail -n 1 | awk '{print $(NF-2)}')
		if [ "${size:-0}" -le "$FULL_UPPER_MAX_KB" ] && [ $((${size:-0} * 3)) -lt "${avail:-0}" ]; then
			mkdir -p "$E/files/upper"
			tar -C "$UPPER" -cf - . 2>/dev/null | tar -C "$E/files/upper" -xf - 2>/dev/null
			echo "complete copy of the upper layer (${size} KiB)" >"$E/overlay/README.txt"
		else
			echo "upper layer is ${size:-?} KiB (free in work dir: ${avail:-?} KiB): only finding paths copied" >"$E/overlay/README.txt"
		fi
	fi
	# Always copy the finding paths (merged view) and key files.
	list=$TMP/copylist
	awk -F '\t' '$3 ~ /^\// {print substr($3,2)}' "$FIND" >"$list"
	for f in etc/mp_ip_mapping_info $FW_PATHS $MARKER_DIRS $PERSIST etc/crontabs root/.ssh etc/dropbear/authorized_keys \
		etc/passwd etc/group etc/sysupgrade.conf lib/upgrade/keep.d; do echo "$f"; done >>"$list"
	mkdir -p "$E/files/merged"
	sort -u "$list" | while IFS= read -r f; do
		exists "$(r "$f")" || continue
		tar -C "${ROOT%/}/" -cf - "./$f" 2>/dev/null | tar -C "$E/files/merged" -xf - 2>/dev/null
	done
	# passwords and private keys do not go into the archive (see scrub)
	: >"$TMP/redacted"
	scrub "$E/files/upper" files/upper
	scrub "$E/files/merged" files/merged
	{
		echo "Left out of this archive by gl-helper-triage $VERSION, so that it can be handed on:"
		echo "the password file always (see etc/shadow-summary.txt), private keys unless the"
		echo "script ran with --with-secrets (this run: $([ "$SECRETS" = 1 ] && echo with || echo without) --with-secrets)."
		echo "The SHA-256 of the original files is in overlay/upper-sha256.txt."
		echo
		if [ -s "$TMP/redacted" ]; then cat "$TMP/redacted"; else echo "(nothing had to be left out)"; fi
	} >"$E/REDACTED.txt"
	# shadow: whether a hash changed, never the hash itself
	if [ -r "$(r etc/shadow)" ]; then
		base_shadow=/dev/null
		[ -n "$LOWER" ] && [ -r "$(l etc/shadow)" ] && base_shadow=$(l etc/shadow)
		awk -F: 'NR==FNR {b[$1]=$2; next}
			{st = ($1 in b) ? (b[$1]==$2 ? "same as base" : "CHANGED vs base") : "not in base"
			 printf "%s\t%s\tlastchg=%s\n", $1, ($2 ~ /^[!*]/ || $2=="" ? "locked/empty" : "hash set, " st), $3}' \
			"$base_shadow" "$(r etc/shadow)" >"$E/etc/shadow-summary.txt" 2>/dev/null
	fi

	if [ "$LIVE" = 1 ]; then
		cp "$TMP/procs" "$E/proc/all-processes.tsv" 2>/dev/null
		cp "$TMP/sockets" "$E/net/socket-owners.tsv" 2>/dev/null
		awk -F '\t' '($1=="IOC" || $2=="deleted-exe") && $3 ~ /^[0-9]+$/ {print $3}' "$FIND" | sort -u | while read -r pid; do
			[ -d "/proc/$pid" ] || continue
			mkdir -p "$E/proc/$pid"
			for f in cmdline environ status maps stat; do cat "/proc/$pid/$f" >"$E/proc/$pid/$f" 2>/dev/null; done
			readlink "/proc/$pid/exe" >"$E/proc/$pid/exe.link" 2>/dev/null
			readlink "/proc/$pid/cwd" >"$E/proc/$pid/cwd.link" 2>/dev/null
			ls -l "/proc/$pid/fd" >"$E/proc/$pid/fd.txt" 2>/dev/null
			cat "/proc/$pid/exe" >"$E/proc/$pid/exe.bin" 2>/dev/null
		done
		for f in tcp tcp6 udp udp6 raw raw6 unix route arp; do cat "/proc/net/$f" >"$E/net/$f" 2>/dev/null; done
		decode_tcp >"$E/net/tcp-established.txt"
		for f in iptables-save.txt ip6tables-save.txt nft-ruleset.txt; do
			[ -s "$TMP/$f" ] && cp "$TMP/$f" "$E/net/$f"
		done
		dmesg >"$E/logs/dmesg.txt" 2>/dev/null
		command -v logread >/dev/null 2>&1 && logread >"$E/logs/logread.txt" 2>/dev/null
		for f in /var/log/messages /var/log/messages.0 /var/log/messages.1 /userdata/log/messages; do
			[ -f "$f" ] && cp "$f" "$E/logs/$(echo "${f#/}" | tr / _)" 2>/dev/null
		done
	fi

	(cd "$E" && find . -type f -exec sha256sum {} + >"$TMP/manifest") && mv "$TMP/manifest" "$E/MANIFEST.sha256"

	if [ "$STDOUT" = 1 ]; then
		tar -C "$TMP" -czf - evidence || die "writing archive to stdout failed"
		say "   Evidence archive written to stdout."
		secrets_note
		return 0
	fi
	mkdir -p "$OUTDIR" || die "cannot create $OUTDIR"
	ARCHIVE=$OUTDIR/gl-triage-$HOST-$STAMP.tar.gz
	tar -C "$TMP" -czf "$ARCHIVE" evidence || { rm -f "$ARCHIVE"; die "writing $ARCHIVE failed"; }
	tar -tzf "$ARCHIVE" >/dev/null 2>&1 || die "archive verification failed: $ARCHIVE"
	(cd "$OUTDIR" && sha256sum "${ARCHIVE##*/}" >"${ARCHIVE##*/}.sha256")
	section "Evidence archive"
	kv File "${B}$ARCHIVE${N}"
	kv sha256 "$(cut -d ' ' -f1 "$ARCHIVE.sha256")"
	secrets_note
	case $OUTDIR in /tmp | /tmp/* | /var/run* | /run* | /var/tmp*)
		say "   ${YEL}/tmp is RAM: copy it off the device before rebooting.${N}" ;;
	esac
}

# What the archive holds in the way of secrets, said where the archive is announced.
secrets_note() {
	local n
	n=$(wc -l <"$TMP/redacted" 2>/dev/null | tr -d ' ')
	if [ "$SECRETS" = 1 ]; then
		say "   ${YEL}--with-secrets: the archive holds the private keys of this device. Do not pass it on.${N}"
	elif [ "${n:-0}" -gt 0 ]; then
		say "   ${D}Left out: the password file and private keys, $n file(s), listed in REDACTED.txt (--with-secrets keeps the keys).${N}"
	fi
	say "   ${D}It still holds the configuration, which can include Wi-Fi keys and other passwords.${N}"
}

# ---------------------------------------------------------------- fix
restore_from_lower() {
	local p="$1"
	rm -rf "$(r "$p")" || return 1
	if [ -n "$LOWER" ] && exists "$(l "$p")"; then
		cp -a "$(l "$p")" "$(r "$p")" && act "restored /$p from base image"
	else
		act "removed /$p (not in base image)"
	fi
}

fix() {
	local pid p f failed=0
	if [ "$LIVE" = 1 ] && [ "$(id -u)" != 0 ]; then die "--fix needs root"; fi
	if [ "$(count IOC)" = 0 ]; then
		say ""
		say "   No IOC found, nothing to remediate. REVIEW items were not touched."
		return 0
	fi
	section "Remediation"
	# 1. processes: freeze all first so they cannot restart each other, then kill
	awk -F '\t' '$1=="IOC" && $2=="process" {print $3}' "$FIND" | sort -u >"$TMP/pids"
	while read -r pid; do kill -STOP "$pid" 2>/dev/null; done <"$TMP/pids"
	while read -r pid; do kill -KILL "$pid" 2>/dev/null && act "killed pid $pid"; done <"$TMP/pids"
	# 2. the implant's own files
	for p in $MARKER_DIRS; do
		exists "$(r "$p")" || continue
		if rm -rf "$(r "$p")"; then act "removed /$p"; else failed=1; fi
	done
	if [ -p "$(r tmp/f)" ] && grep -q "^IOC${TAB}pipe${TAB}" "$FIND"; then
		if rm -f "$(r tmp/f)"; then act "removed the pipe /tmp/f"; else failed=1; fi
	fi
	# 3. persistence, only because an IOC was found (same set as the vendor cleanup)
	for p in $PERSIST; do
		exists "$(src "$p")" || continue
		same_as_lower "$p" && continue
		restore_from_lower "$p" || failed=1
		say "     ${D}(previous version: files/merged/$p in the archive)${N}"
	done
	# 4. other files that start the implant (init scripts, hotplug, profile, ...)
	#    and replaced applets: put the base image version back or remove them
	awk -F '\t' '$1=="IOC" && ($2=="persist-ref" || $2=="applet-hijack") {print substr($3,2)}' "$FIND" |
		while IFS= read -r p; do
			case " $PERSIST " in *" $p "*) continue ;; esac
			exists "$(r "$p")" || continue
			restore_from_lower "$p" || echo fail >>"$TMP/fixfail"
			case $p in etc/init.d/*) exists "$(r "$p")" || echo "${p##*/}" >>"$TMP/removed-init" ;; esac
		done
	[ -f "$TMP/fixfail" ] && failed=1
	# 5. OpenWrt: service links to init scripts removed in step 4
	if [ -s "$TMP/removed-init" ] && [ -d "$(r etc/rc.d)" ]; then
		for f in "$(r etc/rc.d)"/*; do
			[ -L "$f" ] || continue
			grep -qxF "$(readlink "$f" | sed 's#.*/##')" "$TMP/removed-init" || continue
			rm -f "$f" && act "removed service link /etc/rc.d/${f##*/}"
		done
	fi
	# 6. sysupgrade keep lists: drop only the lines that keep implant paths
	awk -F '\t' '$1=="IOC" && $2=="keep-ref" {print substr($3,2)}' "$FIND" | while IFS= read -r p; do
		f=$(r "$p")
		[ -f "$f" ] || continue
		grep -vE "$IOC_RE" "$f" >"$TMP/keep.new"
		cat "$TMP/keep.new" >"$f" && act "removed gl-helper lines from /$p" || echo fail >>"$TMP/fixfail"
	done
	[ -f "$TMP/fixfail" ] && failed=1
	# 7. the firewall rule that the command of the reported remote shell left behind
	if [ "$LIVE" = 1 ] && [ -s "$TMP/fw-ioc" ]; then
		while IFS="$TAB" read -r p f; do
			# shellcheck disable=SC2086 # the saved rule is a list of iptables arguments
			if iptables -t "$p" $(printf '%s' "$f" | sed 's/^-A /-D /') 2>/dev/null; then
				act "removed firewall rule ($p): $f"
			else
				echo fail >>"$TMP/fixfail"
			fi
		done <"$TMP/fw-ioc"
	fi
	[ -f "$TMP/fixfail" ] && failed=1
	# 8. make cron forget a removed crontab (KVM: S50crond, OpenWrt: cron)
	if [ "$LIVE" = 1 ]; then
		for s in /etc/init.d/S50crond /etc/init.d/cron; do
			[ -x "$s" ] && "$s" restart >/dev/null 2>&1 && act "restarted cron ($s)" && break
		done
		sync
	fi
	return $failed
}

recommend() {
	section "Next steps"
	say "   - Copy the evidence archive off the device and keep it."
	case $PLATFORM in
	openwrt)
		say "   - Update the firmware WITHOUT keeping settings: OpenWrt keeps /etc/config across"
		say "     sysupgrade, and the implant hides in /etc/config/.gl."
		say "   - A factory reset (firstboot / reset button) wipes the whole overlay and is the safe option."
		say "   - Check every client that used this router as gateway or DNS." ;;
	glkvm-*)
		say "   - Install GL.iNet's security firmware. Only RM1PE 1.10.2 removes these IOCs at boot;"
		say "     an update that keeps settings also keeps the password, SSH keys and /etc/kvmd/user."
		say "   - A factory reset is still recommended: this cleanup only removes known IOCs."
		say "   - Check the computer connected to the KVM (unknown software, accounts, autostart)." ;;
	*)
		say "   - Update the firmware and do a factory reset: this cleanup only removes known IOCs." ;;
	esac
	say "   - Change the device password, the GL.iNet cloud account password and SSH keys."
	say "   - Everything this device held a key for is exposed too: remove its VPN profile on the"
	say "     server or with the VPN provider and create a new one, and remove its SSH keys from"
	say "     every machine that trusts them."
	[ -s "$TMP/creds" ] && say "     What was found on this device is listed above under \"Credentials on this device\"."
	return 0
}

# ---------------------------------------------------------------- anonymous report
# A few facts for the community's picture of the incident. Built from the first scan,
# before anything is changed. When indicators were found it also carries what the attacker
# left: the changed lines of autostart files, the firewall rules of the chain the attack
# used, and the command lines of its processes. All of it is shown before it is sent.
# JSON string of free text: printable ASCII only, tabs become spaces, quotes escaped.
jtxt() { printf '"%s"' "$(printf '%s' "$1" | tr '\t' ' ' | tr -cd '\40-\176' | cut -c1-"${2:-300}" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }
jlines() { while IFS= read -r line; do printf '%s,' "$(jtxt "$line" "${1:-300}")"; done | sed 's/,$//'; }

jstr() { printf '"%s"' "$(printf '%s' "$1" | tr -cd 'A-Za-z0-9 ._:/+@=,()-' | cut -c1-"${2:-64}")"; }

build_report() {
	local model fw up quick started ports ptime list files stime f persist rules cmds kind mac devid n
	# Device ID: the hardware address of the first network interface, hashed. The address
	# itself never leaves the device.
	devid=''
	if [ "$DEVICE_ID" = 1 ]; then
		mac=$(cat /sys/class/net/eth0/address 2>/dev/null)
		if [ -z "$mac" ] || [ "$mac" = 00:00:00:00:00:00 ]; then
			mac=$(for f in /sys/class/net/*/address; do case $f in */lo/address) continue ;; esac; cat "$f" 2>/dev/null; done | grep -v '^00:00:00:00:00:00$' | sort | head -n 1)
		fi
		[ -n "$mac" ] && devid=$(printf 'csa-2026-01:%s' "$mac" | tr 'A-F' 'a-f' | sha256sum 2>/dev/null | cut -c1-16)
	fi
	model=$(cat /proc/gl-hw-info/model 2>/dev/null)
	[ -n "$model" ] || model=$(cat /tmp/sysinfo/model 2>/dev/null)
	# GL.iNet re-issues builds under the same version number, so the build tells them
	# apart: "4.8.3 release2 build 1024 2026-05-29"
	fw=$(cat "$(r etc/glversion)" 2>/dev/null)
	if [ -n "$fw" ]; then
		f=$(cat "$(r etc/version.type)" 2>/dev/null); [ -n "$f" ] && fw="$fw $f"
		f=$(cat "$(r etc/version.build)" 2>/dev/null); [ -n "$f" ] && fw="$fw build $f"
		f=$(cut -c1-10 "$(r etc/version.date)" 2>/dev/null); [ -n "$f" ] && fw="$fw $f"
	fi
	# KVM devices keep it in /etc/version: RK_VERSION=V1.10.2 release1
	[ -n "$fw" ] || fw=$(sed -n 's/^RK_VERSION=//p' "$(r etc/version)" 2>/dev/null | head -n 1)
	up=$(cut -d. -f1 /proc/uptime 2>/dev/null)
	quick=false
	grep -q "^IOC${TAB}process${TAB}[0-9]*${TAB}GL.iNet's quick check" "$FIND" && quick=true
	started=$(grep "^IOC${TAB}process${TAB}[0-9]*${TAB}remote shell" "$FIND" |
		sed -n 's/.*started \([0-9-]* [0-9:]* UTC\).*/\1/p' | sort | head -n 1)
	ports=$(grep "^IOC${TAB}" "$FIND" | grep -oE '170\.39\.226\.[0-9]+[: ][0-9]+' | sed 's/.*[: ]//' | sort -un | head -n 10 | tr '\n' ',' | sed 's/,$//')
	ptime=$(grep "^IOC${TAB}pipe${TAB}" "$FIND" | sed -n 's/.*last data \([0-9-]* [0-9:]* UTC\).*/\1/p' | head -n 1)
	# kind and what was found: a path or a name. For a process, what sort it is and its
	# binary, never its number or its full command line.
	list=$(awk -F '\t' '$1=="IOC" || $1=="PERSIST" {
			if ($2 != "process") { print $2 " " $3; next }
			exe = ""; if (match($4, /exe=[^ ]+/)) exe = " " substr($4, RSTART + 4, RLENGTH - 4)
			if ($4 ~ /^GL.iNet.s quick check/) print "process quick-check"
			else if ($4 ~ /^remote shell/) print "process remote-shell"
			else if ($4 ~ /^runs replaced applet/) print "process replaced-tool" exe
			else print "process implant" exe
		}' "$FIND" | sort -u | head -n 30 |
		while IFS= read -r line; do printf '%s,' "$(jstr "$line" 120)"; done | sed 's/,$//')
	# fingerprints of the implant's own files and of replaced system tools: the hash shows
	# whether everyone has the same variant, the time when it arrived
	files=$(awk -F '\t' '$1=="IOC" && ($2=="marker" || $2=="applet-hijack") {print $3}' "$FIND" | sort -u | head -n 12 |
		while IFS= read -r f; do
			[ -f "$(r "${f#/}")" ] && [ ! -L "$(r "${f#/}")" ] || continue
			printf '{"path": %s, "sha256": %s, "size": %s, "mtime": %s, "ctime": %s},' "$(jstr "$f" 120)" \
				"$(jstr "$(sha256sum "$(r "${f#/}")" 2>/dev/null | cut -c1-64)")" \
				"$(cat "$(r "${f#/}")" 2>/dev/null | wc -c | tr -d ' ')" "$(jstr "$(file_time "$(r "${f#/}")")")" "$(jstr "$(file_ctime "$(r "${f#/}")")")"
		done | sed 's/,$//')
	stime=
	[ -f "$(r etc/mp_ip_mapping_info)" ] && stime=$(file_time "$(r etc/mp_ip_mapping_info)")
	# What the attacker left, only when indicators were found. /etc/rc.local in full (up
	# to 60 lines); other autostart files: the lines that are not in the base image (up to
	# 20 per file); from the lists of files a firmware update keeps only the lines that
	# name the implant, the rest is yours.
	persist='' rules='' cmds=''
	: >"$TMP/rlines"   # the same lines as plain text, to show before asking
	if [ "$(count IOC)" -gt 0 ]; then
		persist=$(awk -F '\t' '$2=="persist-ref" || $2=="keep-ref" || $2=="persistence" {print $2 "\t" $3}' "$FIND" | sort -u -k2 | head -n 6 |
			while IFS="$TAB" read -r kind f; do
				[ -f "$(r "${f#/}")" ] || continue
				n=20
				if [ "$kind" = keep-ref ]; then
					grep -E "$IOC_RE" "$(r "${f#/}")"
				elif [ "$f" = /etc/rc.local ]; then
					# the whole file: what stands around the attacker's line matters too
					n=60; cat "$(r "${f#/}")"
				elif [ -n "$LOWER" ] && [ -f "$(l "${f#/}")" ]; then
					grep -vxFf "$(l "${f#/}")" "$(r "${f#/}")"
				else
					cat "$(r "${f#/}")"
				fi 2>/dev/null | grep -v '^[[:space:]]*$' | head -n "$n" >"$TMP/plines"
				sed "s|^|$f:  |" "$TMP/plines" >>"$TMP/rlines"
				printf '{"path": %s, "lines": [%s]},' "$(jstr "$f" 120)" "$(jlines <"$TMP/plines")"
			done | sed 's/,$//')
		# the chain the reported attack writes to, as it is now
		if [ -s "$TMP/fw-rules" ]; then
			awk -F '\t' '$2 ~ /^-A SDWAN_IP_MAPPING / {print "firewall " $1 ": " $2}' "$TMP/fw-rules" | head -n 10 >"$TMP/rfw"
			cat "$TMP/rfw" >>"$TMP/rlines"
			rules=$(sed 's/^firewall //' "$TMP/rfw" | jlines)
		fi
		cmds=$(grep "^IOC${TAB}process${TAB}" "$FIND" | sed -n 's/.* cmd=//p' | sort -u | head -n 5 | jlines 400)
	fi
	cat >"$TMP/report.json" <<EOF
{
"schema": 5,
"tool": $(jstr "$VERSION" 16),
"platform": $(jstr "$PLATFORM" 48),
"model": $(jstr "${model:-unknown}"),
"firmware": $(jstr "${fw:-unknown}" 48),
"checked_at": $(jstr "$WHEN"),
"uptime_s": ${up:-0},
"ioc": $(count IOC),
"persist": $(count PERSIST),
"review": $(count REVIEW),
"findings": [$list],
"quick_check": $quick,
"shell_started": $(jstr "$started"),
"shell_ports": [$ports],
"pipe_time": $(jstr "$ptime"),
"state_file_time": $(jstr "$stime"),
"files": [$files],
"persistence": [$persist],
"fw_rules": [$rules],
"commands": [$cmds],
"device_id": $(jstr "$devid")
}
EOF
}

send_report() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsS -m 20 -o /dev/null -H 'Content-Type: application/json' --data-binary "@$TMP/report.json" "$REPORT_URL" 2>/dev/null
	elif command -v wget >/dev/null 2>&1; then
		wget -q -T 20 -O /dev/null --header='Content-Type: application/json' --post-file="$TMP/report.json" "$REPORT_URL" 2>/dev/null ||
			wget -q -T 20 -O /dev/null --header='Content-Type: application/json' --post-data="$(cat "$TMP/report.json")" "$REPORT_URL" 2>/dev/null
	else
		return 1
	fi
}

# Offered at the very end on a live device, with or without indicators: clean devices
# show which models and firmware versions were not hit. The summary says in a
# few lines what the report holds. The lines taken from the user's own files and firewall
# are always shown word for word: they are the only part that can hold a secret of theirs.
offer_report() {
	local answer n ioc extra
	[ "$LIVE" = 1 ] && [ "$REPORT" != no ] && [ -s "$TMP/report.json" ] || return 0
	if [ "$REPORT" = show ]; then
		section "Anonymous report (not sent)"
		sed 's/^/   /' "$TMP/report.json" >&3
		return 0
	fi
	ioc=$(sed -n 's/^"ioc": \(.*\),$/\1/p' "$TMP/report.json")
	section "Anonymous report (optional)"
	# yellow, so the offer stands apart from the result above; short, "v" shows everything
	ysay() { say "   ${YEL}$*${N}"; }
	extra=''
	grep -q '^"shell_started": "..*",$' "$TMP/report.json" && extra="$extra, shell start and port"
	n=$(grep -o '"sha256"' "$TMP/report.json" | wc -l | tr -d ' ')
	[ "$n" -gt 0 ] && extra="$extra, fingerprints of $n file(s)"
	grep -q '^"commands": \[\],$' "$TMP/report.json" || extra="$extra, the attacker's commands"
	if [ "$ioc" = 0 ]; then
		ysay "Nothing known was found. Sending that helps too: it shows which devices were not hit."
		ysay "Sent: model, firmware, time of the check and that no known traces were found."
	else
		ysay "Help the community see which devices were hit and how."
		ysay "Sent: model, firmware, time of the check and the $ioc known traces above."
		[ -n "$extra" ] && ysay "Also: ${extra#, }."
	fi
	grep -q '^"device_id": "..*"$' "$TMP/report.json" && ysay "And a device ID (a hash, not an address), so repeated reports count once."
	if [ -s "$TMP/rlines" ]; then
		ysay "And these lines from your autostart files (rc.local in full) and firewall:"
		sed 's/^/        /' "$TMP/rlines" >&3
		ysay "If one of them is a password or token of yours, do not send."
	fi
	ysay "Not sent: host name, IP or MAC addresses, keys, any other file."
	if [ "$REPORT" != yes ]; then
		if [ -t 0 ] && [ -t 3 ]; then
			while :; do
				say ""
				printf '   %sSend it? [y/N, v = show the complete report]%s ' "$B" "$N" >&3
				read -r answer || answer=
				case $answer in
				v | V) sed 's/^/      /' "$TMP/report.json" >&3 ;;
				y | Y | yes | Yes | YES) break ;;
				*) say "   Not sent."; return 0 ;;
				esac
			done
		else
			say ""
			say "   Not sent. To send it, run the script again with --report (--show-report prints all of it)."
			return 0
		fi
	fi
	if send_report; then act "Sent. Thank you."; else say "   ${YEL}Could not send the report (no connection, or no curl or wget). Nothing was sent.${N}"; fi
}

finish() { offer_report; exit "$1"; }

# ---------------------------------------------------------------- main
report_head
detect "$TMP/findings"
[ "$LIVE" = 1 ] && build_report
case $MODE in
check)
	report_body
	[ "$(count IOC)" -gt 0 ] && { recommend; finish 1; }
	finish 0
	;;
archive)
	report_body
	collect
	[ "$(count IOC)" -gt 0 ] && finish 1
	finish 0
	;;
fix)
	report_body
	collect
	{ [ -n "$ARCHIVE" ] && [ -s "$ARCHIVE" ]; } || die "no verified archive, refusing to change anything"
	[ "$(count IOC)" -gt 0 ] || { fix; finish 0; }
	fix
	FIXRC=$?
	sleep 2
	section "Re-check after remediation"
	detect "$TMP/findings.after"
	if [ "$(count IOC)" -gt 0 ]; then
		grep "^IOC${TAB}" "$FIND" | awk -F '\t' '{printf "   still present: %s %s %s\n", $2, $3, $4}' >&3
		say "   ${RED}Verdict: remediation INCOMPLETE${N}"
		recommend
		finish 3
	fi
	if [ "$FIXRC" != 0 ]; then say "   ${YEL}Verdict: IOCs gone, but some steps reported errors${N}"; recommend; finish 3; fi
	say "   ${GRN}${B}Verdict: no gl-helper indicators left${N}"
	recommend
	finish 2
	;;
esac
