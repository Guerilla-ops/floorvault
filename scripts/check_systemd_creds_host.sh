#!/usr/bin/env bash
# scripts/check_systemd_creds_host.sh
#
# Checks `secrets init --custody systemd-creds` on a real Linux host: does the
# sealed key unseal in the contexts an agent or MCP server actually runs in?
# CI can only test this against a stand-in for systemd-creds.
#
# It creates a throwaway store under $HOME (not /tmp, which a service may see
# privately), stores one random test value, then runs
#     floorvault run -e FV_CHECK=fv:check -- printenv FV_CHECK
# in each context below and compares the output. Nothing else is touched; the
# store is deleted on exit. Run it as the user that will own the real vault.
#
#   shell    this shell
#   bare     cron-like: empty environment, no terminal, new session
#   user     a user service (systemd-run --user); needs a user manager
#   system   a system service running as you, outside any login session
#            (sudo systemd-run --uid); only with --with-sudo
#   cron     a real one-minute cron job; only with --with-cron, which adds a
#            marked line to your crontab and removes it again
#   ssh      a non-interactive `ssh HOST cmd` back into this machine (the
#            store is local); only with --with-ssh [HOST], default localhost
#
# Usage: scripts/check_systemd_creds_host.sh [--with-sudo] [--with-cron]
#                                           [--with-ssh [HOST]]
# Set FLOORVAULT=/path/to/floorvault to choose the binary (default: PATH).
# Exit status: 0 all run contexts passed, 1 a context failed, 2 the host
# cannot run the check (not Linux, systemd older than 256, no floorvault).
set -euo pipefail

WITH_SUDO=0 WITH_CRON=0 SSH_HOST=""
while [ $# -gt 0 ]; do
    case "$1" in
        --with-sudo) WITH_SUDO=1 ;;
        --with-cron) WITH_CRON=1 ;;
        --with-ssh)
            if [ $# -gt 1 ] && [ "${2#-}" = "$2" ]; then SSH_HOST="$2"; shift; else SSH_HOST=localhost; fi ;;
        -h|--help) sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

die() { echo "cannot run the check: $*" >&2; exit 2; }

[ "$(uname -s)" = Linux ] || die "systemd-creds custody is Linux only"
SDCREDS=""
for dir in /usr/bin /bin /usr/sbin /sbin /run/current-system/sw/bin; do
    if [ -x "$dir/systemd-creds" ]; then SDCREDS="$dir/systemd-creds"; break; fi
done
[ -n "$SDCREDS" ] || die "no systemd-creds in the system directories floorvault searches"
SD_VERSION="$("$SDCREDS" --version | sed -n '1s/^systemd \([0-9]*\).*/\1/p')"
[ -n "$SD_VERSION" ] || die "could not read the systemd version"
[ "$SD_VERSION" -ge 256 ] || die "systemd $SD_VERSION; \`systemd-creds --user\` needs 256 or newer"
FV="${FLOORVAULT:-$(command -v floorvault || true)}"
[ -n "$FV" ] && [ -x "$FV" ] || die "floorvault not found; install it or set FLOORVAULT=/path/to/floorvault"
case "$FV" in /*) ;; *) FV="$(cd "$(dirname "$FV")" && pwd)/$(basename "$FV")" ;; esac

echo "== Host"
echo "systemd:        $SD_VERSION ($SDCREDS)"
if [ "$SD_VERSION" -ge 259 ]; then
    echo "null-key check: decrypt passes --refuse-null"
else
    echo "null-key check: none before systemd 259 (file owner and mode only)"
fi
if "$SDCREDS" has-tpm2 --quiet 2>/dev/null; then
    echo "TPM2:           available (systemd may bind the credential to it)"
else
    echo "TPM2:           not usable; expect a host-key-only binding"
fi
FV_PY="$(sed -n '1s/^#! *//p' "$FV")"
FV_VERSION="$("$FV_PY" -c 'import importlib.metadata as m; print(m.version("floorvault"))' 2>/dev/null || echo 'version unknown')"
echo "floorvault:     $FV ($FV_VERSION)"
echo "user:           $(id -un) (uid $(id -u))"
if command -v loginctl >/dev/null 2>&1; then
    echo "linger:         $(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null || echo unknown)"
fi
echo

WORK="$(mktemp -d "$HOME/.fv-sdcreds-check.XXXXXX")"
CRON_MARK="# fv-sdcreds-check $(basename "$WORK")"
cleanup() {
    if [ "$WITH_CRON" = 1 ] && crontab -l >/dev/null 2>&1; then
        crontab -l | grep -vF "$CRON_MARK" | crontab - || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT
chmod 700 "$WORK"
VAULT="$WORK/vault"

echo "== Setup (throwaway store in $WORK)"
if ! "$FV" secrets init --vault "$VAULT" --custody systemd-creds; then
    echo "FAIL: \`secrets init\` could not seal and unseal a key even from this shell." >&2
    exit 1
fi
EXPECTED="fv-check-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
printf 'value=%s\n' "$EXPECTED" | "$FV" secrets add "systemd-creds host check" --id check --vault "$VAULT" --stdin >/dev/null
echo

PROBE=("$FV" run --vault "$VAULT" -e FV_CHECK=fv:check -- /usr/bin/env printenv FV_CHECK)
FAILS=0
report() {  # name, status, detail
    printf '%-7s %-5s %s\n' "$1" "$2" "$3"
    [ "$2" = FAIL ] && FAILS=$((FAILS + 1))
    return 0
}
judge() {  # name, output file, exit status
    local got
    got="$(head -n1 "$2" 2>/dev/null || true)"
    if [ "$3" = 0 ] && [ "$got" = "$EXPECTED" ]; then
        report "$1" PASS "value unsealed and delivered"
    else
        report "$1" FAIL "exit $3: $(grep -v -xF "$EXPECTED" "$2" 2>/dev/null | tail -n 2 | tr '\n' ' ')"
    fi
}

echo "== Results"
set +e

"${PROBE[@]}" >"$WORK/shell.out" 2>&1
judge shell "$WORK/shell.out" $?

env -i HOME="$HOME" USER="$(id -un)" LOGNAME="$(id -un)" SHELL=/bin/sh PATH=/usr/bin:/bin \
    setsid -w "${PROBE[@]}" </dev/null >"$WORK/bare.out" 2>&1
judge bare "$WORK/bare.out" $?

if systemctl --user is-system-running >/dev/null 2>&1 || [ -S "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/systemd/private" ]; then
    systemd-run --user --wait --pipe --quiet --collect "${PROBE[@]}" </dev/null >"$WORK/user.out" 2>&1
    judge user "$WORK/user.out" $?
else
    report user SKIP "no user manager for this session (enable linger, or run from a login)"
fi

if [ "$WITH_SUDO" = 1 ]; then
    # The output file is meant to be written by this user, not root (SC2024).
    # shellcheck disable=SC2024
    sudo systemd-run --uid="$(id -u)" --gid="$(id -g)" --wait --pipe --quiet --collect \
        -p "Environment=HOME=$HOME" "${PROBE[@]}" </dev/null >"$WORK/system.out" 2>&1
    judge system "$WORK/system.out" $?
else
    report system SKIP "pass --with-sudo (runs one transient service as you, via sudo)"
fi

if [ "$WITH_CRON" = 1 ]; then
    if ! command -v crontab >/dev/null 2>&1; then
        report cron SKIP "no crontab command"
    else
        printf -v CMD '%q ' "${PROBE[@]}"
        { crontab -l 2>/dev/null || true
          echo "* * * * * $CMD>$WORK/cron.out 2>&1; echo \$? >$WORK/cron.rc $CRON_MARK"
        } | crontab -
        for _ in $(seq 1 75); do [ -s "$WORK/cron.rc" ] && break; sleep 1; done
        if [ -s "$WORK/cron.rc" ]; then
            judge cron "$WORK/cron.out" "$(cat "$WORK/cron.rc")"
        else
            report cron FAIL "the cron job did not run within 75 s (is cron running?)"
        fi
    fi
else
    report cron SKIP "pass --with-cron (adds a marked crontab line for about a minute)"
fi

if [ -n "$SSH_HOST" ]; then
    printf -v CMD '%q ' "${PROBE[@]}"
    ssh -o BatchMode=yes -T "$SSH_HOST" "$CMD" </dev/null >"$WORK/ssh.out" 2>&1
    judge ssh "$WORK/ssh.out" $?
else
    report ssh SKIP "pass --with-ssh [HOST] (key login back into this machine, default localhost)"
fi
set -e

echo
if [ "$FAILS" -gt 0 ]; then
    echo "$FAILS context(s) failed. systemd-creds custody is not reliable here for those."
    exit 1
fi
echo "Every context that ran unsealed the key."
