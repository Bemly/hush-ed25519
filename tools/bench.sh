#!/bin/sh
# hush-ed25519 benchmark — run inside the target environment, e.g.
#   docker run --rm -v "$PWD":/w busybox:musl sh /w/tools/bench.sh
cd "$(dirname "$0")/.." || exit 1
. ./lib/ed25519.sh

_t="${TMPDIR:-/tmp}/ed-bench.$$"
mkdir -p "$_t" || exit 1
printf 'hush-ed25519 benchmark payload' >"$_t/msg"

SEED=9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
PUB="$(ed25519_pub_hex "$SEED")"
SIG="$(ed25519_sign_hex "$SEED" "$_t/msg")"

# centisecond clock from /proc/uptime (busybox date has no %N)
_now() {
	read -r _u _rest </proc/uptime
	printf '%s%s' "${_u%.*}" "${_u#*.}"
}

_bench() {
	_label="$1" _n="$2" _cmd="$3"
	_s="$(_now)"
	_i=0
	while [ $_i -lt "$_n" ]; do
		eval "$_cmd" >/dev/null 2>&1
		_i=$((_i + 1))
	done
	_e="$(_now)"
	_total=$(( (_e - _s) * 10 ))
	printf '%-10s %2d run(s)  %6d ms total  %6d ms/op\n' "$_label" "$_n" "$_total" $((_total / _n))
}

_bench sign 3 "ed25519_sign_hex $SEED $_t/msg"
_bench verify 3 "ed25519_verify_hex $PUB $_t/msg $SIG"
_bench pub 1 "ed25519_pub_hex $SEED"

rm -rf "$_t"
