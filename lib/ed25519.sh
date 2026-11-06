# hush-ed25519 — Ed25519 sign / verify in pure shell + BusyBox awk
# Source this file: . ./lib/ed25519.sh
# Depends on: lib/awk/ed25519_engine.awk
# BusyBox applets used: awk, sha512sum, xxd, cut, dd, wc, mktemp, rm, cat
#
# No compiler, no openssl, no python, no perl. Everything is BusyBox.

# ---- error handling ----
# hush has no `local`, no arrays, no ERR trap. All library state lives in
# _ed* variables; every public function returns 0 on success, 1 on failure
# and sets _ED25519_ERROR to a one-line description.

_ED25519_ERROR=""
_ed_td=""

_ed_fail() {
	_ED25519_ERROR="$1"
	printf 'hush-ed25519: %s\n' "$1" >&2
	return 1
}

# ---- locate the awk engine ----
# 1. _ED25519_HOME override (set before sourcing)
# 2. <cwd>/hush-ed25519/lib/awk/...   (submodule inside a host project)
# 3. <cwd>/lib/awk/...                (standalone checkout)
_ed_find_awk() {
	if [ -n "$_ED25519_HOME" ] && [ -f "$_ED25519_HOME/lib/awk/ed25519_engine.awk" ]; then
		printf '%s' "$_ED25519_HOME/lib/awk/ed25519_engine.awk"; return
	fi
	for _ed_d in "$(pwd)/hush-ed25519" "$(pwd)"; do
		if [ -f "$_ed_d/lib/awk/ed25519_engine.awk" ]; then
			printf '%s' "$_ed_d/lib/awk/ed25519_engine.awk"; return
		fi
	done
	printf ''
}
_ED25519_AWK="$(_ed_find_awk)"
if [ -z "$_ED25519_AWK" ]; then
	printf 'hush-ed25519: cannot find ed25519_engine.awk. Set _ED25519_HOME before sourcing.\n' >&2
	exit 1
fi

[ "${_ED25519_DEBUG:-0}" = "1" ] && set -x

# ---- internal helpers ----

_ed_is_hex() {
	case "$1" in
		''|*[!0-9a-fA-F]*) return 1 ;;
	esac
	[ ${#1} -eq "$2" ] || return 1
	return 0
}

# _ed_lc <hex> — normalise hex to lowercase
_ed_lc() {
	printf '%s' "$1" | tr 'A-F' 'a-f'
}

_ed_mktmp() {
	_ed_td="${TMPDIR:-/tmp}/ed25519.$$"
	rm -rf "$_ed_td"
	mkdir -p "$_ed_td" || return 1
}

_ed_cleanup() {
	if [ -n "$_ed_td" ] && [ -d "$_ed_td" ]; then
		rm -rf "$_ed_td"
	fi
	_ed_td=""
}

# _ed_resolve_msg <arg> — sets _ed_msgf to a readable file holding the message.
# "-" means stdin: the data is spilled to a temp file because it is hashed twice.
_ed_resolve_msg() {
	_ed_msgf="$1"
	if [ "$1" = "-" ]; then
		_ed_mktmp || { _ed_fail "cannot create temp dir"; return 1; }
		_ed_msgf="$_ed_td/msg"
		cat >"$_ed_msgf" || { _ed_fail "cannot buffer stdin"; return 1; }
	fi
	if [ ! -f "$_ed_msgf" ]; then
		_ed_fail "message file not found: $1"
		return 1
	fi
	return 0
}

# SHA-512 over raw bytes: optional hex prefix(es) followed by an optional file.
# echo must never be used here: it appends a newline and changes the digest.
_ed_sha512() {
	{
		[ -n "$1" ] && printf '%s' "$1" | xxd -r -p
		[ -n "$2" ] && printf '%s' "$2" | xxd -r -p
		[ -n "$3" ] && cat "$3"
	} | sha512sum | cut -d' ' -f1
}

_ed_engine() {
	awk -f "$_ED25519_AWK"
}

# ---- key derivation ----

# ed25519_seed_hex <secret>
# QQ Bot callback signing key: repeat the secret until it reaches 32 bytes,
# then truncate to exactly 32 bytes. Output: 64 lowercase hex chars.
ed25519_seed_hex() {
	[ -n "$1" ] || { _ed_fail "seed_hex: empty secret"; return 1; }
	_ed_buf=""
	while [ "$(printf '%s' "$_ed_buf" | wc -c)" -lt 32 ]; do
		_ed_buf="$_ed_buf$1"
	done
	printf '%s' "$_ed_buf" | dd bs=1 count=32 2>/dev/null | xxd -p -c 256
	return 0
}

# ed25519_pub_hex <seed_hex_64> — 32-byte public key as 64 hex chars
ed25519_pub_hex() {
	_ed_is_hex "$1" 64 || { _ed_fail "pub_hex: seed must be 64 hex chars"; return 1; }
	_ed_h="$(_ed_sha512 "$(_ed_lc "$1")" "" "")"
	_ed_pub="$(printf 'pub %s\n' "$_ed_h" | _ed_engine)"
	case "$_ed_pub" in
		ERR:*|'') _ed_fail "pub_hex: engine failed ($_ed_pub)"; return 1 ;;
	esac
	printf '%s' "$_ed_pub"
}

# ---- signing ----

# ed25519_sign_hex <seed_hex_64> <msg_file|-> — 128 lowercase hex chars
ed25519_sign_hex() {
	[ $# -eq 2 ] || { _ed_fail "sign_hex: usage: ed25519_sign_hex <seed_hex> <msg_file|->"; return 1; }
	_ed_is_hex "$1" 64 || { _ed_fail "sign_hex: seed must be 64 hex chars"; return 1; }
	_ed_resolve_msg "$2" || return 1
	_ed_seed="$(_ed_lc "$1")"

	_ed_h="$(_ed_sha512 "$_ed_seed" "" "")"                      # h = SHA-512(seed)
	_ed_pre="$(printf '%s' "$_ed_h" | cut -c65-128)"      # prefix = h[32..63]
	_ed_rfull="$(_ed_sha512 "$_ed_pre" "" "$_ed_msgf")"   # r = SHA-512(prefix||msg)

	_ed_out="$(printf 'sign1 %s %s\n' "$_ed_h" "$_ed_rfull" | _ed_engine)"
	case "$_ed_out" in
		ERR:*|'') _ed_cleanup; _ed_fail "sign_hex: engine failed ($_ed_out)"; return 1 ;;
	esac
	_ed_pub="${_ed_out%% *}"
	_ed_rest="${_ed_out#* }"
	_ed_R="${_ed_rest%% *}"
	_ed_rmod="${_ed_rest#* }"

	_ed_k="$(_ed_sha512 "$_ed_R$_ed_pub" "" "$_ed_msgf")" # k = SHA-512(R||A||msg)
	_ed_S="$(printf 'sig2 %s %s %s\n' "$_ed_h" "$_ed_rmod" "$_ed_k" | _ed_engine)"
	case "$_ed_S" in
		''|*[!0-9a-f]*) _ed_cleanup; _ed_fail "sign_hex: bad scalar from engine"; return 1 ;;
	esac
	[ ${#_ed_S} -eq 64 ] || { _ed_cleanup; _ed_fail "sign_hex: bad scalar from engine"; return 1; }

	_ed_cleanup
	printf '%s%s' "$_ed_R" "$_ed_S"
	return 0
}

# ed25519_sign_secret <secret> <msg_file|-> — QQ Bot flavour: derive then sign
ed25519_sign_secret() {
	_ed_seed="$(ed25519_seed_hex "$1")" || return 1
	ed25519_sign_hex "$_ed_seed" "$2"
}

# ---- verification ----

# ed25519_verify_hex <pub_hex_64> <msg_file|-> <sig_hex_128>
# 0 = valid, 1 = invalid (reason in _ED25519_ERROR)
ed25519_verify_hex() {
	[ $# -eq 3 ] || { _ed_fail "verify_hex: usage: ed25519_verify_hex <pub> <msg_file|-> <sig>"; return 1; }
	_ed_is_hex "$1" 64 || { _ed_fail "verify_hex: public key must be 64 hex chars"; return 1; }
	_ed_is_hex "$3" 128 || { _ed_fail "verify_hex: signature must be 128 hex chars"; return 1; }
	_ed_resolve_msg "$2" || return 1
	_ed_pk="$(_ed_lc "$1")"
	_ed_sg="$(_ed_lc "$3")"

	_ed_R="$(printf '%s' "$_ed_sg" | cut -c1-64)"
	_ed_S="$(printf '%s' "$_ed_sg" | cut -c65-128)"
	_ed_k="$(_ed_sha512 "$_ed_R$_ed_pk" "" "$_ed_msgf")"
	_ed_v="$(printf 'verify %s %s %s %s\n' "$_ed_pk" "$_ed_R" "$_ed_S" "$_ed_k" | _ed_engine)"
	_ed_cleanup

	case "$_ed_v" in
		1) return 0 ;;
		0) _ED25519_ERROR="verify_hex: signature does not match"
		   printf 'hush-ed25519: signature does not match\n' >&2
		   return 1 ;;
		*) _ed_fail "verify_hex: engine failed ($_ed_v)"; return 1 ;;
	esac
}

# ed25519_verify_secret <secret> <msg_file|-> <sig_hex_128>
ed25519_verify_secret() {
	_ed_seed="$(ed25519_seed_hex "$1")" || return 1
	_ed_pub="$(ed25519_pub_hex "$_ed_seed")" || return 1
	ed25519_verify_hex "$_ed_pub" "$2" "$3"
}

# ---- short aliases ----
ed_seed() { ed25519_seed_hex "$@"; }
ed_pub() { ed25519_pub_hex "$@"; }
ed_sign() { ed25519_sign_hex "$@"; }
ed_verify() { ed25519_verify_hex "$@"; }
