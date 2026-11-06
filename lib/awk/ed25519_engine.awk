# ed25519_engine.awk — Ed25519 arithmetic engine (BusyBox awk only)
# Part of hush-ed25519 <https://github.com/Bemly/hush-ed25519>
# Licence: NCSA (see LICENSE)
# hush-ed25519 — Ed25519 in pure BusyBox awk + hush
#
# Field: radix 2^17, 15 limbs (255 bits), 2^255 = 19 (mod p)  -> fold factor 19
# Points: extended coordinates (X, Y, Z, T), unified addition for a = -1
# Scalars: 16 x 16-bit words (little endian); reduction mod L bit by bit
#
# Only BusyBox awk is supported (no gawk extensions, no 64-bit integers).
# All intermediates stay below 2^53 so IEEE-754 doubles are exact.
#
# Engine protocol: one command line on stdin, result on stdout.
#   pub    <a_hex32>                        -> compressed point hex
#   mul    <scalar_hex32|hash_hex64>        -> compressed [scalar]B
#   sig    <r_hex64> <a_hex32> <h_hex64>    -> S hex (32 bytes)
#   verify <A_hex> <R_hex> <S_hex> <h_hex>  -> 1 | 0
#   clamp  <hash_hex64>                     -> clamped first 32 bytes
#   base                                    -> compressed base point

BEGIN { _boot(); exit _RC }

# ---------------------------------------------------------------- constants --
function _boot(   line, n, a, i) {
	BS = 131072; INV17 = 1 / 131072
	for (i = 0; i < 16; i++) HEXV[substr("0123456789abcdef", i + 1, 1)] = i
	for (i = 0; i < 256; i++) HEX2[i] = sprintf("%02x", i)
	POW2[0] = 1; POW2[1] = 2; POW2[2] = 4; POW2[3] = 8; POW2[4] = 16; POW2[5] = 32
	POW2[6] = 64; POW2[7] = 128; POW2[8] = 256; POW2[9] = 512; POW2[10] = 1024
	POW2[11] = 2048; POW2[12] = 4096; POW2[13] = 8192; POW2[14] = 16384; POW2[15] = 32768
	POW2[16] = 65536
	P16B[0] = 1; P16B[1] = 16; P16B[2] = 256; P16B[3] = 4096
	_con("131053 131071 131071 131071 131071 131071 131071 131071 131071 131071 131071 131071 131071 131071 131071", PL)
	for (i = 0; i < 15; i++) F4P[i] = 4 * PL[i]
	_con("96419 68012 54130 93885 7562 27146 114729 77824 96744 15547 78288 118385 46847 92017 83981", DL)
	_con("61785 4953 108261 56698 15125 54292 98386 24577 62417 31095 25504 105699 93695 52962 36891", D2L)
	_con("41136 107783 100041 71837 65095 13673 68704 85598 130007 19614 54080 123237 64541 74754 44556", SML)
	_con("120090 18322 101208 22826 23163 66729 45853 47314 120540 71934 10552 32728 55013 112286 34212", BX)
	_con("26200 78643 104857 52428 26214 78643 104857 52428 26214 78643 104857 52428 26214 78643 104857", BY)
	_con("122275 119515 107180 44475 70959 954 115326 64065 44003 83762 113299 52396 96439 63614 106013", BT)
	_con("54253 23797 25370 22546 40150 41719 63966 5342 0 0 0 0 0 0 0 4096", LW)
	fe_zero(BZ); fe_one(BZ)
	_RC = 0
	if ((getline line) <= 0) { print "ERR:no-command"; _RC = 2; return }
	n = split(line, a, " ")
	cmd = a[1]
	if (cmd == "pub") { _cmd_pub(a[2]) }
	else if (cmd == "mul") { _cmd_mul(a[2]) }
	else if (cmd == "sig") { _cmd_sig(a[2], a[3], a[4]) }
	else if (cmd == "sign1") { _cmd_sign1(a[2], a[3]) }
	else if (cmd == "sig2") { _cmd_sig2(a[2], a[3], a[4]) }
	else if (cmd == "verify") { _cmd_verify(a[2], a[3], a[4], a[5]) }
	else if (cmd == "clamp") { print _clamp(a[2]) }
	else if (cmd == "unp") { _cmd_unp(a[2]) }
	else if (cmd == "base") { print ge_pack(BX, BY, BZ, BT) }
	else { print "ERR:bad-command"; _RC = 2 }
}

function _con(s, dst,   n, a, i) {
	n = split(s, a, " ")
	for (i = 1; i <= n; i++) dst[i - 1] = a[i]
}

# ------------------------------------------------------------------- field --
function fe_zero(c,   i) { for (i = 0; i < 15; i++) c[i] = 0 }
function fe_one(c,   i) { for (i = 0; i < 15; i++) c[i] = 0; c[0] = 1 }
function fe_copy(c, a,   i) { for (i = 0; i < 15; i++) c[i] = a[i] }
# fe_add / fe_sub keep c in [0, 2^21) so fe_mul products never exceed 2^42 and
# the 19* fold stays below 2^48 (double has 53-bit exact integers).
function fe_add(c, a, b,   i) {
	for (i = 0; i < 15; i++) c[i] = a[i] + b[i]
	fe_trim(c)
}
function fe_sub(c, a, b,   i) {
	for (i = 0; i < 15; i++) c[i] = a[i] + F4P[i] - b[i]
	fe_trim(c)
}

# fe_trim: one carry pass; output limbs stay < 2^17 + 38, small enough that
# fe_mul's 19-fold never leaves the 53-bit exact range.
function fe_trim(c,   i, q) {
	for (i = 0; i < 14; i++) { q = int(c[i] * INV17); c[i] -= q * BS; c[i + 1] += q }
	q = int(c[14] * INV17); c[14] -= q * BS; c[0] += 19 * q
}

# fe_norm: carry chain + conditional subtraction of p
function fe_norm(c,   pass, i, q) {
	for (pass = 0; pass < 3; pass++) {
		for (i = 0; i < 14; i++) { q = int(c[i] * INV17); c[i] -= q * BS; c[i + 1] += q }
		q = int(c[14] * INV17); c[14] -= q * BS; c[0] += 19 * q
	}
	fe_subp(c)
}

function fe_subp(c,   i, ge, br, t) {
	ge = 1
	for (i = 14; i >= 0; i--) {
		if (c[i] != PL[i]) { ge = (c[i] > PL[i]); break }
	}
	if (!ge) return
	br = 0
	for (i = 0; i < 15; i++) {
		t = c[i] - PL[i] - br
		if (t < 0) { t += BS; br = 1 } else br = 0
		c[i] = t
	}
}

# fe_mul: c = a * b mod p  (product limbs fully unrolled for speed)
function fe_mul(c, a, b,   i, q) {
	fa0 = a[0]
	fa1 = a[1]
	fa2 = a[2]
	fa3 = a[3]
	fa4 = a[4]
	fa5 = a[5]
	fa6 = a[6]
	fa7 = a[7]
	fa8 = a[8]
	fa9 = a[9]
	fa10 = a[10]
	fa11 = a[11]
	fa12 = a[12]
	fa13 = a[13]
	fa14 = a[14]
	fb0 = b[0]
	fb1 = b[1]
	fb2 = b[2]
	fb3 = b[3]
	fb4 = b[4]
	fb5 = b[5]
	fb6 = b[6]
	fb7 = b[7]
	fb8 = b[8]
	fb9 = b[9]
	fb10 = b[10]
	fb11 = b[11]
	fb12 = b[12]
	fb13 = b[13]
	fb14 = b[14]
	ft0 = 0
	ft1 = 0
	ft2 = 0
	ft3 = 0
	ft4 = 0
	ft5 = 0
	ft6 = 0
	ft7 = 0
	ft8 = 0
	ft9 = 0
	ft10 = 0
	ft11 = 0
	ft12 = 0
	ft13 = 0
	ft14 = 0
	ft15 = 0
	ft16 = 0
	ft17 = 0
	ft18 = 0
	ft19 = 0
	ft20 = 0
	ft21 = 0
	ft22 = 0
	ft23 = 0
	ft24 = 0
	ft25 = 0
	ft26 = 0
	ft27 = 0
	ft28 = 0
	ft29 = 0
	ft0 += fa0 * fb0; ft1 += fa0 * fb1; ft2 += fa0 * fb2; ft3 += fa0 * fb3; ft4 += fa0 * fb4; ft5 += fa0 * fb5; ft6 += fa0 * fb6; ft7 += fa0 * fb7; ft8 += fa0 * fb8; ft9 += fa0 * fb9; ft10 += fa0 * fb10; ft11 += fa0 * fb11; ft12 += fa0 * fb12; ft13 += fa0 * fb13; ft14 += fa0 * fb14
	ft1 += fa1 * fb0; ft2 += fa1 * fb1; ft3 += fa1 * fb2; ft4 += fa1 * fb3; ft5 += fa1 * fb4; ft6 += fa1 * fb5; ft7 += fa1 * fb6; ft8 += fa1 * fb7; ft9 += fa1 * fb8; ft10 += fa1 * fb9; ft11 += fa1 * fb10; ft12 += fa1 * fb11; ft13 += fa1 * fb12; ft14 += fa1 * fb13; ft15 += fa1 * fb14
	ft2 += fa2 * fb0; ft3 += fa2 * fb1; ft4 += fa2 * fb2; ft5 += fa2 * fb3; ft6 += fa2 * fb4; ft7 += fa2 * fb5; ft8 += fa2 * fb6; ft9 += fa2 * fb7; ft10 += fa2 * fb8; ft11 += fa2 * fb9; ft12 += fa2 * fb10; ft13 += fa2 * fb11; ft14 += fa2 * fb12; ft15 += fa2 * fb13; ft16 += fa2 * fb14
	ft3 += fa3 * fb0; ft4 += fa3 * fb1; ft5 += fa3 * fb2; ft6 += fa3 * fb3; ft7 += fa3 * fb4; ft8 += fa3 * fb5; ft9 += fa3 * fb6; ft10 += fa3 * fb7; ft11 += fa3 * fb8; ft12 += fa3 * fb9; ft13 += fa3 * fb10; ft14 += fa3 * fb11; ft15 += fa3 * fb12; ft16 += fa3 * fb13; ft17 += fa3 * fb14
	ft4 += fa4 * fb0; ft5 += fa4 * fb1; ft6 += fa4 * fb2; ft7 += fa4 * fb3; ft8 += fa4 * fb4; ft9 += fa4 * fb5; ft10 += fa4 * fb6; ft11 += fa4 * fb7; ft12 += fa4 * fb8; ft13 += fa4 * fb9; ft14 += fa4 * fb10; ft15 += fa4 * fb11; ft16 += fa4 * fb12; ft17 += fa4 * fb13; ft18 += fa4 * fb14
	ft5 += fa5 * fb0; ft6 += fa5 * fb1; ft7 += fa5 * fb2; ft8 += fa5 * fb3; ft9 += fa5 * fb4; ft10 += fa5 * fb5; ft11 += fa5 * fb6; ft12 += fa5 * fb7; ft13 += fa5 * fb8; ft14 += fa5 * fb9; ft15 += fa5 * fb10; ft16 += fa5 * fb11; ft17 += fa5 * fb12; ft18 += fa5 * fb13; ft19 += fa5 * fb14
	ft6 += fa6 * fb0; ft7 += fa6 * fb1; ft8 += fa6 * fb2; ft9 += fa6 * fb3; ft10 += fa6 * fb4; ft11 += fa6 * fb5; ft12 += fa6 * fb6; ft13 += fa6 * fb7; ft14 += fa6 * fb8; ft15 += fa6 * fb9; ft16 += fa6 * fb10; ft17 += fa6 * fb11; ft18 += fa6 * fb12; ft19 += fa6 * fb13; ft20 += fa6 * fb14
	ft7 += fa7 * fb0; ft8 += fa7 * fb1; ft9 += fa7 * fb2; ft10 += fa7 * fb3; ft11 += fa7 * fb4; ft12 += fa7 * fb5; ft13 += fa7 * fb6; ft14 += fa7 * fb7; ft15 += fa7 * fb8; ft16 += fa7 * fb9; ft17 += fa7 * fb10; ft18 += fa7 * fb11; ft19 += fa7 * fb12; ft20 += fa7 * fb13; ft21 += fa7 * fb14
	ft8 += fa8 * fb0; ft9 += fa8 * fb1; ft10 += fa8 * fb2; ft11 += fa8 * fb3; ft12 += fa8 * fb4; ft13 += fa8 * fb5; ft14 += fa8 * fb6; ft15 += fa8 * fb7; ft16 += fa8 * fb8; ft17 += fa8 * fb9; ft18 += fa8 * fb10; ft19 += fa8 * fb11; ft20 += fa8 * fb12; ft21 += fa8 * fb13; ft22 += fa8 * fb14
	ft9 += fa9 * fb0; ft10 += fa9 * fb1; ft11 += fa9 * fb2; ft12 += fa9 * fb3; ft13 += fa9 * fb4; ft14 += fa9 * fb5; ft15 += fa9 * fb6; ft16 += fa9 * fb7; ft17 += fa9 * fb8; ft18 += fa9 * fb9; ft19 += fa9 * fb10; ft20 += fa9 * fb11; ft21 += fa9 * fb12; ft22 += fa9 * fb13; ft23 += fa9 * fb14
	ft10 += fa10 * fb0; ft11 += fa10 * fb1; ft12 += fa10 * fb2; ft13 += fa10 * fb3; ft14 += fa10 * fb4; ft15 += fa10 * fb5; ft16 += fa10 * fb6; ft17 += fa10 * fb7; ft18 += fa10 * fb8; ft19 += fa10 * fb9; ft20 += fa10 * fb10; ft21 += fa10 * fb11; ft22 += fa10 * fb12; ft23 += fa10 * fb13; ft24 += fa10 * fb14
	ft11 += fa11 * fb0; ft12 += fa11 * fb1; ft13 += fa11 * fb2; ft14 += fa11 * fb3; ft15 += fa11 * fb4; ft16 += fa11 * fb5; ft17 += fa11 * fb6; ft18 += fa11 * fb7; ft19 += fa11 * fb8; ft20 += fa11 * fb9; ft21 += fa11 * fb10; ft22 += fa11 * fb11; ft23 += fa11 * fb12; ft24 += fa11 * fb13; ft25 += fa11 * fb14
	ft12 += fa12 * fb0; ft13 += fa12 * fb1; ft14 += fa12 * fb2; ft15 += fa12 * fb3; ft16 += fa12 * fb4; ft17 += fa12 * fb5; ft18 += fa12 * fb6; ft19 += fa12 * fb7; ft20 += fa12 * fb8; ft21 += fa12 * fb9; ft22 += fa12 * fb10; ft23 += fa12 * fb11; ft24 += fa12 * fb12; ft25 += fa12 * fb13; ft26 += fa12 * fb14
	ft13 += fa13 * fb0; ft14 += fa13 * fb1; ft15 += fa13 * fb2; ft16 += fa13 * fb3; ft17 += fa13 * fb4; ft18 += fa13 * fb5; ft19 += fa13 * fb6; ft20 += fa13 * fb7; ft21 += fa13 * fb8; ft22 += fa13 * fb9; ft23 += fa13 * fb10; ft24 += fa13 * fb11; ft25 += fa13 * fb12; ft26 += fa13 * fb13; ft27 += fa13 * fb14
	ft14 += fa14 * fb0; ft15 += fa14 * fb1; ft16 += fa14 * fb2; ft17 += fa14 * fb3; ft18 += fa14 * fb4; ft19 += fa14 * fb5; ft20 += fa14 * fb6; ft21 += fa14 * fb7; ft22 += fa14 * fb8; ft23 += fa14 * fb9; ft24 += fa14 * fb10; ft25 += fa14 * fb11; ft26 += fa14 * fb12; ft27 += fa14 * fb13; ft28 += fa14 * fb14
	ft0 += 19 * ft15
	ft1 += 19 * ft16
	ft2 += 19 * ft17
	ft3 += 19 * ft18
	ft4 += 19 * ft19
	ft5 += 19 * ft20
	ft6 += 19 * ft21
	ft7 += 19 * ft22
	ft8 += 19 * ft23
	ft9 += 19 * ft24
	ft10 += 19 * ft25
	ft11 += 19 * ft26
	ft12 += 19 * ft27
	ft13 += 19 * ft28
	ft14 += 19 * ft29
	q = int(ft0 * INV17); ft0 -= q * BS; ft1 += q
	q = int(ft1 * INV17); ft1 -= q * BS; ft2 += q
	q = int(ft2 * INV17); ft2 -= q * BS; ft3 += q
	q = int(ft3 * INV17); ft3 -= q * BS; ft4 += q
	q = int(ft4 * INV17); ft4 -= q * BS; ft5 += q
	q = int(ft5 * INV17); ft5 -= q * BS; ft6 += q
	q = int(ft6 * INV17); ft6 -= q * BS; ft7 += q
	q = int(ft7 * INV17); ft7 -= q * BS; ft8 += q
	q = int(ft8 * INV17); ft8 -= q * BS; ft9 += q
	q = int(ft9 * INV17); ft9 -= q * BS; ft10 += q
	q = int(ft10 * INV17); ft10 -= q * BS; ft11 += q
	q = int(ft11 * INV17); ft11 -= q * BS; ft12 += q
	q = int(ft12 * INV17); ft12 -= q * BS; ft13 += q
	q = int(ft13 * INV17); ft13 -= q * BS; ft14 += q
	q = int(ft14 * INV17); ft14 -= q * BS; ft0 += 19 * q
	q = int(ft0 * INV17); ft0 -= q * BS; ft1 += q
	q = int(ft1 * INV17); ft1 -= q * BS; ft2 += q
	q = int(ft2 * INV17); ft2 -= q * BS; ft3 += q
	q = int(ft3 * INV17); ft3 -= q * BS; ft4 += q
	q = int(ft4 * INV17); ft4 -= q * BS; ft5 += q
	q = int(ft5 * INV17); ft5 -= q * BS; ft6 += q
	q = int(ft6 * INV17); ft6 -= q * BS; ft7 += q
	q = int(ft7 * INV17); ft7 -= q * BS; ft8 += q
	q = int(ft8 * INV17); ft8 -= q * BS; ft9 += q
	q = int(ft9 * INV17); ft9 -= q * BS; ft10 += q
	q = int(ft10 * INV17); ft10 -= q * BS; ft11 += q
	q = int(ft11 * INV17); ft11 -= q * BS; ft12 += q
	q = int(ft12 * INV17); ft12 -= q * BS; ft13 += q
	q = int(ft13 * INV17); ft13 -= q * BS; ft14 += q
	q = int(ft14 * INV17); ft14 -= q * BS; ft0 += 19 * q
	q = int(ft0 * INV17); ft0 -= q * BS; ft1 += q
	q = int(ft1 * INV17); ft1 -= q * BS; ft2 += q
	q = int(ft2 * INV17); ft2 -= q * BS; ft3 += q
	q = int(ft3 * INV17); ft3 -= q * BS; ft4 += q
	q = int(ft4 * INV17); ft4 -= q * BS; ft5 += q
	q = int(ft5 * INV17); ft5 -= q * BS; ft6 += q
	q = int(ft6 * INV17); ft6 -= q * BS; ft7 += q
	q = int(ft7 * INV17); ft7 -= q * BS; ft8 += q
	q = int(ft8 * INV17); ft8 -= q * BS; ft9 += q
	q = int(ft9 * INV17); ft9 -= q * BS; ft10 += q
	q = int(ft10 * INV17); ft10 -= q * BS; ft11 += q
	q = int(ft11 * INV17); ft11 -= q * BS; ft12 += q
	q = int(ft12 * INV17); ft12 -= q * BS; ft13 += q
	q = int(ft13 * INV17); ft13 -= q * BS; ft14 += q
	q = int(ft14 * INV17); ft14 -= q * BS; ft0 += 19 * q
	c[0] = ft0
	c[1] = ft1
	c[2] = ft2
	c[3] = ft3
	c[4] = ft4
	c[5] = ft5
	c[6] = ft6
	c[7] = ft7
	c[8] = ft8
	c[9] = ft9
	c[10] = ft10
	c[11] = ft11
	c[12] = ft12
	c[13] = ft13
	c[14] = ft14
}

function fe_sqn(out, a, n,   i) { fe_copy(out, a); for (i = 0; i < n; i++) fe_mul(out, out, out) }

# shared first half: I0=z^2 I1=z^4 I2=z^8 I3=z^9 I4=z^11 I5=z^22 I6=z^31
# then I7=2^10-1 I8=2^20-1 I9=2^40-1 I5=2^50-1 I6=2^100-1 I7=2^200-1 I8=2^250-1
function fe_chain(zn) {
	fe_copy(TZ, zn)                        # zn may alias out in callers
	fe_mul(I0, TZ, TZ)
	fe_mul(I1, I0, I0)
	fe_mul(I2, I1, I1)
	fe_mul(I3, I2, TZ)
	fe_mul(I4, I3, I0)
	fe_mul(I5, I4, I4)
	fe_mul(I6, I5, I3)
	fe_sqn(I7, I6, 5);  fe_mul(I7, I7, I6)
	fe_sqn(I8, I7, 10); fe_mul(I8, I8, I7)
	fe_sqn(I9, I8, 20); fe_mul(I9, I9, I8)
	fe_sqn(I5, I9, 10); fe_mul(I5, I5, I7)
	fe_sqn(I6, I5, 50); fe_mul(I6, I6, I5)
	fe_sqn(I7, I6, 100); fe_mul(I7, I7, I6)
	fe_sqn(I8, I7, 50); fe_mul(I8, I8, I5)
}

# z^(p-2)
function fe_inv(out, zn) {
	fe_chain(zn)
	fe_sqn(out, I8, 5); fe_mul(out, out, I4)
}

# z^((p-5)/8) = z^(2^252-3)
function fe_pow22523(out, zn) {
	fe_chain(zn)
	fe_sqn(out, I8, 2); fe_mul(out, out, TZ)
}

# fe_pack: normalized limbs -> 32 little-endian bytes in ob[]
function fe_pack(f, ob,   i, nb, acc, v, n) {
	fe_norm(f)
	nb = 0; acc = 0; n = 0
	for (i = 0; i < 15; i++) {
		acc += f[i] * POW2[nb]
		nb += 17
		while (nb >= 8) {
			v = acc - 256 * int(acc / 256)
			acc = int(acc / 256)
			nb -= 8
			ob[n] = v; n++
		}
	}
	if (nb > 0) { ob[n] = acc; n++ }
	return n
}

# fe_frombytes: 32-byte little-endian hex -> limbs (high bit of y masked)
function fe_frombytes(f, h,   i, v, b, nb, k) {
	b = 0; nb = 0; k = 0
	for (i = 0; i < 32; i++) {
		v = hb(h, i)
		if (i == 31) v = v - 128 * int(v / 128)
		b += v * POW2[nb]
		nb += 8
		while (nb >= 17) {
			f[k] = b - BS * int(b * INV17)
			b = int(b * INV17)
			nb -= 17
			k++
		}
	}
	if (k < 15) f[k] = b
}

function fe_eq(a, b,   i) {
	fe_copy(EQ1, a); fe_norm(EQ1)
	fe_copy(EQ2, b); fe_norm(EQ2)
	for (i = 0; i < 15; i++) if (EQ1[i] != EQ2[i]) return 0
	return 1
}

# -------------------------------------------------------------------- bytes --
function hb(h, i,   p) { p = 2 * i + 1; return HEXV[substr(h, p, 1)] * 16 + HEXV[substr(h, p + 1, 1)] }
function bytes_hex(ob, n,   i, s) { s = ""; for (i = 0; i < n; i++) s = s HEX2[ob[i]]; return s }

# -------------------------------------------------------------------- point --
function ge_add(rx, ry, rz, rt, ax, ay, az, at, bx, by, bz, bt) {
	fe_sub(P0, ay, ax); fe_sub(P1, by, bx); fe_mul(P2, P0, P1)
	fe_add(P0, ay, ax); fe_add(P1, by, bx); fe_mul(P3, P0, P1)
	fe_mul(P0, at, D2L); fe_mul(P4, P0, bt)
	fe_add(P0, az, az); fe_mul(P5, P0, bz)
	fe_sub(P6, P3, P2)
	fe_sub(P7, P5, P4)
	fe_add(P8, P5, P4)
	fe_add(P9, P3, P2)
	fe_mul(rx, P6, P7); fe_mul(ry, P8, P9)
	fe_mul(rt, P6, P9); fe_mul(rz, P7, P8)
}

function ge_dbl(rx, ry, rz, rt, ax, ay, az, at) {
	fe_mul(P0, ax, ax)                        # A = X^2
	fe_mul(P1, ay, ay)                        # B = Y^2
	fe_mul(P2, az, az); fe_add(P2, P2, P2)    # C = 2Z^2
	fe_add(P3, P0, P1)                        # H = A+B
	fe_add(P4, ax, ay); fe_mul(P4, P4, P4); fe_sub(P4, P3, P4)   # E = H-(X+Y)^2
	fe_sub(P5, P0, P1)                        # G = A-B
	fe_add(P6, P2, P5)                        # F = C+G
	fe_mul(rx, P4, P6); fe_mul(ry, P5, P3)
	fe_mul(rt, P4, P3); fe_mul(rz, P6, P5)
}

# table helpers: TX/TY/TZ/TT hold [0..15]P
function tb_put(n, X, Y, Z, T,   k) {
	for (k = 0; k < 15; k++) { TX[n, k] = X[k]; TY[n, k] = Y[k]; TZ[n, k] = Z[k]; TT[n, k] = T[k] }
}
function tb_get(n, X, Y, Z, T,   k) {
	for (k = 0; k < 15; k++) { X[k] = TX[n, k]; Y[k] = TY[n, k]; Z[k] = TZ[n, k]; T[k] = TT[n, k] }
}
function tb_put2(n, X, Y, Z, T,   k) {
	for (k = 0; k < 15; k++) { UX[n, k] = X[k]; UY[n, k] = Y[k]; UZ[n, k] = Z[k]; UT[n, k] = T[k] }
}
function tb_get2(n, X, Y, Z, T,   k) {
	for (k = 0; k < 15; k++) { X[k] = UX[n, k]; Y[k] = UY[n, k]; Z[k] = UZ[n, k]; T[k] = UT[n, k] }
}

# tb_make: build table [1..15]P (table[0] = identity) for point P -> TX bank
function tb_make(bx, by, bz, bt,   n, X, Y, Z, T, WX, WY, WZ, WT) {
	fe_zero(X); fe_one(Y); fe_one(Z); fe_zero(T)          # table[0] = identity
	fe_zero(WX); fe_one(WY); fe_one(WZ); fe_zero(WT)
	tb_put(0, X, Y, Z, T)
	fe_copy(X, bx); fe_copy(Y, by); fe_copy(Z, bz); fe_copy(T, bt)
	tb_put(1, X, Y, Z, T)
	for (n = 2; n < 16; n++) {
		ge_add(WX, WY, WZ, WT, X, Y, Z, T, bx, by, bz, bt)
		fe_copy(X, WX); fe_copy(Y, WY); fe_copy(Z, WZ); fe_copy(T, WT)
		tb_put(n, X, Y, Z, T)
	}
}
function tb_make2(bx, by, bz, bt,   n, X, Y, Z, T, WX, WY, WZ, WT) {
	fe_zero(X); fe_one(Y); fe_one(Z); fe_zero(T)
	tb_put2(0, X, Y, Z, T)
	fe_copy(X, bx); fe_copy(Y, by); fe_copy(Z, bz); fe_copy(T, bt)
	tb_put2(1, X, Y, Z, T)
	for (n = 2; n < 16; n++) {
		ge_add(WX, WY, WZ, WT, X, Y, Z, T, bx, by, bz, bt)
		fe_copy(X, WX); fe_copy(Y, WY); fe_copy(Z, WZ); fe_copy(T, WT)
		tb_put2(n, X, Y, Z, T)
	}
}

function ge_mul(rx, ry, rz, rt, w,   i, n, X, Y, Z, T) {
	fe_zero(rx); fe_one(ry); fe_one(rz); fe_zero(rt)
	for (i = 63; i >= 0; i--) {
		ge_dbl(rx, ry, rz, rt, rx, ry, rz, rt)
		ge_dbl(rx, ry, rz, rt, rx, ry, rz, rt)
		ge_dbl(rx, ry, rz, rt, rx, ry, rz, rt)
		ge_dbl(rx, ry, rz, rt, rx, ry, rz, rt)
		n = int(w[int(i / 4)] / P16B[i % 4]) % 16
		if (n != 0) {
			tb_get(n, X, Y, Z, T)
			ge_add(rx, ry, rz, rt, rx, ry, rz, rt, X, Y, Z, T)
		}
	}
}

# [w1]B + [w2]A   (tables: TX = B, UX = A)
function ge_mul2(rx, ry, rz, rt, w1, w2,   i, n, X, Y, Z, T) {
	fe_zero(rx); fe_one(ry); fe_one(rz); fe_zero(rt)
	for (i = 63; i >= 0; i--) {
		ge_dbl(rx, ry, rz, rt, rx, ry, rz, rt)
		ge_dbl(rx, ry, rz, rt, rx, ry, rz, rt)
		ge_dbl(rx, ry, rz, rt, rx, ry, rz, rt)
		ge_dbl(rx, ry, rz, rt, rx, ry, rz, rt)
		n = int(w1[int(i / 4)] / P16B[i % 4]) % 16
		if (n != 0) {
			tb_get(n, X, Y, Z, T)
			ge_add(rx, ry, rz, rt, rx, ry, rz, rt, X, Y, Z, T)
		}
		n = int(w2[int(i / 4)] / P16B[i % 4]) % 16
		if (n != 0) {
			tb_get2(n, X, Y, Z, T)
			ge_add(rx, ry, rz, rt, rx, ry, rz, rt, X, Y, Z, T)
		}
	}
}

function ge_pack(px, py, pz, pt,   ob, i, s) {
	fe_inv(ZI, pz)
	fe_mul(ZJ, px, ZI)
	fe_mul(ZK, py, ZI)
	fe_pack(ZK, ob)
	fe_norm(ZJ)
	if (ZJ[0] % 2 != 0) ob[31] += 128
	s = ""
	for (i = 0; i < 32; i++) s = s HEX2[ob[i] + 0]
	return s
}

# ge_unpack: compressed hex -> extended point; returns 1 on success
function ge_unpack(px, py, pz, pt, h,   ok) {
	fe_frombytes(py, h)
	if (!fe_lt_p(py)) return 0               # y must be canonical (< p)
	fe_zero(px); fe_one(pz)
	fe_mul(U0, py, py)
	fe_one(U3)
	fe_sub(U1, U0, U3)                     # u = y^2 - 1
	fe_mul(U2, U0, DL); fe_add(U2, U2, U3) # v = d*y^2 + 1
	fe_mul(U4, U2, U2); fe_mul(U4, U4, U2) # v^3
	fe_mul(U5, U4, U4); fe_mul(U5, U5, U2) # v^7
	fe_mul(U6, U1, U5)
	fe_pow22523(U6, U6)
	fe_mul(U6, U6, U4); fe_mul(px, U6, U1) # x = u*v^3*(u*v^7)^((p-5)/8)
	fe_mul(U8, px, px); fe_mul(U8, U8, U2) # v*x^2
	ok = 0
	if (fe_eq(U8, U1)) ok = 1
	else {
		fe_zero(U9); fe_sub(U9, U9, U1)        # -u
		if (fe_eq(U8, U9)) { fe_mul(px, px, SML); ok = 1 }
	}
	if (!ok) return 0
	fe_norm(px)
	if (fe_iszero(px) && int(hb(h, 31) / 128) == 1) return 0   # x = 0 with sign 1 is invalid
	if (px[0] % 2 != int(hb(h, 31) / 128)) fe_sub(px, ZERO, px)
	fe_mul(pt, px, py)
	return 1
}

function fe_lt_p(a,   i) {
	fe_copy(EQ1, a); fe_norm(EQ1)
	for (i = 14; i >= 0; i--) {
		if (EQ1[i] != PL[i]) return (EQ1[i] < PL[i])
	}
	return 0
}

function fe_iszero(a,   i) {
	fe_copy(EQ1, a); fe_norm(EQ1)
	for (i = 0; i < 15; i++) if (EQ1[i] != 0) return 0
	return 1
}

# ------------------------------------------------------------------ scalars --
function sc_from32(h, w,   i) {
	for (i = 0; i < 16; i++) w[i] = hb(h, 2 * i) + 256 * hb(h, 2 * i + 1)
}

# reduce a 32-word (512-bit) little-endian value modulo L into out[0..15]
# Bit-by-bit shift-and-subtract: 512 iterations, 16 words each.
function sc_reduce_words(v, out,   bit, i, b, c, t, ge, br) {
	for (i = 0; i < 16; i++) SR[i] = 0
	for (bit = 511; bit >= 0; bit--) {
		b = int(v[int(bit / 16)] / POW2[bit % 16]) % 2
		c = 0
		for (i = 0; i < 16; i++) {
			t = SR[i] * 2 + c
			if (t >= 65536) { t -= 65536; c = 1 } else c = 0
			SR[i] = t
		}
		SR[0] += b
		for (i = 0; i < 16 && SR[i] >= 65536; i++) { SR[i] -= 65536; SR[i + 1] += 1 }
		ge = 1
		for (i = 15; i >= 0; i--) {
			if (SR[i] != LW[i]) { ge = (SR[i] > LW[i]); break }
		}
		if (ge) {
			br = 0
			for (i = 0; i < 16; i++) {
				t = SR[i] - LW[i] - br
				if (t < 0) { t += 65536; br = 1 } else br = 0
				SR[i] = t
			}
		}
	}
	for (i = 0; i < 16; i++) out[i] = SR[i]
}

# reduce a 64-byte (128 hex) little-endian value modulo L
function sc_reduce64(h, out,   i, v) {
	for (i = 0; i < 32; i++) v[i] = hb(h, 2 * i) + 256 * hb(h, 2 * i + 1)
	sc_reduce_words(v, out)
}

# out = a * b mod L (a,b < 2^255)
function sc_mul(a, b, out,   i, j, q, p) {
	for (i = 0; i < 32; i++) p[i] = 0
	for (i = 0; i < 16; i++) if (a[i] != 0) for (j = 0; j < 16; j++) p[i + j] += a[i] * b[j]
	for (i = 0; i < 31; i++) { q = int(p[i] / 65536); p[i] -= q * 65536; p[i + 1] += q }
	q = int(p[31] / 65536); p[31] -= q * 65536
	sc_reduce_words(p, out)
}

# 1 when 0 <= w < L  (canonical scalar)
function sc_lt_l(w,   i) {
	for (i = 15; i >= 0; i--) {
		if (w[i] != LW[i]) return (w[i] < LW[i])
	}
	return 0
}

function sc_add(a, b, out,   i, br, t, ge) {
	br = 0
	for (i = 0; i < 16; i++) {
		t = a[i] + b[i] + br
		if (t >= 65536) { t -= 65536; br = 1 } else br = 0
		out[i] = t
	}
	ge = 1
	for (i = 15; i >= 0; i--) {
		if (out[i] != LW[i]) { ge = (out[i] > LW[i]); break }
	}
	if (!ge) return
	br = 0
	for (i = 0; i < 16; i++) {
		t = out[i] - LW[i] - br
		if (t < 0) { t += 65536; br = 1 } else br = 0
		out[i] = t
	}
}

# little-endian words -> 32-byte hex
function sc_pack(w,   i, ob, s) {
	for (i = 0; i < 16; i++) { ob[2 * i] = w[i] - 256 * int(w[i] / 256); ob[2 * i + 1] = int(w[i] / 256) }
	s = ""
	for (i = 0; i < 32; i++) s = s HEX2[ob[i] + 0]
	return s
}

# ----------------------------------------------------------------- commands --
function _clamp(h,   b0, b31, s) {
	b0 = hb(h, 0); b31 = hb(h, 31)
	b0 = 8 * int(b0 / 8)              # clear the low 3 bits
	b31 = b31 - 128 * int(b31 / 128)          # clear bit 7
	b31 = 64 + (b31 - 64 * int(b31 / 64))     # set bit 6, keep bits 0..5
	s = HEX2[b0] substr(h, 3, 60) HEX2[b31]
	return s
}

function _cmd_unp(h) {
	h = tolower(h)
	if (length(h) != 64) { print "ERR:bad-point"; _RC = 2; return }
	if (!ge_unpack(VX, VY, VZ, VT, h)) { print "ERR:unpack"; _RC = 1; return }
	print ge_pack(VX, VY, VZ, VT)
}

function _cmd_pub(h) {
	h = tolower(h)
	if (length(h) == 128) h = _clamp(h)
	else if (length(h) != 64) { print "ERR:bad-scalar"; _RC = 2; return }
	sc_from32(h, SW)
	tb_make(BX, BY, BZ, BT)
	ge_mul(RX, RY, RZ, RT, SW)
	print ge_pack(RX, RY, RZ, RT)
}

function _cmd_mul(h) {
	h = tolower(h)
	if (length(h) == 128) sc_reduce64(h, SW)
	else if (length(h) == 64) sc_from32(h, SW)
	else { print "ERR:bad-scalar"; _RC = 2; return }
	tb_make(BX, BY, BZ, BT)
	ge_mul(RX, RY, RZ, RT, SW)
	print ge_pack(RX, RY, RZ, RT)
}

function _cmd_sig(rh, ah, hh) {
	rh = tolower(rh); ah = tolower(ah); hh = tolower(hh)
	if (length(rh) != 128 && length(rh) != 64) { print "ERR:bad-args"; _RC = 2; return }
	if (length(ah) != 64 || length(hh) != 128) { print "ERR:bad-args"; _RC = 2; return }
	if (length(rh) == 64) sc_from32(rh, SMR)
	else sc_reduce64(rh, SMR)
	sc_from32(ah, SMA)
	sc_reduce64(hh, SMH)
	sc_mul(SMH, SMA, SMT)
	sc_add(SMT, SMR, SMO)
	print sc_pack(SMO)
}

# sign1 <sha512(seed)_hex> <sha512(prefix||msg)_hex>
#   -> "<pub> <R> <r mod L>"  (one line, lets the facade skip a second reduction)
function _cmd_sign1(hh, rh,   _pub) {
	hh = tolower(hh); rh = tolower(rh)
	if (length(hh) != 128 || length(rh) != 128) { print "ERR:bad-args"; _RC = 2; return }
	sc_from32(_clamp(hh), SW)
	tb_make(BX, BY, BZ, BT)
	ge_mul(RX, RY, RZ, RT, SW)
	_pub = ge_pack(RX, RY, RZ, RT)
	sc_reduce64(rh, SMR)
	ge_mul(RX, RY, RZ, RT, SMR)
	printf "%s %s %s\n", _pub, ge_pack(RX, RY, RZ, RT), sc_pack(SMR)
}

# sig2 <sha512(seed)_hex> <r mod L hex64> <sha512(R||A||msg)_hex>
function _cmd_sig2(hh, rh, h4) {
	hh = tolower(hh); rh = tolower(rh); h4 = tolower(h4)
	if (length(hh) != 128 || length(rh) != 64 || length(h4) != 128) { print "ERR:bad-args"; _RC = 2; return }
	sc_from32(_clamp(hh), SMA)
	sc_from32(rh, SMR)
	sc_reduce64(h4, SMH)
	sc_mul(SMH, SMA, SMT)
	sc_add(SMT, SMR, SMO)
	print sc_pack(SMO)
}

function _cmd_verify(ah, rh, sh, hh) {
	ah = tolower(ah); rh = tolower(rh); sh = tolower(sh); hh = tolower(hh)
	if (length(ah) != 64 || length(rh) != 64 || length(sh) != 64 || length(hh) != 128) { print 0; return }
	if (!ge_unpack(VX, VY, VZ, VT, ah)) { print 0; return }
	if (fe_iszero(VX) && fe_eq(VY, VZ)) { print 0; return }   # identity key: small-order forgery
	fe_sub(VX, ZERO, VX)
	fe_sub(VT, ZERO, VT)
	sc_from32(sh, SWS)
	if (!sc_lt_l(SWS)) { print 0; return }   # S must be canonical (0 <= S < L)
	sc_reduce64(hh, SWH)
	tb_make(BX, BY, BZ, BT)
	tb_make2(VX, VY, VZ, VT)
	ge_mul2(RX, RY, RZ, RT, SWS, SWH)
	if (!ge_unpack(WX, WY, WZ, WT, rh)) { print 0; return }
	if (ge_pack(RX, RY, RZ, RT) == ge_pack(WX, WY, WZ, WT)) print 1
	else print 0
}
