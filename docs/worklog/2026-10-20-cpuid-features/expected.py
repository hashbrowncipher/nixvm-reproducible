"""Reference results for the feature probes in tests/cpuid.rs.

Each function models one instruction from its Intel SDM description. Running this prints
each probe's input and expected output as little-endian hex. Output bytes a probe does not
write keep the 0xAA fill. probes.S beside this file is the probes' source: assemble it with
`as --64`, and replace each RET with SYSCALL to get the bytes in the test.
"""
import struct

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1


def gf_mul(a, b):
    """GF(2^8) multiply modulo x^8 + x^4 + x^3 + x + 1 (GF2P8MULB, AES)."""
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
    return r


def sbox(x):
    inv = 0 if x == 0 else next(y for y in range(256) if gf_mul(x, y) == 1)
    r = 0x63
    for i in range(8):
        bit = (inv >> i ^ inv >> (i + 4) % 8 ^ inv >> (i + 5) % 8 ^ inv >> (i + 6) % 8 ^ inv >> (i + 7) % 8) & 1
        r ^= bit << i
    return r


SBOX = [sbox(x) for x in range(256)]


def aesenc(state, key):
    """One AES encryption round on 16 bytes: ShiftRows, SubBytes, MixColumns, AddRoundKey."""
    s = [SBOX[b] for b in state]
    s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # byte r+4c <- r+4(c+r)
    out = []
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        for r in range(4):
            out.append(gf_mul(2, col[r]) ^ gf_mul(3, col[(r + 1) % 4]) ^ col[(r + 2) % 4] ^ col[(r + 3) % 4])
    return bytes(o ^ k for o, k in zip(out, key))


def clmul(a, b):
    r = 0
    for i in range(64):
        if b >> i & 1:
            r ^= a << i
    return r


def rotr(x, n):
    return (x >> n | x << (32 - n)) & M32


def sha256rnds2(src1, src2, wk):
    """SHA256RNDS2 as specified in the Intel SDM: two rounds; returns DEST."""
    w = lambda v, i: v >> (32 * i) & M32
    a, b, c, d = w(src2, 3), w(src2, 2), w(src1, 3), w(src1, 2)
    e, f, g, h = w(src2, 1), w(src2, 0), w(src1, 1), w(src1, 0)
    for k in (w(wk, 0), w(wk, 1)):
        ch = (e & f) ^ (~e & g)
        maj = (a & b) ^ (a & c) ^ (b & c)
        s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        t = (ch + s1 + k + h) & M32
        a, b, c, d, e, f, g, h = (t + maj + s0) & M32, a, b, c, (t + d) & M32, e, f, g
    return a << 96 | b << 64 | e << 32 | f


def le(n, width):
    return n.to_bytes(width, "little")


def show(name, inputs, output):
    print(f"{name}\n  in  {inputs.hex()}\n  out {output.hex()}")


# AES-NI: the AESENC example from Intel's AES-NI white paper (Gueron).
state = le(0x7B5B54657374566563746F725D53475D, 16)
key = le(0x48692853686179295B477565726F6E5D, 16)
aes = aesenc(state, key)
assert aes == le(0xA8311C2F9FDBA3C58B104B58DED7E595, 16)
show("aes", state + key, aes)

# PCLMULQDQ imm 0x01: DEST.high64 x SRC.low64.
a = [0x0123_4567_89AB_CDEF, 0x8000_0000_0000_0001]
b = [0xF0E1_D2C3_B4A5_9687, 0xFFFF_FFFF_FFFF_FFFF]
show("pclmul", b"".join(le(x, 8) for x in a + b), le(clmul(a[1], b[0]), 16))

# FMA: (1 + 2^-30)(1 - 2^-30) - 1 = -2^-60 exactly; unfused would give 0.
fa, fb, fc = 1 + 2**-30, 1 - 2**-30, -1.0
show("fma", struct.pack("<3d", fa, fb, fc), struct.pack("<d", -(2.0**-60)))

# F16C: 1.0, -2.0, 65504 (max half), 2^-24 (smallest half subnormal).
show("f16c", struct.pack("<4H", 0x3C00, 0xC000, 0x7BFF, 0x0001), struct.pack("<4f", 1.0, -2.0, 65504.0, 2.0**-24))

# LZCNT: 0 -> 64 with CF; 1 -> 63 without (BSR would give 0).
show("lzcnt", struct.pack("<2Q", 0, 1), struct.pack("<Q", 64) + b"\x01" + b"\xaa" * 7 + struct.pack("<Q", 63) + b"\x00" + b"\xaa" * 7)

# ADX: CF and OF chains are independent.
show("adx", struct.pack("<3Q", M64, 1, 0), struct.pack("<QQ", 1, 1) + bytes([1, 0, 1, 1, 0, 1, 0, 0]))

# SHA: SHA-256 initial hash state, first round constants plus W = 0.
H = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
# Intel's lane order: SRC1 = {C, D, G, H} = (CDGH), SRC2 = (ABEF), high dword first.
abef = H[0] << 96 | H[1] << 64 | H[4] << 32 | H[5]
cdgh = H[2] << 96 | H[3] << 64 | H[6] << 32 | H[7]
wk = 0x71374491 << 32 | 0x428A2F98
show("sha", le(cdgh, 16) + le(abef, 16) + le(wk, 16), le(sha256rnds2(cdgh, abef, wk), 16))

# GFNI: GF2P8MULB bytewise; 0x53 * 0xCA = 1 (AES inverse pair), 2 * 0x80 = 0x1B.
ga = bytes([0x53, 0x02, 0x03, 0xFF, 0x00, 0x01, 0x8D, 0x57] + list(range(0x10, 0x18)))
gb = bytes([0xCA, 0x80, 0x03, 0xFF, 0x77, 0x77, 0x02, 0x83] + list(range(0xF0, 0xF8)))
show("gfni", ga + gb, bytes(gf_mul(x, y) for x, y in zip(ga, gb)))

# VAES: one AESENC per 128-bit lane; lane 1 swaps the white-paper operands.
show("vaes", state + key + key + state, aesenc(state, key) + aesenc(key, state))

# VPCLMULQDQ imm 0x10: SRC1.low64 x SRC2.high64 in each lane.
va = [0x0123_4567_89AB_CDEF, 0x1111, 0xDEAD_BEEF_0000_0003, 0x2222]
vb = [0x3333, 0xF0E1_D2C3_B4A5_9687, 0x4444, 0x8000_0000_0000_0005]
show("vpclmul", b"".join(le(x, 8) for x in va + vb),
     le(clmul(va[0], vb[1]), 16) + le(clmul(va[2], vb[3]), 16))

# RDPID: TSC_AUX is fixed at zero.
show("rdpid", b"", le(0, 8))

# PREFETCHW, CLFLUSHOPT, CLWB: complete without fault, then store a marker.
for name in ("prefetchw", "clflushopt", "clwb"):
    show(name, b"", le(0x600D, 4))
