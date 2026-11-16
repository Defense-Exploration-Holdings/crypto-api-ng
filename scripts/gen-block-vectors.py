#!/usr/bin/env python3
"""Generates the test vectors of the hashers that are not in crypto-api 0.8.5 and have no
`node:crypto` or `hashlib` implementation: Tiger, Tiger2 and Streebog (test/vectors/blocks/).

Both algorithms are implemented here from their specifications, in plain Python and in a way that
shares nothing with the Zig and JavaScript code under test. Before writing anything the script
checks its own implementations against the published test vectors (Tiger: the reference test
vectors of the design; Streebog: the empty message and the 63-byte message of RFC 6986), and the
Tiger S-box generator against typed-in words of the reference tables.

The inputs are `pattern(length, tag)` (see below), so only the lengths are stored. The digest
is the full digest in hex; the tests truncate it for the shorter Tiger sizes.

  python3 scripts/gen-block-vectors.py
"""
import json
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'test', 'vectors', 'blocks')
M = (1 << 64) - 1


def pattern(length, tag):
    return bytes((i * 31 + tag * 17 + length) & 255 for i in range(length))


# ---- Tiger ----------------------------------------------------------------------------------

TIGER_SEED = b'Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham'
TIGER_IV = [0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xF096A5B4C3B2E187]


def tiger_compress(table, state, x):
    a, b, c = state
    aa, bb, cc = a, b, c
    x = list(x)

    def rnd(a, b, c, xv, mul):
        c ^= xv
        a = (a - (table[c & 255] ^ table[256 + ((c >> 16) & 255)] ^ table[512 + ((c >> 32) & 255)] ^ table[768 + ((c >> 48) & 255)])) & M
        b = (b + (table[768 + ((c >> 8) & 255)] ^ table[512 + ((c >> 24) & 255)] ^ table[256 + ((c >> 40) & 255)] ^ table[(c >> 56) & 255])) & M
        return a, (b * mul) & M, c

    def key_schedule(x):
        x[0] = (x[0] - (x[7] ^ 0xA5A5A5A5A5A5A5A5)) & M
        x[1] ^= x[0]
        x[2] = (x[2] + x[1]) & M
        x[3] = (x[3] - (x[2] ^ ((~x[1] & M) << 19 & M))) & M
        x[4] ^= x[3]
        x[5] = (x[5] + x[4]) & M
        x[6] = (x[6] - (x[5] ^ ((~x[4] & M) >> 23))) & M
        x[7] ^= x[6]
        x[0] = (x[0] + x[7]) & M
        x[1] = (x[1] - (x[0] ^ ((~x[7] & M) << 19 & M))) & M
        x[2] ^= x[1]
        x[3] = (x[3] + x[2]) & M
        x[4] = (x[4] - (x[3] ^ ((~x[2] & M) >> 23))) & M
        x[5] ^= x[4]
        x[6] = (x[6] + x[5]) & M
        x[7] = (x[7] - (x[6] ^ 0x0123456789ABCDEF)) & M

    for p in range(3):
        if p:
            key_schedule(x)
        mul = (5, 7, 9)[p]
        a, b, c = rnd(a, b, c, x[0], mul)
        b, c, a = rnd(b, c, a, x[1], mul)
        c, a, b = rnd(c, a, b, x[2], mul)
        a, b, c = rnd(a, b, c, x[3], mul)
        b, c, a = rnd(b, c, a, x[4], mul)
        c, a, b = rnd(c, a, b, x[5], mul)
        a, b, c = rnd(a, b, c, x[6], mul)
        b, c, a = rnd(b, c, a, x[7], mul)
        a, b, c = c, a, b
    return [a ^ aa, (b - bb) & M, (c + cc) & M]


def tiger_sboxes():
    """The S-boxes, from the generator of the design (5 passes over the table bytes)."""
    tb = [bytearray([i & 255] * 8) for i in range(1024)]
    state = list(TIGER_IV)
    x = [int.from_bytes((TIGER_SEED + bytes(64))[8 * i:8 * i + 8], 'little') for i in range(8)]
    abc = 2
    for _ in range(5):
        for i in range(256):
            for sb in range(0, 1024, 256):
                abc += 1
                if abc == 3:
                    abc = 0
                    table = [int.from_bytes(t, 'little') for t in tb]
                    state = tiger_compress(table, state, x)
                sbytes = state[abc].to_bytes(8, 'little')
                for col in range(8):
                    tb[sb + i][col], tb[sb + sbytes[col]][col] = tb[sb + sbytes[col]][col], tb[sb + i][col]
    return [int.from_bytes(t, 'little') for t in tb]


TIGER_TABLE = tiger_sboxes()
assert TIGER_TABLE[0] == 0x02AAB17CF7E90C5E and TIGER_TABLE[1] == 0xAC424B03E243A8EC


def tiger(msg, pad=0x01):
    state = list(TIGER_IV)
    length = len(msg)
    data = bytes(msg)
    while len(data) >= 64:
        state = tiger_compress(TIGER_TABLE, state, [int.from_bytes(data[8 * i:8 * i + 8], 'little') for i in range(8)])
        data = data[64:]
    data += bytes([pad])
    data += bytes(-len(data) % 8)
    if len(data) > 56:
        data += bytes(64 - len(data))
        state = tiger_compress(TIGER_TABLE, state, [int.from_bytes(data[8 * i:8 * i + 8], 'little') for i in range(8)])
        data = b''
    data += bytes(56 - len(data)) + (length * 8).to_bytes(8, 'little')
    state = tiger_compress(TIGER_TABLE, state, [int.from_bytes(data[8 * i:8 * i + 8], 'little') for i in range(8)])
    return b''.join(w.to_bytes(8, 'little') for w in state)


# ---- Streebog (RFC 6986) ----------------------------------------------------------------------

PI = [
    0xfc, 0xee, 0xdd, 0x11, 0xcf, 0x6e, 0x31, 0x16, 0xfb, 0xc4, 0xfa, 0xda, 0x23, 0xc5, 0x04, 0x4d,
    0xe9, 0x77, 0xf0, 0xdb, 0x93, 0x2e, 0x99, 0xba, 0x17, 0x36, 0xf1, 0xbb, 0x14, 0xcd, 0x5f, 0xc1,
    0xf9, 0x18, 0x65, 0x5a, 0xe2, 0x5c, 0xef, 0x21, 0x81, 0x1c, 0x3c, 0x42, 0x8b, 0x01, 0x8e, 0x4f,
    0x05, 0x84, 0x02, 0xae, 0xe3, 0x6a, 0x8f, 0xa0, 0x06, 0x0b, 0xed, 0x98, 0x7f, 0xd4, 0xd3, 0x1f,
    0xeb, 0x34, 0x2c, 0x51, 0xea, 0xc8, 0x48, 0xab, 0xf2, 0x2a, 0x68, 0xa2, 0xfd, 0x3a, 0xce, 0xcc,
    0xb5, 0x70, 0x0e, 0x56, 0x08, 0x0c, 0x76, 0x12, 0xbf, 0x72, 0x13, 0x47, 0x9c, 0xb7, 0x5d, 0x87,
    0x15, 0xa1, 0x96, 0x29, 0x10, 0x7b, 0x9a, 0xc7, 0xf3, 0x91, 0x78, 0x6f, 0x9d, 0x9e, 0xb2, 0xb1,
    0x32, 0x75, 0x19, 0x3d, 0xff, 0x35, 0x8a, 0x7e, 0x6d, 0x54, 0xc6, 0x80, 0xc3, 0xbd, 0x0d, 0x57,
    0xdf, 0xf5, 0x24, 0xa9, 0x3e, 0xa8, 0x43, 0xc9, 0xd7, 0x79, 0xd6, 0xf6, 0x7c, 0x22, 0xb9, 0x03,
    0xe0, 0x0f, 0xec, 0xde, 0x7a, 0x94, 0xb0, 0xbc, 0xdc, 0xe8, 0x28, 0x50, 0x4e, 0x33, 0x0a, 0x4a,
    0xa7, 0x97, 0x60, 0x73, 0x1e, 0x00, 0x62, 0x44, 0x1a, 0xb8, 0x38, 0x82, 0x64, 0x9f, 0x26, 0x41,
    0xad, 0x45, 0x46, 0x92, 0x27, 0x5e, 0x55, 0x2f, 0x8c, 0xa3, 0xa5, 0x7d, 0x69, 0xd5, 0x95, 0x3b,
    0x07, 0x58, 0xb3, 0x40, 0x86, 0xac, 0x1d, 0xf7, 0x30, 0x37, 0x6b, 0xe4, 0x88, 0xd9, 0xe7, 0x89,
    0xe1, 0x1b, 0x83, 0x49, 0x4c, 0x3f, 0xf8, 0xfe, 0x8d, 0x53, 0xaa, 0x90, 0xca, 0xd8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xa4, 0x2d, 0x2b, 0x09, 0x5b, 0xcb, 0x9b, 0x25, 0xd0, 0xbe, 0xe5, 0x6c, 0x52,
    0x59, 0xa6, 0x74, 0xd2, 0xe6, 0xf4, 0xb4, 0xc0, 0xd1, 0x66, 0xaf, 0xc2, 0x39, 0x4b, 0x63, 0xb6,
]

# Row i of the linear map L: the contribution of bit i of a 64-bit word.
A = [
    0x641c314b2b8ee083, 0xc83862965601dd1b, 0x8d70c431ac02a736, 0x07e095624504536c,
    0x0edd37c48a08a6d8, 0x1ca76e95091051ad, 0x3853dc371220a247, 0x70a6a56e2440598e,
    0xa48b474f9ef5dc18, 0x550b8e9e21f7a530, 0xaa16012142f35760, 0x492c024284fbaec0,
    0x9258048415eb419d, 0x39b008152acb8227, 0x727d102a548b194e, 0xe4fa2054a80b329c,
    0xf97d86d98a327728, 0xeffa11af0964ee50, 0xc3e9224312c8c1a0, 0x9bcf4486248d9f5d,
    0x2b838811480723ba, 0x561b0d22900e4669, 0xac361a443d1c8cd2, 0x456c34887a3805b9,
    0x5b068c651810a89e, 0xb60c05ca30204d21, 0x71180a8960409a42, 0xe230140fc0802984,
    0xd960281e9d1d5215, 0xafc0503c273aa42a, 0x439da0784e745554, 0x86275df09ce8aaa8,
    0x0321658cba93c138, 0x0642ca05693b9f70, 0x0c84890ad27623e0, 0x18150f14b9ec46dd,
    0x302a1e286fc58ca7, 0x60543c50de970553, 0xc0a878a0a1330aa6, 0x9d4df05d5f661451,
    0xaccc9ca9328a8950, 0x4585254f64090fa0, 0x8a174a9ec8121e5d, 0x092e94218d243cba,
    0x125c354207487869, 0x24b86a840e90f0d2, 0x486dd4151c3dfdb9, 0x90dab52a387ae76f,
    0x46b60f011a83988e, 0x8c711e02341b2d01, 0x05e23c0468365a02, 0x0ad97808d06cb404,
    0x14aff010bdd87508, 0x2843fd2067adea10, 0x5086e740ce47c920, 0xa011d380818e8f40,
    0x83478b07b2468764, 0x1b8e0b0e798c13c8, 0x3601161cf205268d, 0x6c022c38f90a4c07,
    0xd8045870ef14980e, 0xad08b0e0c3282d1c, 0x47107ddd9b505a38, 0x8e20faa72ba0b470,
]

# The twelve iteration constants, eight 64-bit words each, little-endian.
C = [
    0xdd806559f2a64507, 0x05767436cc744d23, 0xa2422a08a460d315, 0x4b7ce09192676901,
    0x714eb88d7585c4fc, 0x2f6a76432e45d016, 0xebcb2f81c0657c1f, 0xb1085bda1ecadae9,
    0xe679047021b19bb7, 0x55dda21bd7cbcd56, 0x5cb561c2db0aa7ca, 0x9ab5176b12d69958,
    0x61d55e0f16b50131, 0xf3feea720a232b98, 0x4fe39d460f70b5d7, 0x6fa3b58aa99d2f1a,
    0x991e96f50aba0ab2, 0xc2b6f443867adb31, 0xc1c93a376062db09, 0xd3e20fe490359eb1,
    0xf2ea7514b1297b7b, 0x06f15e5f529c1f8b, 0x0a39fc286a3d8435, 0xf574dcac2bce2fc7,
    0x220cbebc84e3d12e, 0x3453eaa193e837f1, 0xd8b71333935203be, 0xa9d72c82ed03d675,
    0x9d721cad685e353f, 0x488e857e335c3c7d, 0xf948e1a05d71e4dd, 0xef1fdfb3e81566d2,
    0x601758fd7c6cfe57, 0x7a56a27ea9ea63f5, 0xdfff00b723271a16, 0xbfcd1747253af5a3,
    0x359e35d7800fffbd, 0x7f151c1f1686104a, 0x9a3f410c6ca92363, 0x4bea6bacad474799,
    0xfa68407a46647d6e, 0xbf71c57236904f35, 0x0af21f66c2bec6b6, 0xcffaa6b71c9ab7b4,
    0x187f9ab49af08ec6, 0x2d66c4f95142a46c, 0x6fa4c33b7a3039c0, 0xae4faeae1d3ad3d9,
    0x8886564d3a14d493, 0x3517454ca23c4af3, 0x06476983284a0504, 0x0992abc52d822c37,
    0xd3473e33197a93c9, 0x399ec6c7e6bf87c9, 0x51ac86febf240954, 0xf4c70e16eeaac5ec,
    0xa47f0dd4bf02e71e, 0x36acc2355951a8d9, 0x69d18d2bd1a5c42f, 0xf4892bcb929b0690,
    0x89b4443b4ddbc49a, 0x4eb7f8719c36de1e, 0x03e7aa020c6e4141, 0x9b1f5b424d93c9a7,
    0x7261445183235adb, 0x0e38dc92cb1f2a60, 0x7b2b8a9aa6079c54, 0x800a440bdbb2ceb1,
    0x3cd955b7e00d0984, 0x3a7d3a1b25894224, 0x944c9ad8ec165fde, 0x378f5a541631229b,
    0x74b4c7fb98459ced, 0x3698fad1153bb6c3, 0x7a1e6c303b7652f4, 0x9fe76702af69334b,
    0x1fffe18a1b336103, 0x8941e71cff8a78db, 0x382ae548b2e4f3f3, 0xabbedea680056f52,
    0x6bcaa4cd81f32d1b, 0xdea2594ac06fd85d, 0xefbacd1d7d476e98, 0x8a1d71efea48b9ca,
    0x2001802114846679, 0xd8fa6bbbebab0761, 0x3002c6cd635afe94, 0x7bcd9ed0efc889fb,
    0x48bc924af11bd720, 0xfaf417d5d9b21b99, 0xe71da4aa88e12852, 0x5d80ef9d1891cc86,
    0xf82012d430219f9b, 0xcda43c32bcdf1d77, 0xd21380b00449b17a, 0x378ee767f11631ba,
]


def linear(w):
    r = 0
    for i in range(64):
        if (w >> i) & 1:
            r ^= A[i]
    return r


def lps(data):
    s = [PI[b] for b in data]
    p = [s[8 * j + i] for i in range(8) for j in range(8)]
    return b''.join(linear(int.from_bytes(bytes(p[8 * i:8 * i + 8]), 'little')).to_bytes(8, 'little') for i in range(8))


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


CONSTANTS = [b''.join(w.to_bytes(8, 'little') for w in C[8 * i:8 * i + 8]) for i in range(12)]


def e(k, m):
    for i in range(12):
        m = lps(xor(k, m))
        k = lps(xor(k, CONSTANTS[i]))
    return xor(k, m)


def g(h, n, m):
    return xor(xor(e(lps(xor(h, n)), m), h), m)


def add512(a, b):
    return ((int.from_bytes(a, 'little') + int.from_bytes(b, 'little')) % (1 << 512)).to_bytes(64, 'little')


def streebog(msg, bits):
    h = bytes([1] * 64) if bits == 256 else bytes(64)
    n = bytes(64)
    sigma = bytes(64)
    zero = bytes(64)
    i = 0
    while len(msg) - i >= 64:
        m = msg[i:i + 64]
        h = g(h, n, m)
        n = add512(n, (512).to_bytes(64, 'little'))
        sigma = add512(sigma, m)
        i += 64
    rest = msg[i:]
    m = rest + b'\x01' + bytes(63 - len(rest))
    h = g(h, n, m)
    n = add512(n, (8 * len(rest)).to_bytes(64, 'little'))
    sigma = add512(sigma, m)
    h = g(h, zero, n)
    h = g(h, zero, sigma)
    return h[32:] if bits == 256 else h


# ---- self-check against the published vectors --------------------------------------------------

TIGER_PUBLISHED = [
    (b'', '3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3', '4441be75f6018773c206c22745374b924aa8313fef919f41'),
    (b'abc', '2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93', 'f68d7bc5af4b43a06e048d7829560d4a9415658bb0b1f3bf'),
    (b'Tiger', 'dd00230799f5009fec6debc838bb6a27df2b9d6f110c7937', None),
    (b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-', 'f71c8583902afb879edfe610f82c0d4786a3a534504486b5', None),
    (TIGER_SEED, '8a866829040a410c729ad23f5ada711603b3cdd357e4c15e', None),
]
for message, t1, t2 in TIGER_PUBLISHED:
    assert tiger(message).hex() == t1, message
    if t2:
        assert tiger(message, 0x80).hex() == t2, message
assert tiger(b'a' * 1000000).hex() == '6db0e2729cbead93d715c6a7d36302e9b3cee0d2bc314b41'
M1 = b'012345678901234567890123456789012345678901234567890123456789012'
assert streebog(b'', 256).hex() == '3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb'
assert streebog(b'', 512).hex() == '8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a'
assert streebog(M1, 256).hex() == '9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500'
assert streebog(M1, 512).hex() == '1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48'

# ---- vectors -------------------------------------------------------------------------------------

LENGTHS = sorted(set(list(range(0, 140)) + [191, 192, 193, 255, 256, 257, 1000, 4097]))


def write(name, rows):
    with open(os.path.join(OUT, name), 'w') as f:
        f.write('[\n' + ',\n'.join('  ' + json.dumps(r, separators=(',', ':')) for r in rows) + '\n]\n')


os.makedirs(OUT, exist_ok=True)
write('tiger.json', [{'length': n, 'tag': n % 5, 'digest': tiger(pattern(n, n % 5)).hex()} for n in LENGTHS])
write('tiger2.json', [{'length': n, 'tag': n % 5, 'digest': tiger(pattern(n, n % 5), 0x80).hex()} for n in LENGTHS])
write('streebog256.json', [{'length': n, 'tag': n % 5, 'digest': streebog(pattern(n, n % 5), 256).hex()} for n in LENGTHS])
write('streebog512.json', [{'length': n, 'tag': n % 5, 'digest': streebog(pattern(n, n % 5), 512).hex()} for n in LENGTHS])
print('ok', len(LENGTHS), 'lengths')
