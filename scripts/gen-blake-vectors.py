#!/usr/bin/env python3
"""Generates the BLAKE test vectors under test/vectors/blake/.

  blake2-kat.json     a selection of the official BLAKE2 known-answer tests (blake2b and blake2s),
                      from https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2-kat.json
                      (pass that file as the first argument). Input is the bytes 0..n-1, the
                      key (when "keyed") the bytes 0..k-1 with k = 64 (blake2b) or 32 (blake2s).
  blake2-params.json  digest lengths, keys, salts and personalizations, computed with Python's
                      hashlib (its own BLAKE2 code, not OpenSSL): an independent implementation
                      for the options that node:crypto does not expose. The inputs are
                      `pattern(length, tag)` (see below), so only the lengths are stored.
  blake3.json         the official BLAKE3 test vectors, verbatim:
                      https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
                      (pass that file as the second argument).

  python3 scripts/gen-blake-vectors.py blake2-kat.json blake3-test_vectors.json
"""
import hashlib
import json
import os
import random
import shutil
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'test', 'vectors', 'blake')


def write(name, data, compact=True):
    with open(os.path.join(OUT, name), 'w') as f:
        if compact:
            f.write('[\n' + ',\n'.join('  ' + json.dumps(e, separators=(',', ':')) for e in data) + '\n]\n')
        else:
            json.dump(data, f, indent=2)
            f.write('\n')


KAT_LENGTHS = sorted(set(list(range(0, 71)) + list(range(120, 136)) + [191, 192, 193, 254, 255]))


def kat(path):
    out = []
    for e in json.load(open(path)):
        n = len(e['in']) // 2
        if e['hash'] in ('blake2b', 'blake2s') and n in KAT_LENGTHS:
            out.append({'hash': e['hash'], 'keyed': bool(e['key']), 'inLen': n, 'hex': e['out']})
    write('blake2-kat.json', out)


def pattern(length, tag):
    """The test inputs: the same bytes in this script and in test/blake.test.js."""
    return bytes((i * 31 + tag * 17 + length) & 255 for i in range(length))


def params():
    rng = random.Random(7)
    out = []
    for algo, digest, block, keymax, plen in (('blake2b', 64, 128, 64, 16), ('blake2s', 32, 64, 32, 8)):
        make = getattr(hashlib, algo)

        def add(n, inlen, key=0, salt=0, person=0):
            args = {}
            if key:
                args['key'] = pattern(key, 1)
            if salt:
                args['salt'] = pattern(salt, 2)
            if person:
                args['person'] = pattern(person, 3)
            e = {'algo': algo, 'length': n * 8, 'inLen': inlen}
            for name, v in (('keyLen', key), ('saltLen', salt), ('personLen', person)):
                if v:
                    e[name] = v
            e['hex'] = make(pattern(inlen, 0), digest_size=n, **args).hexdigest()
            out.append(e)

        lengths = [0, 1, block - 1, block, block + 1, 2 * block, 2 * block + 3]
        for n in range(1, digest + 1):
            add(n, rng.choice(lengths))
            add(n, rng.choice(lengths), rng.randrange(1, keymax + 1), rng.randrange(1, plen + 1), rng.randrange(1, plen + 1))
        for k in range(1, keymax + 1):
            add(digest, rng.choice(lengths), key=k)
        for k in range(1, plen + 1):
            add(digest, rng.choice(lengths), salt=k)
            add(digest, rng.choice(lengths), person=k)
    write('blake2-params.json', out)


if __name__ == '__main__':
    os.makedirs(OUT, exist_ok=True)
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    kat(sys.argv[1])
    params()
    shutil.copyfile(sys.argv[2], os.path.join(OUT, 'blake3.json'))
