<!--
The test-vectors folder was pulled from
https://github.com/algorand/bls_sigs_ref/tree/master/test-vectors

Copyright (c) 2019 Algorand

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
-->

The files in this directory comprises test inputs, one per line.

Each line is a space-separated tuple (msg, sk).

msg and sk should be interpreted as hex-encoded octet strings, wherein each
pair of hex characters represents one byte.

Equivalently, msg and sk can be interpreted as hexadecimal integers and then
converted to octet strings using I2OSP (RFC 8017).

In Python, the following code can be used to load the file:

~~~
import binascii
with open("fips_186_3", "r") as vec_file:
  test_inputs = [ tuple( binascii.unhexlify(val)       \
                  for val in line.strip().split(' ') ) \
                  for line in vec_file.readlines()     \
                ]
~~~

These files are extracted from the NIST CAVP ECDSA test vectors, available from
    https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3ecdsatestvectors.zip

## `sig_g1_X`, `sig_g2_X` subdirectories

The files in these subdirs correspond to the above, except that the lines in each
file are space-separated tuples (msg, sk, sig).

- In `sig_g1_X`, sig is the signature on msg under sk in the G1 group.

- In `sig_g2_X`, the signature is in the G2 group instead.

`X` is one of `aug`, `basic`, or `pop`, indicating signatures made with the
augmented, basic, or proof-of-possession schemes, respectively.

## `pop_g1`, `pop_g2` subdirectories

The files in these subdirs correspond to the above, except that the lines in each
file are space-separated tuples ("00", sk, proof). The literal string "00" helps
to avoid confusion with files containing (msg, sk).

- In `pop_g1`, proof is a proof of possession of the public key corresponding to sk
  in the G1 group.

- In `pop_g2`, the proof is in the G2 group instead.

## `hash_g1`, `hash_g2` subdirectories

The files in these subdirs correspond to the above, except that the lines in each
file are space-separated tuples (msg, "00", P). The literal string "00" helps
to avoid confusion with files containing (msg, sk).

- In `hash_g1`, P is the hash of msg to the G1 group.

- In `hash_g2`, P is the hash of msg to the G2 group.
