import binascii
import base64
from pwn import *
import itertools as it
from pprint import *
import operator as op
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import gensafeprime
import math
import gmpy2
import hashlib
import os
import random
import re
from Crypto.Cipher import PKCS1_v1_5

import sys
sys.path.append('..')

from set5_utils import *
from set6_utils import *


print "6.42 Bleichenbacher's e=3 RSA Attack"

sha1_asn1 = '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'

# vulnerable implementation
def verify(signature, message, pk):
    # generate clearsig
    clearsig = pow(signature, pk[0], pk[1])
    clearsig = '\x00' + int2bytes(clearsig)
    print 'clearsig', repr(clearsig)

    # will verify if the signature has proper format.
    # vulnerable because it doesn't check all the ffs in the middle

    # If we can't find the signature  marker, verification failed.
    if clearsig[0:3] != '\x00\x01\xff':
        raise ValueError("No sig marker")

    # Find the 00 separator between the padding and the payload
    sep_idx = clearsig.index('\x00', 2)

    # Get the hash and the hash method
    if not clearsig[sep_idx+1:].startswith(sha1_asn1) :
        raise ValueError("no asn1")

    # vulnerable python-rsa version, taking all the remainder of string after asn1 as the hash
    # signature_hash = clearsig[sep_idx+len(sha1_asn1)+1:]

    # weaker version, taking only the next 20 bytes as hash, allowing us to append garbage
    signature_hash = clearsig[sep_idx+len(sha1_asn1)+1:sep_idx+len(sha1_asn1)+1+20]
    print "signature_hash", signature_hash

    message_hash = hashlib.sha1(message).digest()

    # Compare the real hash to the hash in the signature
    if message_hash != signature_hash:
        raise ValueError("hashes don't match")

    return True

def forgeSignature(msg, pk):
    (e, n) = pk
    msg_hash = hashlib.sha1(msg).digest()
    garbage = '\x00'*75
    forge_sig =  "\x00\x01\xff\x00" + sha1_asn1 + msg_hash + garbage

    forge_sig_num = int(binascii.hexlify(forge_sig), 16)

    # compute the cube root of our forged signature block
    (cube_root, exact) = gmpy2.iroot(forge_sig_num, 3)
    cube_root += 1

    # make sure we don't wrap the modulus
    assert n > pow(int(cube_root), e)

    # recovered = int2bytes(pow(int(cube_root), pk[0], pk[1]))
    recovered = int2bytes(pow(int(cube_root), e, n))

    assert "\x01\xff" in recovered
    assert sha1_asn1 in recovered
    assert msg_hash in recovered

    return int(cube_root)

message = "hello mom"

# pk, sk = rsa_keygen(1024)

# forge_sig = forgeSignature(message, pk)

# assert verify(forge_sig, message, pk) == True

print '6.43 DSA key recovery from nonce'

# msg = 'sign me'

# Create secret keys, random values mod p
# d = random.randint(0, p)
# B = modexp(g, d, p)
#
# (r, sig) = dsa_sign(msg, d)
# print dsa_verify(msg, r, sig, B)


print '6.44 DSA nonce recovery from repeated nonce'
y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821

# DSA params
p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1

q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b

g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291


def dsa_sign(msg, d):
    k_e = random.randint(0, q)
    r = pow(g, k_e, p) % q
    x = bytes2int(hashlib.sha1(msg).digest())

    s = ((x + d*r)*modinv(q, k_e)) % q

    return (r,s)


def dsa_verify(msg, r, sig, B):
    x = bytes2int(hashlib.sha1(msg).digest())

    #compute aux value w
    s_inv = modinv(q, sig)
    u_1  = s_inv*x % q
    u_2  = s_inv*r % q

    v = (pow(g, u_1, p) * pow(B, u_2, p) % p) % q

    return v == r%q


lines = open('44.txt').read()
lines = lines.split('\n')

tuples = []
for i in xrange(0, len(lines), 4):
    msg = lines[i].split('msg: ')[1]
    s = int(lines[i+1].split('s: ')[1])
    r = int(lines[i+2].split('r: ')[1])
    m = int(lines[i+3].split('m: ')[1], 16)

    tuples.append((msg, s, r, m))


msg_pairs = list(it.combinations(tuples, 2))

# if the r's are equal
repeat_k_pairs = [pair for pair in msg_pairs if pair[0][2] == pair[1][2]]
match_pair = repeat_k_pairs[0]


def recover_k(m1, m2, s1, s2):
    return ((m1-m2)*modinv(q, s1-s2)) %q

msg1 = match_pair[0][0]
s1 = match_pair[0][1]
r1 = match_pair[0][2]
m1 = match_pair[0][3]
s2 = match_pair[1][1]
r2 = match_pair[1][2]
m2 = match_pair[1][3]

assert dsa_verify(msg1, r1, s1, y)

k = recover_k(m1, m2, s1, s2)

def recover_privkey(s, r, m, k_e):
    return ((s*k_e - m)*modinv(q, r))% q

privkey_num = recover_privkey(s1, r1, m1, k)
assert pow(g, privkey_num, p) == y

assert hashlib.sha1(str(hex(privkey_num))[2:]).hexdigest() == 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'

print '6.45 DSA parameter tampering'

g = p+1
msg = "Hello, world"
secret_key = random.randint(0, p)
B = pow(g, secret_key, p)

print 'B', B

z = 3
r = pow(g, z, p) % q
s = r*modinv(q, z) %q

assert dsa_verify(msg, r, s, B)



print '6.46 RSA parity oracle'
secret_msg = base64.b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')

def parity_oracle(enc, d, n):
    decrypted = pow(enc, d, n)
    return decrypted%2

def break_message():
    pk, sk = rsa_keygen(1024)

    e = pk[0]
    n = pk[1]
    d = sk[0]
    enc_text = pow(bytes2int(secret_msg), e, n)

    assert int2bytes(pow(enc_text, d, n)) == secret_msg

    upper_bound = n
    lower_bound = 0
    for i in xrange(1, int(math.log(n, 2))):
        multiplier = pow(2, i*e, n)
        is_odd = parity_oracle(multiplier*enc_text, d, n)

        if is_odd:
            lower_bound = (upper_bound+lower_bound)/2
        else:
            upper_bound = (upper_bound+lower_bound)/2

        if i%10 == 0:
            print 'upper_bound', int2bytes(upper_bound)

        if secret_msg in int2bytes(upper_bound):
            break

    # Found "That's why I found you don't play around with the Funky Cold Medina"
    assert secret_msg[:-2] in int2bytes(upper_bound)

break_message()


print "6.47 Bleichenbacher's padding oracle, simple"

pk, sk = rsa_keygen(128)
e = pk[0]
n = pk[1]
d = sk[0]
block_size = 32

def pkcs_oracle(msg_num):
    msg = pow(int(msg_num), d, n)
    msg = int2bytes(msg)
    return msg.startswith("\x02")

def pkcs1_5_pad(msg, blksize):
    assert blksize - len(msg) > 11
    padded = "\x00\x02"
    padded += os.urandom(blksize - len(msg) - 3)
    padded += "\x00"
    padded += msg

    assert len(padded) == blksize

    return padded

msg = "kick it, CC"
pad_num = bytes2int(pkcs1_5_pad(msg, block_size))
enc_num = pow(pad_num, e, n)
assert pkcs_oracle(enc_num)

B = pow(2, 256-16)
B2, B3 = 2.*B, 3.*B-1

def int_div(num, denom):
    return int(math.ceil(num/denom))

def rsa_multiply(enc_num, mult):
    return enc_num*pow(mult, e , n) % n

def find_first_s(enc_num):
    # because it's already correctly padded
    s_1 = int_div(n, B3)
    while True:
        mult_cnum = rsa_multiply(enc_num, s_1)
        if pkcs_oracle(mult_cnum):
            return s_1
        s_1 += 1

def find_next_s(M, s_0):
    # binary search
    # starting r
    (start, end) = M[0]
    r = int_div(2*(end*s_0 - B2), n)
    print 'r', r

    while True:
        start_s = int_div(B2+r*n, end)
        end_s = int((B3+r*n)/start)+1

        for s_i in range(start_s, end_s):
            mult_cnum = rsa_multiply(enc_num, s_i)
            if pkcs_oracle(mult_cnum):
                print 'find next s', s_i
                return s_i
        r += 1


def bbreak_message(enc_num):
    s_1 = find_first_s(enc_num)
    print 'first s', s_1

    M = [(B2, B3)]
    M = narrow_intervals(M, s_1)
    # print 'difference', M[0][1] - M[0][0]

    s_i = s_1
    # step 2, find next s

    while True:
        # step 2
        s_i = find_next_s(M, s_i)
        print s_i
        # step 3
        M = narrow_intervals(M, s_i)
        print 'narrow_intervals', M

        # step 4, check length of interval set
        print int(M[0][1])
        print int(M[0][0])
        print 'difference', int(M[0][1]) - int(M[0][0])
        if len(M) == 1 and int(M[0][0]) == int(M[0][1]):
            print "found it!"
            print repr(int2bytes(int(M[0][0])))
            break

    # We know m1 = m0s1 - rn.
    # find all possible values of r

def narrow_intervals(M, s_1):
    new_interval_set = []

    for (a, b) in M:
        print 'before low r', (a*s_1 - B3)/n
        low_r_range = int_div(a*s_1 - B3, n)
        print 'low_r_range', low_r_range
        high_r_range = int((b*s_1 - B2)/n)
        print 'befpre high range', (b*s_1 - B2)/n
        print 'high_r_range', high_r_range

        # if low_r_range > high_r_range:
        #     low_r_range -= 1

        for r in xrange(low_r_range, high_r_range+1):
            aa = max(a, math.ceil((B2+r*n)/s_1))
            print 'aa ceil', int(math.ceil((B2+r*n)/s_1))
            print 'aa', int(aa)
            bb = min(b, math.ceil((B3+r*n)/s_1))
            print 'bb ceil', int(math.ceil((B3+r*n)/s_1))
            print 'bb', int(bb)

            new_interval_set.append((aa, bb))
    return new_interval_set


# bbreak_message(enc_num)

# print "6.48 Bleichenbacher's padding oracle, advanced"
