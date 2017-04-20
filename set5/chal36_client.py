from pwn import *
import binascii
import base64
from pwn import *
import itertools as it
from pprint import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import hmac

import os
import random
import sys
sys.path.append('..')

from set5_utils import *

r = remote('localhost', 1234)

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

g = 2 # generator for group of prime p
k = 3
# passwd = 'alotofentropy'
passwd = 'wrongpass'

a = random.randint(0, N)
A = pow(g, a, N)

#Challenge 37, Break SRP with a zero key
# If A is 0 or a multiple of N, then the S computed by server in S = A * pow(v, u, N)
# will always be 0, because S is taken mod N
A = N*2

print "Attempt login"
r.sendline(str(A))

salt = r.recvline(keepends = False)
print "C: Received salt", salt
B = int(r.recvline(keepends = False))
print "C: Received B"

# Compute scrambling parameter u
u = int(hashlib.sha256(str(A) + str(B)).hexdigest(), 16)

# Generate
auth_attempt = int(hashlib.sha256(salt+passwd).hexdigest(), 16)

S = B-k*pow(g, auth_attempt, N)
S = pow(S, a+u*auth_attempt, N)
K = hashlib.sha256(str(S)).digest()

#Challenge 37, Break SRP with a zero key
if passwd == 'wrongpass':
    K = hashlib.sha256(str(0)).digest()

print "C: Sending HMAC of K and salt"
hmac_digest = hmac.new(salt, str(K), digestmod = hashlib.sha256).digest()
r.sendline(hmac_digest)
