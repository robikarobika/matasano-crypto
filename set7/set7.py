# -*- coding: utf-8 -*-

import IPython
import binascii
import base64
from pwn import *
import itertools as it
from pprint import *
import operator as op
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import os
import random
import zlib
import multiprocessing as mp

import sys
sys.path.append('..')

from set5_utils import *
from set3_utils import *
from set6_utils import *
from set2_utils import *
from set7_utils import *


# def padPKCS7semis(x, padto):
# 	diff = (padto - (len(x)%padto)) % 16

# 	padded = x + ';'*diff
# 	return padded


# print "Challenge 50 Hashing with CBC-MAC"
# js = "alert('MZA who was that?');\n"
# js_padded = padPKCS7(js, 16)

# iv = '\x00'*16
# key = "YELLOW SUBMARINE"

# assert binascii.hexlify(CBC_MAC(key, iv, js_padded)) == "296b8d7cb78a243dda4d0a61d33bbdd1"

# # Forge this JS snippet, adding a comment so illegal characters after are ignored
# forge = "alert('Ayo, the Wu is back!');//"
# forge_padded = padPKCS7(forge, 16)

# mac = CBC_MAC(key, iv, forge_padded)
# concat_forge = forge_padded + xor(mac, js_padded[:16]) + js_padded[16:]
# print "concat_forge", repr(concat_forge)

# assert binascii.hexlify(CBC_MAC(key, iv, concat_forge)) == "296b8d7cb78a243dda4d0a61d33bbdd1"


print "Challenge 51 Compression Ratio Side-Channel Attacks — or CRIME!"

def compression_oracle_ctr(ptext):
    rand_key = os.urandom(16)
    rand_nonce = u64(os.urandom(8))
    ctr = CTR(Cipher(algorithm = algorithms.AES(rand_key), mode = modes.ECB(), backend=default_backend()), rand_nonce)
    return len(ctr.encrypt(zlib.compress(ptext)))


def compression_oracle_cbc(ptext):
    rand_key = os.urandom(16)
    rand_nonce = os.urandom(16)
    ptext = zlib.compress(ptext)

    cipher = Cipher(algorithm = algorithms.AES(rand_key), mode = modes.CBC(rand_nonce), backend=default_backend())
    enc = cipher.encryptor()

    ciphertext = enc.update(padPKCS7(ptext, 16)) + enc.finalize()
    return len(ciphertext)


request = """POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: {}
{}"""

base64_chars = "T0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSUVWXYZ="
padding_chars = "!@#$%^&*()-`~[]}{"

def format_request(content):
    return request.format(str(len(content)), content)

def compression_oracle_worker(args):
    padding, cookie = args
    return (oracle(format_request(padding + cookie)), padding + cookie, padding)

def get_padding(text):
    ''' 
    This function adds the proper padding such that we push the length of the compressed, encrypted data past a block boundary, when there is no extra compression.
    '''

    padding = ""
    base_len = compression_oracle_cbc(format_request(text))

    for i in xrange(17):
        padding += padding_chars[i]
        padded_len = compression_oracle_cbc(format_request(padding + text))
        if padded_len > base_len:
            # We've pushed the padding past a block boundary
            return padding


def crime_attack():
    final = "sessionid="

    # Get padding for CBC mode
    for i in xrange(22):  
        padding = get_padding(final)

        pool = mp.Pool(processes = 8) 
        base64_perms = [[padding[:-1], final + "".join(perm)] for perm in it.permutations(base64_chars, 2)]
        base64_perms += [[padding[:-2], final + "".join(perm)] for perm in it.permutations(base64_chars, 2)]

        compression_lens = pool.map(compression_oracle_worker, base64_perms)

        best_compression, best_cookie, best_padding = min(compression_lens, key=operator.itemgetter(0))

        final = best_cookie[len(best_padding):]

    return final


# oracle = compression_oracle_ctr
# found_session_id = crime_attack()
# assert found_session_id == "sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="

oracle = compression_oracle_cbc
found_session_id = crime_attack()

assert found_session_id == "sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="
