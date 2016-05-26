import binascii 
import base64
from pwn import *
import itertools as it
from pprint import *
import operator as op
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import time

import os
import random
import json
import sys
sys.path.append('..')

from set1_utils import *
from set3_utils import *
from set2_utils import *


print '4.25 Break read/write AES CTR'

rand_key = os.urandom(16)

def edit(ciphertext, offset, newtext):
	cipher = Cipher(algorithm = algorithms.AES(rand_key), mode = modes.ECB(), backend=default_backend())
	ctr = CTR(cipher, 0)

	ctr.encrypt('0'*offset)

	enc_newtext = ctr.encrypt(newtext)
	return ciphertext[:offset] + enc_newtext + ciphertext[offset+len(enc_newtext):]

def break_readwrite_ctr(ciphertext):
	'''
		Bit by bit, guess the plaintext character that, when encrypted and inserted into old ciphertext, results in the same ciphertext
	'''
	candidates = [chr(i) for i in xrange(0, 256)]
	result = ''

	for i in xrange(len(ciphertext)):
		for c in candidates:
			new_ciphertext = edit(ciphertext, i, c)

			if new_ciphertext == ciphertext:
				print 'i', c
				result += c

	return result



file = base64.b64decode(open('25.txt', 'r').read())

cipher = Cipher(algorithm = algorithms.AES('YELLOW SUBMARINE'), mode = modes.ECB(), backend=default_backend())
d = cipher.decryptor()
plaintext = d.update(file)


ctr = CTR(Cipher(algorithm = algorithms.AES(rand_key), mode = modes.ECB(), backend=default_backend()), 0)
ciphertext = ctr.encrypt(plaintext)

# print edit(ciphertext, 0, ciphertext)
# print break_readwrite_ctr(ciphertext)


print '4.26 CTR Bitflipping attack LOLZ'

rand_nonce = random.getrandbits(64)
rand_key = os.urandom(16)

def add_strings_and_ctr_encrypt(input_text):
	s = "comment1=cooking%20MCs;userdata=" # len(s) = 32
	s2 = ";comment2=%20like%20a%20pound%20of%20bacon"
	plaintext = s + input_text.replace(';', '%3B').replace('=', '%3D') + s2

	cipher = Cipher(algorithm = algorithms.AES(rand_key), mode = modes.ECB(), backend=default_backend())
	ctr = CTR(cipher, rand_nonce)

	return ctr.encrypt(plaintext)


def decrypt_and_check_admin(ciphertext):
	cipher = Cipher(algorithm = algorithms.AES(rand_key), mode = modes.ECB(), backend=default_backend())
	ctr = CTR(cipher, rand_nonce)

	return ';admin=true;' in ctr.decrypt(ciphertext)

s = '\x00admin\x00true\x00'
ciphertext = list(add_strings_and_ctr_encrypt(s))

ciphertext[32] = chr(ord(ciphertext[32]) ^ 59) # 59 is the decimal for ; http://www.nthelp.com/ascii.htm
ciphertext[38] = chr(ord(ciphertext[38]) ^ 61) # 61 is the decimal for = 
ciphertext[43] = chr(ord(ciphertext[43]) ^ 59)
ciphertext = ''.join(ciphertext)

cipher = Cipher(algorithm = algorithms.AES(rand_key), mode = modes.ECB(), backend=default_backend())
ctr = CTR(cipher, rand_nonce)

assert decrypt_and_check_admin(ciphertext)


print '4.27 Recover key from CBC when IV = Key'

rand_key = os.urandom(16)
iv = rand_key

def add_strings_and_cbc_encrypt(input_text):
	s = "comment1=cooking%20MCs;userdata="
	s2 = ";comment2=%20like%20a%20pound%20of%20bacon"
	plaintext = s + input_text.replace(';', '%3B').replace('=', '%3D') + s2

	cipher = Cipher(algorithm = algorithms.AES(rand_key), mode = modes.ECB(), backend=default_backend())
	cbc = CBC(cipher, iv)	

	return cbc.encrypt(plaintext)

def verify_ascii(plaintext):
	if any(ord(i) > 127 for i in plaintext):
		return False
	return True

def decrypt_and_check_admin(ciphertext):
	cipher = Cipher(algorithm = algorithms.AES(rand_key), mode = modes.ECB(), backend=default_backend())
	cbc = CBC(cipher, iv)	

	return ';admin=true;' in cbc.decrypt(ciphertext)


ciphertext = add_strings_and_cbc_encrypt('')
ciphertext = ciphertext[:16] + '\x00'*16 + ciphertext[:16] + ciphertext[48:]
# by inserting a block of \x00, when we CBC decrypt block 3, we recover the 'plaintext' of block 1 that has not been changed at all
# , having been xor'd with all 0's
# we also obviously have the plaintext of block 1, which we got by xor-ing by the IV
# so, recovering the IV is trivial — we simply xor out the 'plaintext' from block 1 to get the IV

cipher = Cipher(algorithm = algorithms.AES(rand_key), mode = modes.ECB(), backend=default_backend())
cbc = CBC(cipher, iv)

modified_plaintext = cbc.decrypt(ciphertext)
found_key = xor(modified_plaintext[:16], modified_plaintext[32:48]) #xor out the 'plaintext' from block 1 to get the IV

assert rand_key == found_key

