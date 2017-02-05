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
from set4_utils import *


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
# so, recovering the IV is trivial - we simply xor out the 'plaintext' from block 1 to get the IV

cipher = Cipher(algorithm = algorithms.AES(rand_key), mode = modes.ECB(), backend=default_backend())
cbc = CBC(cipher, iv)

modified_plaintext = cbc.decrypt(ciphertext)
found_key = xor(modified_plaintext[:16], modified_plaintext[32:48]) #xor out the 'plaintext' from block 1 to get the IV

assert rand_key == found_key

print '4.29 break SHA1 keyed mac with sign extension'


key = os.urandom(16)

message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
message_digest = authsha1(key, message)


def sha1_pad(message):
	padding = ''

	# append the bit '1' to the message
	padding += b'\x80'
	
	# append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
	# is congruent to 56 (mod 64)
	padding += b'\x00' * ((56 - (len(message) + 1) % 64) % 64)
	
	# append length of message (before pre-processing), in bits, as 64-bit big-endian integer
	message_bit_length = len(message) * 8
	padding += struct.pack(b'>Q', message_bit_length)

	return message + padding

def validate_oracle(message, digest):
	return authsha1(key, message) == digest

# need to find length of key. To do so, need to try keys of all lengths, each time substringing out the key  


def forgeHash(message, message_digest, extension_data):

	paddedMessageWithKey = sha1_pad(key + message) + extension_data
	#recreate internal state
	# the forged_digest picks up at the internal SHA1 5-register state of the valid key+message+padding
	# and adds my evil extension data to that internal state
	# message_byte_length is length of everything processed so far, which would be everything except the new extension data

	h = unpack_many(message_digest, word_size = 32, endianness='big')
	# print 'h', h
	forged_digest = SHA1(h, message_byte_length = len(paddedMessageWithKey) - len(extension_data)).update(extension_data).digest()

	for keylen_guess in xrange(1,40):
		# print keylen_guess

		paddedMessageSubstring = paddedMessageWithKey[keylen_guess:]

		# then, if we guessed the correct keylen_guess, we properly substring-ed out the key, and
		# the remaining substring, once appended to the key on server side, will have proper padding
		# and digest to the same thing as the forged_digest
	 	
	 	# print 'forged_message', authsha1(key, paddedMessageSubstring)

		if validate_oracle(paddedMessageSubstring, forged_digest):
			# we found the correct keylen_guess
			# and we can return the valid message and valid digest of the message 
			return paddedMessageSubstring, forged_digest

	
message, forged_digest = forgeHash(message, message_digest, ';admin=true')
print 'message', message



def 

