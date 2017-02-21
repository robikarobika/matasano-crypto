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

			if new_ciphertext[i] == ciphertext[i]:
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
# by inserting a block of \x00, when we CBC decrypt block 3, we recover the intermediate state of block 1 that has not been changed at all
# , having been xor'd with all 0's
# we also obviously have the plaintext of block 1, which we got by xor-ing by the IV
# so, recovering the IV is trivial - we simply xor out the intermediate state from block 1 to get the IV

cipher = Cipher(algorithm = algorithms.AES(rand_key), mode = modes.ECB(), backend=default_backend())
cbc = CBC(cipher, iv)

modified_plaintext = cbc.decrypt(ciphertext)
found_key = xor(modified_plaintext[:16], modified_plaintext[32:48]) #xor out the 'plaintext' from block 1 to get the IV

assert rand_key == found_key

print '4.28 Implement a SHA-1 keyed MAC'


def validate_oracle(key, message, digest):
	return authsha1(key, message) == digest

key = os.urandom(16)

text = "Verify this message"

text_mac_digest = authsha1(key, text)

print validate_oracle(key, text, text_mac_digest)


print '4.29 break SHA1 keyed mac with length extension'

# Make sure MD5 implem is correct
assert MD5("hello").hexdigest() == '5d41402abc4b2a76b9719d911017c592'

key = os.urandom(16)
# key = os.urandom(random.randint(3,40))

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


def forgeHash(message, message_digest, extension_data):

	#recreate internal state
	# the forged_digest picks up at the internal SHA1 5-register state of the valid key+message+padding
	# and adds my evil extension data to that internal state
	# message_byte_length is length of everything processed so far, which would be everything except the new extension data

	h = unpack_many(message_digest, word_size = 32, endianness='big')
	# print 'h', h

	# need to find length of key. To do so, need to try keys of all lengths, each time slicing out the key
	for keylen_guess in xrange(1,40):

		padded_plaintext_with_key_extension = sha1_pad('A'*keylen_guess + message) + extension_data

		len_bytes_processed = len(sha1_pad('A'*keylen_guess + message))

		forged_digest = SHA1(h, message_byte_length = len_bytes_processed).update(extension_data).digest()

		padded_plaintext_no_key = padded_plaintext_with_key_extension[keylen_guess:]

		# then, if we guessed the correct keylen_guess, we properly substring-ed out the key, and
		# the remaining substring, once appended to the key on server side, will have proper padding
		# and digest to the same thing as the forged_digest

	 	# print 'forged_message', authsha1(key, padded_plaintext_no_key)

		if validate_oracle(key, padded_plaintext_no_key, forged_digest):
			print "Found keylen_guess", keylen_guess

			# we found the correct keylen_guess
			# and we can return the valid message and valid digest of the message
			return padded_plaintext_no_key, forged_digest


extended_message, forged_digest = forgeHash(message, message_digest, ';admin=true')

print "true keylen: ", len(key)
print "This message: %s \t has a forged digest of %s. A receiver will think that we generated this digest by knowing the key." % (extended_message, forged_digest)


print '4.30 Break an MD5 keyed MAC using length extension'

# key = os.urandom(random.randint(3,40))
key = os.urandom(14)

untamp_message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
untamp_message_digest = authmd5(key, untamp_message)


def md5_pad(message):
	padding = ''

	# append the bit '1' to the message
	padding += b'\x80'

	# append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
	# is congruent to 56 (mod 64)
	padding += b'\x00' * ((56 - (len(message) + 1) % 64) % 64)

	# append length of message (before pre-processing), in bits, as 64-bit big-endian integer
	message_bit_length = len(message) * 8
	padding += struct.pack(b'<Q', message_bit_length)

	return message + padding


def validate_md5_mac(key, message, digest):
	return authmd5(key, message) == digest


def forge_hash_md5(message, message_digest, extension_data):

	md5_state_array = unpack_many(message_digest, word_size = 32, endianness='big')

	# print [hex(state) for state in md5_state_array]

	for keylen_guess in xrange(14, 15):
		# print keylen_guess
		padded_plaintext_with_key_extension = md5_pad('A'*keylen_guess + message) + extension_data

		# print padded_plaintext_with_key_extension

		len_bytes_processed = len(md5_pad('A'*keylen_guess + message))

		# print "len_bytes_processed", len_bytes_processed

		forged_digest = MD5(extension_data, message_byte_length = len_bytes_processed, state_array = md5_state_array).digest()

		padded_plaintext_no_key = padded_plaintext_with_key_extension[keylen_guess:] # this is the forged message

		# print "padded_plaintext_no_key", padded_plaintext_no_key

		if validate_md5_mac(key, padded_plaintext_no_key, forged_digest):
			# print "Found keylen_guess md5", keylen_guess

			# we found the correct keylen_guess
			# and we can return the valid message and valid digest of the message
			return padded_plaintext_no_key, forged_digest


# ext_message, forged_digest = forge_hash_md5(untamp_message, untamp_message_digest, ";admin=true")
