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


print '3.18, implemented CTR mode'

s = base64.b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")

cipher = Cipher(algorithm = algorithms.AES("YELLOW SUBMARINE"), mode = modes.ECB(), backend=default_backend())
ctr = CTR(cipher, 0)

assert ctr.decrypt(s) == "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "

print '3.19, break fixed-nonce CTR'

rand_key = os.urandom(16)
key = b'\xa3\xc9\xe7\xedmZU\x1e\xac\x15\xe2\xaf\xb4$\xa9{'


file_lines = base64.b64decode(open('19.txt', 'r').read())

def ctr_fixed_nonce(s):
	return CTR(Cipher(algorithm = algorithms.AES(rand_key), mode = modes.ECB(), backend=default_backend()), 0).encrypt(s)

encrypted_texts = [ctr_fixed_nonce(l) for l in file_lines.split('\n')]

block_list = it.izip_longest(*encrypted_texts, fillvalue='0')



print '3.20, break fixed-nonce CTR statistically'


file_lines = open('20.txt', 'rb').read()

encrypted_texts = [ctr_fixed_nonce(base64.b64decode(l)) for l in file_lines.split('\n')][:-1]

# min_length = len(min(encrypted_texts, key=len))
# truncated_encrypted_texts = [text[:min_length] for text in encrypted_texts]
#
# # print 'truncated_encrypted_texts encrypted_texts', truncated_encrypted_texts

max_length = len(max(encrypted_texts, key=len))
print max_length

padded_encrypted_texts = [text.ljust(max_length, '\x00') for text in encrypted_texts]

# print "".join(padded_encrypted_texts)

keystream = breakRepeatingXor("".join(padded_encrypted_texts), max_length)
print "KEYSTREAM", repr(keystream)

# for i, msg in enumerate(encrypted_texts):
# 	print i, xor(msg, keystream)


print '3.21, Mersenne Twister algo'

mt = MT19937(5489)
assert mt.get_number() == 3499211612


print '3.21, Crack MT seed'


def random_wait():
	time.sleep(random.randint(40, 1000))

	mt = MT19937(int(time.time()))

	time.sleep(random.randint(40, 1000))

	return mt.get_number()



def getBit(value, index):
	# return bit [index] of value, index counted from left, most significant bit

	return value >> (31-index) & 1 if index >= 0 and index <= 31 else 0

def setBit(value, index, new_bit):
	# set bit [index] of value to be new_bit, index counted from left
	return value | (new_bit << (31 - index))


def unRightShiftXor(binary_str, shift):
	orig_bits = 0

	for i in xrange(32):
		# get bit at index i of orig_bits
		output_bit = getBit(binary_str, i)

		# undo the xor with the shifted original bitstring at that index
		# (i - shift) index of binary_str essentially undoes the shift operation by grabbing the correct bit from the unmodified, original bit_str
		# NOT the shifted and xor'd binary_str, but rather orig_bits as it's being reconstructed
		# if I use binary_str, will not work if the shift is <16, because after [shift] bits I'd be xor-ing with modified bits,
		# not the original bits
		recovered_bit = output_bit ^ getBit(orig_bits, i - shift)

		# set the bit at index i in the orig_bits to be the recovered bit
		orig_bits = setBit(orig_bits, i, recovered_bit)

	return orig_bits

def unLeftShiftXorAnd(binary_str, shift, and_val):

	orig_bits = 0

	for i in reversed(xrange(32)):
		# have to build from the right side because I need to grab bits from the right side of the original as it's being reconstructed
		# get bit at index i of orig_bits
		output_bit = getBit(binary_str, i)

		# undo the xor with the shifted original bitstring at that index
		# undo_xor_bit needs to be modified before I can xor it. we have to apply the mask. We're not reversing the &, just applying it
		# I can then xor to recover the original bit
		# again, I need orig_bits here, not binary_str
		undo_xor_bit = getBit(orig_bits, i + shift) & getBit(and_val, i)
		recovered_bit = output_bit ^ undo_xor_bit

		# set the bit at index i in the orig_bits to be the recovered bit
		orig_bits = setBit(orig_bits, i, recovered_bit)

	return orig_bits

def untemper(val):
	val = unRightShiftXor(val, 18)
	# print ('1', val)
	val = unLeftShiftXorAnd(val, 15, 4022730752)
	# print ('2', val)
	val = unLeftShiftXorAnd(val, 7, 2636928640)
	# print ('3', val)
	val = unRightShiftXor(val, 11)
	# print ('4', val)
	return val

# print 'untempered', (bin(untemper(2006116153)))
# print 'untempered', (bin(unRightShiftXor(0b10110111010111110001000011001110, 15)))

print '3.22, Clone and predict MT RNG by untempering'

seed = 1
mt = MT19937(seed)

cloned_mt_state = [0]*624

for i in xrange(624):
	rand = mt.get_number()
	cloned_mt_state[i] = untemper(rand)

cloned_mt = MT19937(0)
cloned_mt.state = cloned_mt_state

assert cloned_mt.state == mt.state

for i in xrange(1000):
	expected = mt.get_number()
	cloned = cloned_mt.get_number()

	assert expected == cloned

print '3.22, Breaking MT Stream Cipher'


rand_seed = unpack(os.urandom(2), 'all')

def MToracle(plaintext):
	# rand_prefix = os.urandom(random.randint(2, 40))
	rand_prefix = 'RRR'
	return MT19937Cipher(rand_seed).encrypt(rand_prefix + plaintext)

def break_mt_oracle(oracle):
	# first, as always, find prefix length
	plaintext = 'A'*14

	oracle_ciphertext = MToracle(plaintext)

	prefix_len = len(oracle_ciphertext) - len(plaintext)
	print prefix_len

	for i in xrange(2**16):
		# A's padded to length of oracle ciphertext so that we get the exact same blockstream encrypting
		# the 'A's past prefix_len. I missed this, thought I only needed 14 'A's when I actually needed 14 + prefix_len
		padded = 'A' * len(oracle_ciphertext)
		if MT19937Cipher(i).encrypt(padded)[prefix_len:] == oracle_ciphertext[prefix_len:]:
			return i


found_key = break_mt_oracle(MToracle)

print 'rand seed',rand_seed
print 'found key', found_key

assert rand_seed == found_key
