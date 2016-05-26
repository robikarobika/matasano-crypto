import binascii 
import base64
import Crypto
from pwn import *
import itertools as it
from pprint import *
import operator as op
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import os

character_frequency = {
	'a': 0.0651738,
	'b': 0.0124248,
	'c': 0.0217339,
	'd': 0.0349835,
	'e': 0.1041442,
	'f': 0.0197881,
	'g': 0.0158610,
	'h': 0.0492888,
	'i': 0.0558094,
	'j': 0.0009033,
	'k': 0.0050529,
	'l': 0.0331490,
	'm': 0.0202124,
	'n': 0.0564513,
	'o': 0.0596302,
	'p': 0.0137645,
	'q': 0.0008606,
	'r': 0.0497563,
	's': 0.0515760,
	't': 0.0729357,
	'u': 0.0225134,
	'v': 0.0082903,
	'w': 0.0171272,
	'x': 0.0013692,
	'y': 0.0145984,
	'z': 0.0007836,
	' ': 0.1918182
}

def find_singlechar_key_xor(msg):
	""" takes in a byte string msg 
		returns a tuple (result, word_score, char)
	
	"""
	candidate_keys = [chr(i) for i in xrange(0, 256)]

	cand_words = []

	for char in candidate_keys:
		result = xor(msg, char)
		word_score = 0

		for c in result:
			c = c.lower()
			if c in character_frequency:
				word_score += character_frequency[c]

		cand_words.append((result, word_score, char))

	max_tuple = max(cand_words, key=op.itemgetter(1))

	return max_tuple

def breakRepeatingXor(x, keysize):
	blocks = [x[i:i+keysize] for i in range(0, len(x), keysize)]

	# blocks = it.izip_longest(*blocks, fillvalue='0')
	blocks = it.izip(*blocks)
	# print list(blocks)

	block_list = [''.join(msg) for msg in blocks]
	# block_list contains the 1st, 2nd, etc... chars of each block of length keysize, grouped together

	char_freqs = [find_singlechar_key_xor(''.join(msg))[2] for msg in block_list]
	return ''.join(char_freqs)


	
