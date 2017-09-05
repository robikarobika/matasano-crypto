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


class CTR():

	def __init__(self, cipher, nonce):
		self.cipher = cipher
		self.nonce = nonce
		self.counter = 0
		self.carry_over_bytes = ''

	def decrypt(self, ciphertext):
		return self.encrypt(ciphertext)

	def encrypt(self, plaintext):
		e = self.cipher.encryptor()

		if len(plaintext) == 0:
			return ''

		keystream = self.carry_over_bytes
		while len(keystream) < len(plaintext):
			keyblock = e.update(p64(self.nonce) + p64(self.counter))
			keystream += keyblock
			self.counter += 1

		if len(keystream) > len(plaintext):
			self.carry_over_bytes = keystream[len(plaintext):]
			keystream = keystream[:len(plaintext)]

		return xor(plaintext, keystream)

class MT19937():
	def int32(self, val):
		return val & 0xffffffff

	def __init__(self, seed):
		self.state = [0]*624
		self.seed = self.int32(seed)
		self.index = 0

		f = 1812433253

		self.state[0] = seed
		for i in xrange(1, 624):
			self.state[i] =  self.int32(f * (self.state[i-1] ^ (self.state[i-1] >> 30)) + i)

	def get_number(self):
		if self.index == 0:
			self.twist()

		temp = self.state[self.index]

		temp ^= (temp >> 11)
		temp ^= (temp << 7) & 2636928640
		temp ^= (temp << 15) & 4022730752
		temp ^= (temp >> 18)

		self.index = (self.index+1) % 624

		return temp

	def twist(self):
		for i in xrange(624):
			y = (self.state[i] & 0x80000000) + (self.state[(i+1) % 624] & 0x7fffffff)

			self.state[i] = self.state[(i+397) % 624] ^ (y>>1)

			if y % 2 != 0:
				# if odd, xor with another magic number
				self.state[i] ^= 0x9908b0df


class MT19937Cipher():

	def __init__(self, seed):
		self.seed = seed
		self.mt = MT19937(seed)
		self.carry_over_bytes = ''

	def decrypt(self, ciphertext):
		return self.encrypt(ciphertext)

	def encrypt(self, plaintext):
		if len(plaintext) == 0:
			return ''

		keystream = self.carry_over_bytes
		while len(keystream) < len(plaintext):
			keyblock = pack(self.mt.get_number(), 'all')
			keystream += keyblock

		if len(keystream) > len(plaintext):
			self.carry_over_bytes = keystream[len(plaintext):]
			keystream = keystream[:len(plaintext)]

		return xor(plaintext, keystream)
