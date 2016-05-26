import binascii 
import base64
from pwn import *
import itertools as it
from pprint import *
import operator as op
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import os
import random
import json


class CBC():

	def __init__(self, cipher, iv):
		self.cipher = cipher
		self.iv = iv
		self.blocksize = 16


	def encrypt(self, plaintext):
		e = self.cipher.encryptor()

		# plaintext = padPKCS7(plaintext, 16)

		blocks = [plaintext[i:i+self.blocksize] for i in xrange(0, len(plaintext), self.blocksize)]

		prev_xor_block = self.iv
		ciphertext = ""
		for i in xrange(0, len(blocks)):
			pre_aes_block = xor(blocks[i], prev_xor_block)

			current_cipher_block = e.update(pre_aes_block)
			prev_xor_block = current_cipher_block
			ciphertext += current_cipher_block

		return ciphertext

	def decrypt(self, ciphertext):
		plaintext = ""
		d = self.cipher.decryptor()
		blocks = [ciphertext[i:i+self.blocksize] for i in xrange(0, len(ciphertext), self.blocksize)]

		decrypted_block = d.update(blocks[0])
		plaintext += xor(decrypted_block, self.iv)

		for i in xrange(1, len(blocks)):
			decrypted_block = d.update(blocks[i])
			# print decrypted_block

			plaintext += xor(decrypted_block, blocks[i-1])

		return plaintext
