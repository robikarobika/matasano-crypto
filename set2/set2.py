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


print '2.9 PKCS#7 padding'

def padPKCS7(x, padto):
	diff = (padto - (len(x)%padto)) % 16

	padded = x + pack(diff, 'all')*diff

	return padded

expected = "YELLOW SUBMARINE\x04\x04\x04\x04"

assert expected == padPKCS7("YELLOW SUBMARINE", 20)



print '2.10 Implemented CBC!'

iv = '\x00\x00\x00'

key = "YELLOW SUBMARINE"

file = base64.b64decode(open('10.txt', 'r').read())

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


cipher = Cipher(algorithm = algorithms.AES("YELLOW SUBMARINE"), mode = modes.ECB(), backend=default_backend())

cbc = CBC(cipher, '\x00'*16)
song = cbc.decrypt(file)

assert cbc.encrypt(song) == file



print '2.11 CBC-ECB Encryption oracle'

def encryption_oracle(input_text):
	key = os.urandom(16)

	random_nfix = os.urandom(random.randint(5,10))
	input_text = random_nfix + input_text + random_nfix
	input_text = padPKCS7(input_text, 16)
	
	cipher = Cipher(algorithm = algorithms.AES(key), mode = modes.ECB(), backend=default_backend())

	if random.randint(1,2) == 1:
		print 'Using ECB'
		# Use AES with ECB	
		e = cipher.encryptor()
		ciphertext = e.update(input_text) + e.finalize()
		return ciphertext
	else:
		# Use AES with CBC
		print 'Using CBC'
		rand_iv = os.urandom(16)
		cbc = CBC(cipher, rand_iv)
		return cbc.encrypt(input_text)


def detect_ecb_cbc(encryption_oracle):
	s = '\x00'*100 #This needs to be at least 43 bytes (32+11) long. Why? Because we need at least 2 identical 16-byte plaintext blocks to be able to detect ECB, because those blocks will then encrypt to the same ciphertext. 
	blocksize = 16
	encrypted = encryption_oracle(s)
	blocks = [encrypted[i:i+blocksize] for i in xrange(0, len(encrypted), blocksize)]

	for i in xrange(len(blocks)-1):
		if blocks[i] == blocks[i+1]:
			# at least two adjacent identical plaintext blocks are encrypted to the same thing, so it's definitely ECB
			print "Detected ECB"
			return
	else:
		print "Detected CBC"


detect_ecb_cbc(encryption_oracle)


print '2.12 ECB decryption'

key = os.urandom(16)

def ecb_oracle_same_key(input_text):

	s =	"""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"""

	plain_text = padPKCS7(input_text + base64.b64decode(s), 16)
	
	cipher = Cipher(algorithm = algorithms.AES(key), mode = modes.ECB(), backend=default_backend())

	e = cipher.encryptor()
	ciphertext = e.update(plain_text) + e.finalize()

	return ciphertext

def find_block_size(oracle):
	# two ways to find block size
	# first is to keep increasing offset padding until ciphertext without padding is found in ciphertext of plaintext with padding - then, I know the offset required to repeat the ciphertext
	# second is to increase offset until I increase the length of the ciphertext by starting a new pad of length blocksize
	# here, 144..144....160! so difference is blocksize
	no_offset = ecb_oracle_same_key('')	
	# print 'no offset', len(no_offset)

	i = 1
	while True:
		offset = 'A'*i
		enc_text = ecb_oracle_same_key(offset)
		# print 'enc_text', len(enc_text)

		if len(no_offset) != len(enc_text):
			blocksize = len(enc_text) - len(no_offset)
			return blocksize

		i+=1

blocksize = find_block_size(ecb_oracle_same_key)
assert blocksize == 16
detect_ecb_cbc(ecb_oracle_same_key)

def find_next_byte(oracle, blocksize, knownbytes):
	offset_len = (blocksize - len(knownbytes)%blocksize - 1)

	if len(knownbytes) < blocksize:
		# if we don't yet have enough known bytes to construct the offset entirely from known bytes,
		# use filler variables
		offset = 'A'*offset_len+knownbytes
	else:
		# get last blocksize bytes of knownbytes as offset
		offset = knownbytes[-blocksize+1:]

	#len(offset) is ALWAYS 15

	candidates = string.printable
	cand_dict = {} # maps possible ciphertext blocks to printable characters
	for cand in candidates:
		# every candidate block of ciphertext is 16 bytes
		block_of_interest = oracle(offset+cand)[0:blocksize]
		cand_dict[block_of_interest] = cand


	block_num = len(knownbytes)/blocksize
	#block_num to locate where the 16-byte ciphertext of interest is
	oracle_block = oracle('A'*offset_len)[block_num*blocksize:(block_num+1)*blocksize]
	if oracle_block in cand_dict:
		next_byte = cand_dict[oracle_block]
		return next_byte
	return None


flag_bytes = ''
while len(flag_bytes) < ecb_oracle_same_key(''):
	new_byte = find_next_byte(ecb_oracle_same_key, blocksize, flag_bytes)
	if new_byte is None:
		break
	flag_bytes += new_byte

expected = """Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"""
assert flag_bytes == expected


print '2.13 ECB cut-and-paste'
# Skipped, but the point is that you encrypt the word 'admin' alone, padded with 11 zeroes, and append it to another profile string, cutting out 'user'

parse = "foo=bar&baz=qux&zap=zazzle"

def parse_profile(s):
	d = {}
	args = parse.split('&')
	for arg in args:
		d[arg.split('=')[0]] = arg.split('=')[1]	

	return d
# print json.dumps(d, indent=4)

def encode_profile(d):

	def sanitize(s):
		s = s.replace('&', '').replace('=', '')
		return s
	encoded = ""

	encoded = encoded + "email=" + sanitize(d['email']) + "&"
	encoded = encoded + "uid=" + str(d['uid']) + '&'
	encoded = encoded + 'role=' + d['role']

	return encoded

def profile_for(string):
	d = {}
	
	d['email'] = string
	d['uid'] = 10
	d['role'] = 'user'
	return encode_profile(d)

profile = profile_for('foobar@me.com')

key = os.urandom(16)

cipher = Cipher(algorithm = algorithms.AES(key), mode = modes.ECB(), backend=default_backend())
e = cipher.encryptor()


profile_padded = padPKCS7(profile, 16)

ciphertext = e.update(profile_padded) + e.finalize()
# print ciphertext



print '2.14 Byte-at-a-time ECB decryption with prefix'

rand_prefix = os.urandom(random.randint(1, 43))

def ecb_oracle_prefix(input_text):

	s =	"""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"""
	

	plain_text = padPKCS7(rand_prefix + input_text + base64.b64decode(s), 16)
	
	cipher = Cipher(algorithm = algorithms.AES(key), mode = modes.ECB(), backend=default_backend())

	e = cipher.encryptor()
	ciphertext = e.update(plain_text) + e.finalize()

	return ciphertext


def find_prefix_block_index(prefix_oracle, blocksize):
	ciphertext1 = prefix_oracle('')
	ciphertext2 = prefix_oracle('A')

	blocks1 = [ciphertext1[i:i+blocksize] for i in xrange(0, len(ciphertext1), blocksize)]
	blocks2 = [ciphertext2[i:i+blocksize] for i in xrange(0, len(ciphertext2), blocksize)]

	for i in xrange(len(blocks1)):
		if blocks1[i] != blocks2[i]:
			return i

def find_prefix_block_modulo_offset(prefix_oracle, blocksize):
	prev_len = len(prefix_oracle(''))

	for i in xrange(0, blocksize):
		offset = 'A'*i + '\x00'*32
		ciphertext = prefix_oracle(offset)
		
		blocks = [ciphertext[index:index+blocksize] for index in xrange(0, len(ciphertext), blocksize)]

		for j in xrange(len(blocks)-1):
			if blocks[j] == blocks[j+1]:
				# at least two adjacent identical plaintext blocks are encrypted to the same thing, so we've found the correct offset
				return blocksize - i

def find_next_byte_with_prefix(oracle, blocksize, knownbytes):
	prefix_location = find_prefix_block_index(ecb_oracle_prefix, blocksize)*blocksize + find_prefix_block_modulo_offset(ecb_oracle_prefix, blocksize)

	offset_len = blocksize - (len(knownbytes)%blocksize) - 1 # continue cycling offset len from 15 to 0
	extra_offset_for_prefix = blocksize - find_prefix_block_modulo_offset(ecb_oracle_prefix, blocksize)
	# I need extra_offset_for_prefix to align the actual (blocksize-1) offset on a blocksize boundary

	offset = 'A'*(extra_offset_for_prefix + offset_len)

	candidates = string.printable
	cand_dict = {} # maps possible ciphertext blocks to printable characters
	for cand in candidates:
		block_of_interest = oracle(offset + knownbytes + cand)[prefix_location: prefix_location + len(offset) + len(knownbytes) + 1]
		cand_dict[block_of_interest] = cand
		# keys are variable length blocks of ciphertext

	oracle_block = oracle(offset)[prefix_location : prefix_location + len(offset) + len(knownbytes) + 1]
	if oracle_block in cand_dict:
		next_byte = cand_dict[oracle_block]
		print 'next_byte', next_byte
		return next_byte
	return None


flag_bytes = ''
while len(flag_bytes) < ecb_oracle_prefix(''):
	new_byte = find_next_byte_with_prefix(ecb_oracle_prefix, blocksize, flag_bytes)
	if new_byte is None:
		break
	flag_bytes += new_byte


expected = """Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"""
assert flag_bytes == expected


print '2.15 Validate PKCS#7'

def validate_and_strip_PKCS7(s):
	byte = s[-1]
	byte_int = unpack(byte, 'all')
	if byte == 0 or s[-byte_int:] != byte * byte_int or byte == "":
		return False
	return True

assert validate_and_strip_PKCS7("ICE ICE BABY\x04\x04\x04\x04")
assert validate_and_strip_PKCS7("ICE ICE BABY\x05\x05\x05\x05") is False


print '2.16 CBC Bitflipping attack'

rand_key = os.urandom(16)
iv = os.urandom(16)

def add_strings_and_cbc_encrypt(input_text):
	s = "comment1=cooking%20MCs;userdata="
	s2 = ";comment2=%20like%20a%20pound%20of%20bacon"
	plaintext = s + input_text.replace(';', '%3B').replace('=', '%3D') + s2

	cipher = Cipher(algorithm = algorithms.AES(rand_key), mode = modes.ECB(), backend=default_backend())

	cbc = CBC(cipher, iv)	

	return cbc.encrypt(plaintext)


def decrypt_and_check_admin(ciphertext):
	cipher = Cipher(algorithm = algorithms.AES(rand_key), mode = modes.ECB(), backend=default_backend())

	cbc = CBC(cipher, iv)	

	return ';admin=true;' in cbc.decrypt(ciphertext)


s = 'A'*16 + '\x00admin\x00true\x00'
ciphertext = list(add_strings_and_cbc_encrypt(s))

ciphertext[32] = chr(ord(ciphertext[32]) ^ 59) # 59 is the decimal for ; http://www.nthelp.com/ascii.htm
ciphertext[38] = chr(ord(ciphertext[38]) ^ 61) # 61 is the decimal for = 
ciphertext[43] = chr(ord(ciphertext[43]) ^ 59)

ciphertext = ''.join(ciphertext)

assert decrypt_and_check_admin(ciphertext)


print '3.17 CBC Padding oracle holy shit fuck'
	

string_set = {"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"}

s = base64.b64decode(random.sample(string_set, 1)[0])
# s  = base64.b64decode("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93")

rand_key = os.urandom(16)
iv = os.urandom(16)

def encrypt_random(input_text):
	cipher = Cipher(algorithm = algorithms.AES(rand_key), mode = modes.ECB(), backend=default_backend())
	cbc = CBC(cipher, iv)

	padded = padPKCS7(input_text, 16)

	return cbc.encrypt(padded)

def padding_oracle(ciphertext):
	cipher = Cipher(algorithm = algorithms.AES(rand_key), mode = modes.ECB(), backend=default_backend())
	cbc = CBC(cipher, iv)

	decrypted = cbc.decrypt(ciphertext)

	if validate_and_strip_PKCS7(decrypted) is False:
		# if not valid padding
		return False
	return True


def padding_oracle_attack(padding_oracle, ciphertext, blocksize):
	blocks = [ciphertext[i:i+blocksize] for i in xrange(0, len(ciphertext), blocksize)]

	flag_str = ""

	for i in range(0, len(ciphertext), blocksize):
		ciphertext_piece = ciphertext if i == 0 else ciphertext[:-i]
		block_bytes = decipher_block(ciphertext_piece, 16)
		flag_str = block_bytes + flag_str
	return flag_str

def decipher_block(ciphertext, blocksize):
	
	blockstr = ""
	for j in xrange(blocksize):
		char = decipher_block_previous_byte(ciphertext, blockstr, 16)
		blockstr = char + blockstr

	return blockstr

def decipher_block_previous_byte(ciphertext, known_last_bytes, blocksize):
	num_padding_byte = len(known_last_bytes) + 1
	# print 'num_padding_byte', num_padding_byte

	offset_pad = 'A'* (blocksize - num_padding_byte)
	
	prev_block = ciphertext[-32:-16] if len(ciphertext) > 16 else iv
	for cand_ord in xrange(0, 256):
		# tricky xors here
		# test all possible plaintext characters by xor-ing with padding num and previous block's ciphertext char, seeing if I xor out the correct plaintext char and get the padding num
		# fill in valid padding by xor-ing out known bytes and replacing with padding bytes
		pad_str = offset_pad + xor(prev_block[-num_padding_byte], cand_ord, num_padding_byte)
		pad_str = pad_str + xor(prev_block[-num_padding_byte+1:], known_last_bytes, num_padding_byte) if len(known_last_bytes) > 0 else pad_str
		assert len(pad_str) == blocksize
		new_ciphertext = ciphertext[:-32] + pad_str + ciphertext[-16:]

		if padding_oracle(new_ciphertext):
			return chr(cand_ord)


encrypted = encrypt_random(s)
# print padding_oracle_attack(padding_oracle, encrypted, 16)

print padding_oracle_attack(padding_oracle, encrypted, 16)

