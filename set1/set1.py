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
import sys
sys.path.append('..')
from set1_utils import character_frequency, find_singlechar_key_xor, breakRepeatingXor


def hextobase64(s):
	s = s.decode("hex") #same as a2b_hex, same as unhexlify
	return binascii.b2a_base64(s).rstrip("\n")

# Multiple ways : one requires se be a byte string, with b in front
s = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

# print binascii.b2a_base64(binascii.unhexlify(s))

# Other way
s = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
 
expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

print "1.1 hex to base64"
assert hextobase64(s) == expected


def fixed_xor(s1, s2):
	s1 = s1.decode("hex")
	s2 = s2.decode("hex")
	return ''.join([chr(ord(i)^ord(j)) for i, j in zip(s1, s2)])


inp1 = "686974207468652062756c6c277320657965"
inp2 = "1c0111001f010100061a024b53535009181c"
expected =  "746865206b696420646f6e277420706c6179" 

# print inp2.decode("hex") #decode and unhexlify do the same thing
# print binascii.unhexlify(inp2)


# print 'fixed_xor', fixed_xor(inp1, inp2)
res = fixed_xor(inp1, inp2)
# print 'res', res
res = binascii.hexlify(res)
# print 'res', res

print "1.2 Fixed xor!"
assert res == expected, "1.2 Fixed xor!"


def fixed_xor_any_len(s1, s2):
	s1 = s1.decode("hex")
	s2 = s2.decode('hex')

	return ''.join([chr(ord(i)^ord(j)) for i, j in it.izip(s1, it.cycle(s2))])


msg = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

# def find_singlechar_key_xor(msg):
# 	#takes in a byte string msg
# 	candidate_keys = string.printable

# 	cand_words = []

# 	for char in candidate_keys:
# 		result = xor(msg, char)
# 		word_score = 0

# 		for c in result:
# 			c = c.lower()
# 			if c in character_frequency:
# 				word_score += character_frequency[c]

# 		cand_words.append((result, word_score, char))

# 	max_tuple = max(cand_words, key=op.itemgetter(1))
# 	print max_tuple

# 	return max_tuple

print "1.3 Single char fixed xor"
assert find_singlechar_key_xor(binascii.unhexlify(msg))[0] == "Cooking MC's like a pound of bacon"



print "1.4 Single char fixed xor on 4.txt"

# lines = open('4.txt', 'r').read()

# words = []
# for line in lines.split("\n"):
# 	line_xor_char = find_singlechar_key_xor(binascii.unhexlify(line))
# 	words.append(line_xor_char)

# max_tuple = max(words, key=op.itemgetter(1))	
# assert max_tuple[0] == 'Now that the party is jumping\n'


text = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""

expected = """0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"""

print '1.5 Repeated xor'
assert binascii.hexlify(xor(text, 'ICE')) == expected

def hamming(str1, str2):
	str1 = bits_str(str1)
	str2 = bits_str(str2)
	return sum(c1 != c2 for c1, c2 in it.izip(str1, str2))

# print hamming('this is a test', 'wokka wokka!!!')


def find_key_length(x):
	key_dists = []

	#find keysize that creates blocks with minimum hamming distance 
	for keysize in range(2, 41):
		blocks = [x[i:i+keysize] for i in range(0, len(x), keysize)][0:4]
		pairs = list(it.combinations(blocks, 2))
		hamsum = it.starmap(hamming, pairs)
		normalized = float(reduce(lambda x, y: x+y, hamsum))/keysize
		key_dists.append((keysize, normalized))
		# hamming = 
	# hamming()

	#to do this in pwnlib, 

	return min(key_dists, key=op.itemgetter(1))[0]

# def breakRepeatingXor(x, keysize):
# 	blocks = [x[i:i+keysize] for i in range(0, len(x), keysize)]
# 	print list(blocks)

# 	blocks = it.izip_longest(*blocks, fillvalue='0')
# 	# print list(blocks)

# 	block_list = [''.join(msg) for msg in blocks]
# 	print block_list
# 	# block_list contains the 1st, 2nd, etc... chars of each block of length keysize, grouped together

# 	char_freqs = [find_singlechar_key_xor(''.join(msg))[2] for msg in block_list]
# 	return ''.join(char_freqs)

print '1.6 Vigenere cipher break repeating xor'
x = base64.b64decode(open('6.txt', 'r').read())
keylen = find_key_length(x)
assert keylen == 29

key = breakRepeatingXor(x, keylen)
assert key == 'Terminator X: Bring the noise'


print "1.7 AES in ECB mode"

file = base64.b64decode(open('7.txt', 'r').read())

cipher = Cipher(algorithm = algorithms.AES("YELLOW SUBMARINE"), mode = modes.ECB(), backend=default_backend())
d = cipher.decryptor()

decrypted_text = d.update(file) + d.finalize()
# print decrypted_text

print "1.8 Detect AES in ECB mode"

file = open('8.txt', 'r').read()

lines = file.split("\n")

lines = [(i+1, binascii.unhexlify(l)) for i, l in enumerate(lines)]

def hamming_score_line(line):
	blocks = [line[1][i:i+16] for i in range(0, len(x), 16)][0:4]

	#-------------this version calculates the hamming distances between some number of blocks
	pairs = list(it.combinations(blocks, 2))
	hamsums = it.starmap(hamming, pairs)
	hamsum = float(reduce(lambda x, y: x+y, hamsums))
	return hamsum

	#---------------this version simply counts the number of blocks that equal other blocks
	# same = 0
	# count = 0
	# for p in pairs:
	# 	if p[0] == p[1]:
	# 		same += 1
	# return same

	
# sorted_list = sorted(lines, key=hamming_score_line)
# print [line[0] for line in sorted_list]

min_line_num = min(lines, key=hamming_score_line)[0]
assert min_line_num == 133


