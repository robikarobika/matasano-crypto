#! /usr/local/bin/python3

import sys
sys.path.append("..")
from set5_utils import *

print("6.48 Bleichenbacher's padding oracle complete")

KEYSIZE = 768
k = KEYSIZE // 8

pk, sk = rsa_keygen(KEYSIZE)
e = pk[0]
n = pk[1]
print ("e", e, "n", n)

d = sk[0]
print ("d", d)
block_size = 32

B = pow(2, 8*(k-2))
B2, B3 = 2 * B, 3 * B

def int_to_bytes(n):
  byte_length = math.ceil(n.bit_length() / 8.0)
  return n.to_bytes(byte_length, 'big')

def pkcs_oracle(enc_num):
	dec_num = pow(enc_num, d, n)
	dec = int_to_bytes(dec_num)
	return dec.startswith(b"\x02") and len(dec) == k-1

def pkcs1_5_pad(msg):
	assert k - len(msg) > 11
	padded = b"\x00\x02"
	padding = os.urandom(k - len(msg) - 3)
	# padded += b'A' * (k - len(msg) - 3)
	while b'\x00' in padding:
		padding = os.urandom(k - len(msg) - 3)
	padded += padding
	padded += b"\x00"
	padded += msg

	assert len(padded) == k
	return padded

def pkcs1_5_unpad(plaintext):
  index = plaintext.index(b'\x00', 1)
  return plaintext[index + 1 :]

# returns ceil(a/b)

mult_mod_ct = 0

def mult_mod(c, s):
	# global mult_mod_ct
	# mult_mod_ct += 1
	# if mult_mod_ct%1000 == 0:
	# 	print("mult_mod_ct", mult_mod_ct)
	return (c * pow(s, e, n)) % n


def ceil_div(a, b):
	x = a // b
	if b * x < a:
		return x + 1
	return x

# Step 2a
def start_search(enc_num):
	si = ceil_div(n, B3)

	while True:
		if si%1000 == 0:
			print("si", si)
		if pkcs_oracle(mult_mod(enc_num, si)):
			return si
		si += 1

# Step 2b
def search_morethanone_interval(enc_num, si):
	snew = si + 1
	while True:
		if pkcs_oracle(mult_mod(enc_num, snew)):
			return snew
	snew += 1

# Step 2c
def search_one_interval(enc_num, m, si):
	a, b = m
	ris = 2*ceil_div((b * si - B2), n)

	ri = ris
	while True:
		starts = ceil_div(B2 + ri * n, b)
		# This ends 
		ends = ceil_div((B3 + ri * n), a)

		if starts >= ends:
			ri += 1
			continue

		for si in range(starts, ends):
			if pkcs_oracle(mult_mod(enc_num, si)):
				print("search one interval")
				return si
		ri += 1

# Step 3
# 
def narrow_intervals(old_intervals, si):
	m_intervals = []
	for (a, b) in old_intervals:
		startr = ceil_div(a * si - B3 + 1, n)
		endr = (b * si - B2) // n
		print("startr endr diff", endr - startr)

		for r in range(startr, endr + 1):
			new_left = max(a, ceil_div(B2 + r * n, si))
			new_right = min(b, (B3 - 1 + r * n) // si)

			if new_left <= new_right:
				m_intervals.append((new_left, new_right))

	print("m_intervals", len(m_intervals))
	return m_intervals

# Step 4
def check_intervals(m_intervals):
	# If M contains only one interval of length 1
	if len(m_intervals) == 1 and m_intervals[0][0] == m_intervals[0][1]:
			# We're done!
			a = m_intervals[0][0]
			m = a * modinv(n, 1)
			return m
	else:
		print("Diff interval", m_intervals[0][1] - m_intervals[0][0])
		return False

def bleichenbacher_attack(enc_msg):
	# Step 1 - this is the longest step
	new_si = start_search(enc_msg)
	print("new_si", new_si)
	assert pkcs_oracle(mult_mod(enc_num, new_si))

	first_interval = [(B2, B3 - 1)]
	intervals = narrow_intervals(first_interval, new_si)
	found_msg = check_intervals(intervals)

	while not found_msg:
		if len(intervals) == 1:
			new_si = search_one_interval(enc_num, intervals[0], new_si)
			intervals = narrow_intervals(intervals, new_si)
			assert len(intervals) == 1
			found_msg = check_intervals(intervals)
		elif len(intervals) > 1: 
			# There's more than one interval left
			new_si = search_morethanone_interval(enc_num, new_si)
			intervals = narrow_intervals(intervals, new_si)
			found_msg = check_intervals(intervals)
		else: 
			exit("intervals are empty")

	return found_msg

# Step 1
msg = b"kick it, CC"
pad_num = int.from_bytes(pkcs1_5_pad(msg), byteorder='big')
enc_num = pow(pad_num, e, n)
assert pkcs_oracle(enc_num)

found_msg = bleichenbacher_attack(enc_num)

found_msg = pkcs1_5_unpad(int_to_bytes(found_msg))
print("found_msg", found_msg)
assert found_msg == msg
