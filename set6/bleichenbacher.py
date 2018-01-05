#! /usr/local/bin/python3

import sys
sys.path.append("..")
from set5_utils import *

print("6.47 Bleichenbacher's padding oracle")

pk, sk = rsa_keygen(128)
e = pk[0]
n = pk[1]
d = sk[0]
block_size = 32

B = pow(2, 256 - 16)
B2, B3 = 2 * B, 3 * B


def pkcs_oracle(enc_num):
	dec_num = pow(enc_num, d, n)
	dec = dec_num.to_bytes(block_size, byteorder="big")
	return dec.startswith(b"\x00\x02")


def pkcs1_5_pad(msg, blksize):
	assert blksize - len(msg) > 11
	padded = b"\x00\x02"
	padding = os.urandom(blksize - len(msg) - 3)
	# padded += b'A' * (blksize - len(msg) - 3)
	while b'\x00' in padding:
		padding = os.urandom(blksize - len(msg) - 3)
	padded += padding
	padded += b"\x00"
	padded += msg

	assert len(padded) == blksize
	return padded

def pkcs1_5_unpad(plaintext):
  index = plaintext.index(b'\x00', 1)
  return plaintext[index + 1 :]

def mult_mod(c, s):
	return (c * pow(s, e, n)) % n

def ceil_div(a, b):
	x = a // b
	if b * x < a:
		return x + 1
	return x

def start_search(enc_num):
	si = ceil_div(n, B3)
	while True:
		if pkcs_oracle(mult_mod(enc_num, si)):
			return si
		si += 1

# Step 3
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
				print("Step 2c one interval left, si", si)
				return si
		ri += 1


def narrow_intervals(old_interval, si):
	m_intervals = []
	# for a, b in m_intervals:
	a, b = old_interval

	startr = ceil_div(a * si - B3 + 1, n)
	endr = (b * si - B2) // n
	print("startr", startr, "endr", endr)

	for r in range(startr, endr + 1):
		m_intervals.append((max(a, ceil_div(B2 + r * n, si)),
							min(b, (B3 - 1 + r * n) // si)))

	print("m_intervals", len(m_intervals))
	return m_intervals


def check_intervals(m_intervals):
	# If M contains only one interval of length 1
	if len(m_intervals) == 1:
		if m_intervals[0][0] == m_intervals[0][1]:
			# We're done!
			a = m_intervals[0][0]
			m = a * modinv(n, 1)
			return m
		else:
			print("Diff interval", m_intervals[0][1] - m_intervals[0][0])
			return False

def bleichenbacher_attack(enc_msg):
	# Step 1
	new_si = start_search(enc_msg)
	print("new_si", new_si)

	# Step 2
	first_interval = (B2, B3 - 1)
	intervals = narrow_intervals(first_interval, new_si)
	assert len(intervals) == 1
	found_msg = check_intervals(intervals)

	while not found_msg:
		if len(intervals) == 1:
			new_si = search_one_interval(enc_num, intervals[0], new_si)
			intervals = narrow_intervals(intervals[0], new_si)
			assert len(intervals) == 1
			found_msg = check_intervals(intervals)

	return found_msg


# Step 1
msg = b"kick it, CC"
pad_num = int.from_bytes(pkcs1_5_pad(msg, block_size), byteorder='big')
enc_num = pow(pad_num, e, n)
assert pkcs_oracle(enc_num)

found_msg = bleichenbacher_attack(enc_num)

found_msg = pkcs1_5_unpad(found_msg.to_bytes(block_size, byteorder="big"))
print("found_msg", found_msg)
assert found_msg == msg
