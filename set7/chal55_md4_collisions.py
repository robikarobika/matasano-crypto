# -*- coding: utf-8 -*-

import binascii
import base64
import itertools as it
from pprint import *
import operator as op
import os
import random
import struct
import sys

sys.path.append("..")
from MD4 import *

'''
Let's define some utility functions to massage the message
For the first round, we want these conditions to hold:

a1 a1[6] = b0[6]
d1 d1[6] = 0, d1[7] = a1[7], d1[10] = a1[10]
c1 c1[6] = 1, c1[7] = 1, c1[10] = 0, c1[25] = d1[25]
b1 b1[6] = 1, b1[7] = 0, b1[10] = 0, b1[25] = 0
'''

MASK_32 = 0xffffffff

lrot = lambda x, n: (x << n) & MASK_32 | (x >> (32 - n))
rrot = lambda x, n: (x >> n) | (x << (32 - n)) & MASK_32

assert lrot(0xffffffff, 2) == 0xffffffff
assert rrot(0xffffffff, 2) == 0xffffffff

def getBit(value, index):
    # return bit [index] of value, index zero-indexed from right, least significant bit

    return value >> index & 1 if index >= 0 and index <= 31 else 0

def setBit(value, index, new_bit):
    # set bit [index] of value to be new_bit, index zero-indexed from right, least significant bit
    return (value & ~(1 << index)) | (new_bit << index)


def F(x,y,z):
    return (x&y) | ((~x) & z)

def G(x,y,z):
    return (x&y) | (x&z) | (y&z)

msg = b'\x00'*64
X = list(struct.unpack("<16I", msg))
X_copy = X
print(X)


_round1 = [
    [0,1,2,3, 0,3],
    [3,0,1,2, 1,7],
    [2,3,0,1, 2,11],
    [1,2,3,0, 3,19],

    [0,1,2,3, 4,3],
    [3,0,1,2, 5,7],
    [2,3,0,1, 6,11],
    [1,2,3,0, 7,19],

    [0,1,2,3, 8,3],
    [3,0,1,2, 9,7],
    [2,3,0,1, 10,11],
    [1,2,3,0, 11,19],

    [0,1,2,3, 12,3],
    [3,0,1,2, 13,7],
    [2,3,0,1, 14,11],
    [1,2,3,0, 15,19],
]

# a, b, c, d = [0]*10, [0]*10, [0]*10, [0]*10
a = [0x67452301]
b = [0xefcdab89]
c = [0x98badcfe]
d = [0x10325476]
# a = [0x00000001]
# b = [0x00000001]
# c = [0x00000001]
# d = [0x00000001]

states = [a, b, c, d]


letterMap = {"a": 0, "b": 1, "c": 2, "d": 3}
constraints = [
    {6: "b"},
    {6: 0, 7: "a", 10: "a"},
    {6: 1, 7: 1, 10: 0, 25: "d"},
    {6: 1, 7: 0, 10: 0, 25: 0},
    {7:1, 10: 1, 25: 0, 13: "b"},
    {13: 0, 18: "a", 19: "a", 20: "a", 21: "a", 25: 1},
    {12: "d", 13: 0, 14: "d", 18: 0, 19: 0, 20: 1, 21: 0},
    # b2
    {12: 1, 13:1, 14: 0, 16: "c", 18: 0, 19: 0, 20: 0, 21:0 },
    # a3
    {12: 1, 13: 1, 14: 1, 16: 0, 18: 0, 19: 0, 20: 0, 21: 1, 25: "b", 22: "b"},
    {12: 1, 13: 1, 14: 1, 16: 0, 19:0, 20: 1, 21: 1, 22:0, 25: 1, 29: "a"},
    {16: 1, 19: 0, 20:0, 21: 0, 22:0, 25: 0, 29: 1, 31: "d"},
    {19: 0, 20: 1, 21: 1, 22: "c", 25: 1, 29: 0, 31: 0},
    {22: 0, 25: 0, 26: "b", 28: "b", 29: 1, 31: 0},
    {22:0, 25:0, 26: 1, 28: 1, 29: 0, 31: 1},
    {18: "d", 22: 1, 25: 1, 26:0, 28: 0, 29:0},
    {18:0, 25: 1, 26: 1, 28: 1, 29: 0}
]

def get_new_state(round_idx):
    global states
    i1, i2, i3, i4, k, s = _round1[round_idx]

    new_state = lrot(states[i1][-1] + F(states[i2][-1], states[i3][-1], states[i4][-1]) + X[k], s)

    states[i1].append(new_state)
    return new_state

def solve_for_msg(X, round_idx):
    i1, i2, i3, i4, k, s = _round1[round_idx]

    print(rrot(states[i1][-1], s))
    print(states[i1][-2])
    print(F(states[i2][-1], states[i3][-1], states[i4][-1]))
    X[k] = (rrot(states[i1][-1], s) - states[i1][-2] - F(states[i2][-1], states[i3][-1], states[i4][-1])) % (1 << 32)


def set_constraints(round_idx, new_state):
    constraints_dict = constraints[round_idx]
    for bit in constraints_dict:
        if constraints_dict[bit] is 0 or constraints_dict[bit] is 1:
            new_state = setBit(new_state, bit, constraints_dict[bit])
        else: 
            state_idx = letterMap[constraints_dict[bit]]
            new_state = setBit(new_state, bit, getBit(states[state_idx][-1], bit))

    return new_state

# round_idx = 2
# i1, i2, i3, i4, k, s = _round1[round_idx]
# new_state = get_new_state(round_idx)
# states[i1][-1] = set_constraints(round_idx, new_state)
# solve_for_msg(X_copy, round_idx)

# Solve for message again


for round_idx in range(16):
    # round_idx = 0
    print(round_idx)
    i1, i2, i3, i4, k, s = _round1[round_idx]
    new_state = get_new_state(round_idx)
    states[i1][-1] = set_constraints(round_idx, new_state)
    solve_for_msg(X_copy, round_idx)
    print("new msg", [bin(b) for b in X_copy])
    print()


# Solve for message again

print("new msg", [b for b in X_copy])





