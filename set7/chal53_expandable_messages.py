# -*- coding: utf-8 -*-

import IPython
import binascii
import base64
import itertools as it
from pprint import *
import operator as op
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import os
import random
import zlib
import multiprocessing as mp
from Crypto.Cipher import *
import struct

import sys
sys.path.append('..')

message_byte_length = 8
def MD_padding(message, msg_len):
    # append the byte '1' to the message
    message += b'\x80'

    # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
    # is congruent to 56 (mod message_byte_length)
    message += b'\x00' * ((-4 - len(message) % message_byte_length) % message_byte_length)

    # append length of message (before pre-processing), in bits, as message_byte_length-bit big-endian integer
    message += struct.pack(b'>I', msg_len)

    assert len(message) % message_byte_length == 0

    return message

def blowfish_weak_hash(block, init_state):
    cipher = Blowfish.new(init_state, Blowfish.MODE_ECB)

    # Drop bits to keep state at length hash_length
    new_state = cipher.encrypt(block)[:hash_length]
    return new_state


hash_length = 2
def iterated_hash(msg, init_state, cipher_f, block_len, padding = False):
    # Fuck the padding — just makes things more complicated.
    
    if padding:
        padded_msg = MD_padding(msg, len(msg))
    else:
        padded_msg = msg

    if len(init_state) < hash_length:
        # Pad initial state on the way in 
        init_state = init_state + (b'\x00' * (hash_length - len(init_state)))
    else:
        # Drop bits if necessary
        init_state = init_state[:hash_length]

    for block in [padded_msg[x:x+block_len] for x in range(0, len(padded_msg), block_len)]:
        init_state = cipher_f(block, init_state)

    return init_state


print("Challenge 53 Kelsey and Schneier's Expandable Messages")


def find_collision(k, hash_state):
    single_block = b'\x01'*8
    target_hash = iterated_hash(single_block, hash_state, blowfish_weak_hash, message_byte_length)

    print("target hash", repr(target_hash))
    dummy_blocks = (b'\x01'*8) * 2**(k-1)
    dummy_blocks_hash = iterated_hash(dummy_blocks, hash_state, blowfish_weak_hash, message_byte_length)

    print("many block hash", repr(dummy_blocks_hash))

    for msg in (num.to_bytes(8, byteorder="little") for num in range(2**(message_byte_length*8))):
        # print(msg)
        new_hash = iterated_hash(msg, dummy_blocks_hash, blowfish_weak_hash, message_byte_length)

        if new_hash == target_hash:
            print("Found collisions with 2^(%s-1) + 1" % str(k))
            return single_block, dummy_blocks+ msg, target_hash


    # iterated_hash(single_block)

def gen_expandable(k):
    fragments = []
    output_state = init_state
    for i in range(k, 0, -1):
        single_block, many_block, output_state = find_collision(i, output_state)
        fragments.append((single_block, many_block, output_state))

    return output_state, fragments

def get_intermed_states(msg, init_state, cipher_f):
    intmed_states = []
    intmed_state = init_state
    print(len(msg))
    # for block in [msg[x:x+message_byte_length] for x in range(0, len(msg), message_byte_length)]:
    for block in [msg[x*message_byte_length : x*message_byte_length + message_byte_length] for x in range(len(msg)//message_byte_length)]:


        assert len(block) % 8 == 0

        intmed_state = cipher_f(block, intmed_state)
        intmed_states.append(intmed_state)

    return intmed_states


# Find a single-block bridge to an intermediate state of target large msg

def find_bridge_block(expandable_msg_state):
    for block in (num.to_bytes(8, byteorder="little") for num in range(2**(message_byte_length*8))):

        new_hash = iterated_hash(block, expandable_msg_state, blowfish_weak_hash, message_byte_length)

        if new_hash in intmed_states:
            print("Found linking block!")
            return block, intmed_states.index(new_hash)



def generate_prefix(target_len):
    # Takes in target_len, a number of blocks we want the prefix to be
    # Basically for each bit of the binary representation of desired length, select one or the other of the expandable messages, which come in sets of (1, power of 2 + 1)

    prefix = b""
    assert len(fragments) == k

    for i in range(0, k):
        block = fragments[i]
        # if binary_len[i] == '1':
        #     # Select block of len(power of 2 + 1)
        #     prefix += fragments[i][1]
        # else:
        #     # Select single block
        #     prefix += fragments[i][0]

        if len(prefix) // message_byte_length + len(block[1]) // message_byte_length + (k - i - 1) <= target_len:
            # Select block of len(power of 2 + 1)
            prefix += block[1]
        else:
            # Select single block
            prefix += block[0]

        print("prefix len", len(prefix))

    print("final prefix len", len(prefix))
    assert len(prefix)//8 == target_len
    return prefix


# k = 5
# init_state = os.urandom(2)

# expandable_msg_state, fragments = gen_expandable(k)

# target_long_msg = os.urandom(100)
# intmed_states = get_intermed_states(target_long_msg, init_state, blowfish_weak_hash)

# # Exclude first k intermediate states, because expandable message cannot be made shorter than k blocks, so we wouldn't be able to generate a prefix of len < k 
# intmed_states[:k] = ['fake'] * k

# # Find a bridge block that intercepts one of the intermediate hashes of the target message
# # The key is that the starting state of bridge block is the final state of the expandable message
# linking_block, intmed_state_index = find_bridge_block(expandable_msg_state)
# print("linking block", linking_block, "index: ", intmed_state_index)


# prefix = generate_prefix(intmed_state_index)
# print(repr(prefix))

# second_preimage = prefix + linking_block
# second_preimage += target_long_msg[len(second_preimage): ]

# print("length of second preimage", len(second_preimage))
# assert len(second_preimage) == len(target_long_msg)

# second_preimage_hash = iterated_hash(second_preimage, init_state, blowfish_weak_hash, message_byte_length, padding = True)
# target_msg_hash = iterated_hash(target_long_msg, init_state, blowfish_weak_hash, message_byte_length, padding = True)

# print("second preimage hash", repr(second_preimage_hash))
# print("target msg hash", repr(target_msg_hash))

# assert second_preimage_hash == target_msg_hash


print("Challenge 54 Kelsey and Kohno's Nostradamus attack")

def pairwise(iterable):
    "s -> (s0, s1), (s2, s3), (s4, s5), ..."
    a = iter(iterable)
    return zip(a, a)

# Note that this is pretty inefficient, we could have used a parallel search algorithm for this part instead of grabbing the leaves by the pair and fixing the message of one... 
def find_collision(state1, state2):
    single_block = b'\x01'*8
    target_hash = iterated_hash(single_block, state1, blowfish_weak_hash, message_byte_length)

    print("target hash", repr(target_hash))

    for msg in (num.to_bytes(8, byteorder="little") for num in range(2**(message_byte_length*8))):

        new_hash = iterated_hash(msg, state2, blowfish_weak_hash, message_byte_length)

        if new_hash == target_hash:
            print("Found collision with this pair %s %s" % (state1, state2))
            return single_block, msg, target_hash


hash_length = 2
def gen_collision_tree(k):
    init_hash_states = [i.to_bytes(hash_length, byteorder='little') for i in range(2**k)]

    collision_tree = []

    hash_states = init_hash_states
    for i in range(0, k):
        next_layer = []
        this_layer = []
        print("i", i)
        for state1, state2 in pairwise(hash_states):
            # Generate a collision with these two states
            # this becomes the parent in the tree 
            collide_block1, collide_block2, collide_hash = find_collision(state1, state2)

            # Add the blocks to this layer of the collision tree
            this_layer.append((state1, collide_block1))
            this_layer.append((state2, collide_block2))

            next_layer.append(collide_hash)

        collision_tree.append(this_layer)
        print("collision tree", collision_treae)
        hash_states = next_layer

    collision_tree.append(next_layer)

    assert len(collision_tree[-1]) == 1
    return collision_tree


# root of collision tree is our magic prediction
collision_tree = gen_collision_tree(3)

# prediction = collision_tree[-1]

# nostradamus_msg = b"The world will end in 2016"

# num_msg_blocks = len(nostradamus_msg)//8 + 1

# glue_blocks = ("\x00"*8) * (k - num_msg_blocks) + "\x00"*(8 - len(nostradamus_msg)%8)

# nostradamus_msg += glue_blocks

# assert len(nostradamus_msg)%8 == 0

# # Find the last bridge block that will collide with a leaf in my tree
# nostradamus_msg_state = iterated_hash(nostradamus_msg, init_state, blowfish_weak_hash, message_byte_length)
# for msg in (num.to_bytes(8, byteorder="little") for num in range(2**(message_byte_length*8))):

#     new_hash = iterated_hash(msg, nostradamus_msg_state, blowfish_weak_hash, message_byte_length)

#     if new_hash in leaves:




# Now, follow the path from the leaf to the root, appending all the colliding message blocks to get to the root hash



















