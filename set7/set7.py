# -*- coding: utf-8 -*-

import IPython
import binascii
import base64
from pwn import *
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

import sys
sys.path.append('..')

from set5_utils import *
from set3_utils import *
from set6_utils import *
from set2_utils import *
from set7_utils import *


# def padPKCS7semis(x, padto):
# 	diff = (padto - (len(x)%padto)) % 16

# 	padded = x + ';'*diff
# 	return padded


# print "Challenge 50 Hashing with CBC-MAC"
# js = "alert('MZA who was that?');\n"
# js_padded = padPKCS7(js, 16)

# iv = '\x00'*16
# key = "YELLOW SUBMARINE"

# assert binascii.hexlify(CBC_MAC(key, iv, js_padded)) == "296b8d7cb78a243dda4d0a61d33bbdd1"

# # Forge this JS snippet, adding a comment so illegal characters after are ignored
# forge = "alert('Ayo, the Wu is back!');//"
# forge_padded = padPKCS7(forge, 16)

# mac = CBC_MAC(key, iv, forge_padded)
# concat_forge = forge_padded + xor(mac, js_padded[:16]) + js_padded[16:]
# print "concat_forge", repr(concat_forge)

# assert binascii.hexlify(CBC_MAC(key, iv, concat_forge)) == "296b8d7cb78a243dda4d0a61d33bbdd1"


print "Challenge 51 Compression Ratio Side-Channel Attacks — or CRIME!"

def compression_oracle_ctr(ptext):
    rand_key = os.urandom(16)
    rand_nonce = u64(os.urandom(8))
    ctr = CTR(Cipher(algorithm = algorithms.AES(rand_key), mode = modes.ECB(), backend=default_backend()), rand_nonce)
    return len(ctr.encrypt(zlib.compress(ptext)))


def compression_oracle_cbc(ptext):
    rand_key = os.urandom(16)
    rand_nonce = os.urandom(16)
    ptext = zlib.compress(ptext)

    cipher = Cipher(algorithm = algorithms.AES(rand_key), mode = modes.CBC(rand_nonce), backend=default_backend())
    enc = cipher.encryptor()

    ciphertext = enc.update(padPKCS7(ptext, 16)) + enc.finalize()
    return len(ciphertext)


request = """POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: {}
{}"""

base64_chars = "T0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSUVWXYZ="
padding_chars = "!@#$%^&*()-`~[]}{"

def format_request(content):
    return request.format(str(len(content)), content)

def compression_oracle_worker(args):
    '''
    Returns (compression_len, request content, padding)
    '''

    padding, cookie = args
    return (oracle(format_request(padding + cookie)), padding + cookie, padding)

def get_padding(text):
    ''' 
    This function adds the proper padding such that we push the length of the compressed, encrypted data past a block boundary, when there is no extra compression.
    '''

    padding = ""
    base_len = compression_oracle_cbc(format_request(text))

    for i in xrange(17):
        padding += padding_chars[i]
        padded_len = compression_oracle_cbc(format_request(padding + text))
        if padded_len > base_len:
            # We've pushed the padding past a block boundary
            # Return the padding we found
            return padding


def crime_attack():
    final = "sessionid="

    for i in xrange(22):  
        # Get padding for CBC mode
        padding = get_padding(final)

        pool = mp.Pool(processes = 8) 
        base64_perms = [[padding[:-1], final + "".join(perm)] for perm in it.permutations(base64_chars, 2)]
        base64_perms += [[padding[:-2], final + "".join(perm)] for perm in it.permutations(base64_chars, 2)]

        compression_lens = pool.map(compression_oracle_worker, base64_perms)

        # Find the minimum compressed length 
        best_compression, best_cookie, best_padding = min(compression_lens, key=operator.itemgetter(0))

        # Update the result session id with the cookie of minimum compressed length
        final = best_cookie[len(best_padding):]

    return final


# oracle = compression_oracle_ctr
# found_session_id = crime_attack()
# assert found_session_id == "sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="

# oracle = compression_oracle_cbc
# found_session_id = crime_attack()

# assert found_session_id == "sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="


print "Challenge 52 Iterated Hash Function Multicollisions"

message_byte_length = 8
def MD_padding(message):
    # append the byte '1' to the message
    message += b'\x80'

    # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
    # is congruent to 56 (mod message_byte_length)
    message += b'\x00' * ((56 - len(message) % message_byte_length) % message_byte_length)

    # append length of message (before pre-processing), in bits, as message_byte_length-bit big-endian integer
    message_bit_length = message_byte_length * 8
    message += struct.pack(b'>Q', message_bit_length)

    assert len(message) % message_byte_length == 0

    print repr(message)
    return message

hash_length = 2
def iterated_hash(msg, init_state, cipher_f, block_len, padding = False):
    # Fuck the padding — just makes things more complicated.
    
    if padding:
        padded_msg = MD_padding(msg)
    else:
        padded_msg = msg

    if len(init_state) < hash_length:
        # Pad initial state on the way in 
        init_state = init_state + (b'\x00' * (hash_length - len(init_state)))
    else:
        # Drop bits if necessary
        init_state = init_state[:hash_length]

    for block in [padded_msg[x:x+block_len] for x in xrange(0, len(padded_msg), block_len)]:
        init_state = cipher_f(block, init_state)

    return init_state


def blowfish_weak_hash(block, init_state):
    cipher = Blowfish.new(init_state, Blowfish.MODE_ECB)

    # Drop bits to keep state at length hash_length
    new_state = cipher.encrypt(block)[:hash_length]
    return new_state



collision_calls = 0
def gen_single_collision(init_state):
    print "Calling gen_single_collision"
    global collision_calls
    collision_calls += 1

    # Bruteforce over all possible messages of length hash_length
    # Find initial collision
    hashes = {}
    for msg in [int2bytes(num, 64) for num in xrange(2**(hash_length*8))]:

        new_hash = iterated_hash(msg, init_state, blowfish_weak_hash, message_byte_length)

        if new_hash in hashes:
            # If we found a collision,
            # Return two colliding messages, and the colliding hash
            return (msg, hashes[new_hash], new_hash)
        else:
            hashes[new_hash] = msg


init_state = os.urandom(5)

def extend_collisions(collisions, intermed_state):
    '''
    Generate another pair of colliding blocks, and then append each colliding block to each previous collision. The resulting messages will all collide, because each message goes through the same intermediate states on its way to the final colliding hash, albeit a different permutation of blocks from each pair. This doubles the number of collisions we have. 
    '''

    block1, block2, colliding_state = gen_single_collision(intermed_state)

    return [col_block + m for col_block in collisions for m in [block1, block2]], colliding_state

def gen_multicollisions(n, init_state):
    collisions = []

    block1, block2, colliding_state = gen_single_collision(init_state)
    collisions.extend([block1, block2])

    # Assert that these two collide
    assert iterated_hash(block1, init_state, blowfish_weak_hash, message_byte_length) == iterated_hash(block1, init_state, blowfish_weak_hash, message_byte_length)

    for i in xrange(n-1):
        collisions, colliding_state = extend_collisions(collisions, colliding_state)

    # Assert that these are all indeed collisions
    for col_msg in collisions:
        assert iterated_hash(col_msg, init_state, blowfish_weak_hash, message_byte_length) == colliding_state

    return collisions, colliding_state

stronger_hash_length = 3

# Harder to collide hashes of stronger_hash_length
def strong_hash(block, init_state):
    cipher = ARC2.new(init_state, CAST.MODE_ECB)
    new_state = cipher.encrypt(block)[:stronger_hash_length]
    return new_state


def generate_stronghash_collision():
    stronghashes = {}
    already_hashed_msgs = set()
    weakhash_collisions, intermed_state = gen_multicollisions(stronger_hash_length*4, init_state)

    while True:    
        print "weak collisions calls", collision_calls

        for msg in weakhash_collisions:
            if msg in already_hashed_msgs: continue

            new_hash = iterated_hash(msg, init_state, strong_hash, message_byte_length)

            if new_hash in stronghashes:
                print "FOUND STRONGHASH COLLISION"
                return (msg, stronghashes[new_hash], new_hash)
            else:
                stronghashes[new_hash] = msg
                already_hashed_msgs.add(msg)

        # Need to generate some more weak hash collisions!
        weakhash_collisions, intermed_state = extend_collisions(weakhash_collisions, intermed_state)


# collisions, colliding_state = gen_multicollisions(2, init_state)
# print "Calls to gen_collisions:", collision_calls
# print "number of collisions: ", len(collisions)
# print "Collisions: "
# for col_msg in collisions:
#     print "%s\tHASH: %s" % (repr(col_msg), repr(iterated_hash(col_msg, init_state, blowfish_weak_hash, message_byte_length)))


# colliding1, colliding2, colliding_hash = generate_stronghash_collision()
# print colliding1
# print colliding2
# print colliding_hash

# # Assert that this collides both weak and strong hashes
# assert iterated_hash(colliding1, init_state, blowfish_weak_hash, message_byte_length) == iterated_hash(colliding2, init_state, blowfish_weak_hash, message_byte_length)

# assert iterated_hash(colliding1, init_state, strong_hash, message_byte_length) == iterated_hash(colliding2, init_state, strong_hash, message_byte_length)








