import binascii
import base64
from pwn import *
import itertools as it
from pprint import *
import operator as op
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import gensafeprime
import gmpy2
import hashlib
import os
import random

def CBC_MAC(key, iv, padded):
    cipher = Cipher(algorithm = algorithms.AES(key), mode = modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()

    ciphertext = enc.update(padded) + enc.finalize()
    mac = ciphertext[-16:]
    return mac
