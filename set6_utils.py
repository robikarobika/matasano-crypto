import binascii
import base64
from pwn import *
import itertools as it
from pprint import *
import operator as op
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import gensafeprime
import math
import gmpy2
import hashlib
import os
import random

from set5_utils import *

def int2bytes(num, size = 'all'):
    return pack(num, size ,endianness='big')

def bytes2int(b, size = 'all'):
    return unpack(b, size ,endianness='big')
