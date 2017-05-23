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
import re
from Crypto.Cipher import PKCS1_v1_5

import sys
sys.path.append('..')

from set5_utils import *
from set6_utils import *
from set7_utils import *

import tornado.web

key = "YELLOW SUBMARINE"

l = listen(5000)

while True:
    msg = l.recvline(keepends = False)
    iv = l.recvline(keepends = False)
    mac = l.recvline(keepends = False)

    key = "YELLOW SUBMARINE"

    gen_mac = CBC_MAC(key, iv, msg)

    if gen_mac == mac:
        print "MAC Verified"

        params = msg.split("&")
        amount = params[2].split("=")[1]
        from_id = params[0].split("=")[1]
        to_id = params[1].split("=")[1]
        print "Sending %s from %s to %s"% (amount, from_id, to_id)
    else:
        print "MAC Failed"
