import binascii
import base64
from pwn import *
import itertools as it
from pprint import *
import operator as op
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import math
import hashlib
import os
import random
import re

import sys
sys.path.append('..')

from set5_utils import *
from set6_utils import *
from set7_utils import *

import tornado.web

key = "YELLOW SUBMARINE"
iv = '\x00'*16

l = listen(5000)

while True:
    msg = l.recvline(keepends = False)
    mac = l.recvline(keepends = False)

    CBC_MAC(key, iv, msg)

    if gen_mac == mac:
        print "MAC Verified"

        params = msg.split("&")
        from_param, tx_list_param = params[0], params[1]

        split_from = from_param.split("=")
        assert split_from[0] == "from"
        from_id = split_from[1]

        tx_list = tx_list_param.split("=")[1].split(";")

        for to_amt_pair in tx_list:
            to_id = to_amt_pair.split(":")[0]
            amount = to_amt_pair.split(":")[1]

            print "Sending %s from %s to %s" % (amount, from_id, to_id)

    else:
        print "MAC Failed"
