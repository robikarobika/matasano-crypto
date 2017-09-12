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

l = listen(9999)

def parse_and_send(tx_list):
    for to_amt_pair in tx_list:
        if len(to_amt_pair.split(":")) != 2:
            continue

        to_id = to_amt_pair.split(":")[0]
        amount = to_amt_pair.split(":")[1]
        match = re.match(b'[0-9]+', amount)
        amount = match.group(0)

        print "Sending %s from %s to %s" % (amount, from_id, to_id)

try:
    while True:
        msg = l.recvline(keepends = False)
        mac = l.recvline(keepends = False)

        print "msg", repr(msg)
        print "mac", repr(mac)

        gen_mac = CBC_MAC(key, iv, msg)

        if gen_mac == mac:
            print "MAC Verified"

            params = msg.split("&", 1)
            from_param, tx_list_param = params[0], params[1]

            split_from = from_param.split("=")
            assert split_from[0] == "from"
            from_id = split_from[1]

            tx_list = tx_list_param.split("=", 1)[1].split(";")

            parse_and_send(tx_list)

        else:
            print "MAC Failed"
except EOFError:
    exit()