import binascii
import base64
from pwn import *
import requests
import string
from operator import itemgetter

import sys
import time
sys.path.append('..')

from set4_utils import *

def guess_byte(known_bytes):
    response_times = []
    start = time.time()
    for i in xrange(256):
        hex_dig = hex(i)[2:]
        hmac_guess = known_bytes + hex_dig
        hmac_guess = hmac_guess.ljust(40, '0') # pad out to 40

        payload = {'file': 'hello.txt', 'signature': hmac_guess}

        r = requests.get("http://localhost:9000/test", params = payload)

        ms_delay = r.elapsed.total_seconds()*1000.
        response_times.append((hex_dig, ms_delay))

    end = time.time()
    print "Tried 256 bytes in %s seconds" % (end-start)
    return response_times


def repeated_guess_byte(known_bytes):
    avg_response_times = {hex(key)[2:]: 0 for key in xrange(256)}
    start = time.time()

    for i in xrange(10):
        response_tuples = guess_byte(known_bytes)
        for byte_time_pair in response_tuples:
            avg_response_times[byte_time_pair[0]] += byte_time_pair[1]/10

    end = time.time()
    print "Completed 2560 bytes in %s seconds" % (end-start)
    print avg_response_times
    return max(avg_response_times.iteritems(), key=operator.itemgetter(1))


hmac_known_bytes = ""
for i in xrange(20):
    char = repeated_guess_byte(hmac_known_bytes)[0]
    print char
    hmac_known_bytes += char


assert '7d1476e78124d9a22b121cc5554e7f556a331ac5' == hmac_known_bytes
print "Discovered the hmac: ",  hmac_known_bytes
