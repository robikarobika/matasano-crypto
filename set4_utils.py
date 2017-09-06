#SHA1 implementation from https://github.com/ajalt/python-sha1/
#!/usr/bin/env python

from __future__ import print_function
import struct
import io
import binascii

from pwn import *
import itertools as it
from pprint import *


try:
    range = xrange
except NameError:
    pass

class SHA1(object):
    """A class that mimics that hashlib api and implements the SHA-1 algorithm."""

    name = 'python-sha1'
    digest_size = 20
    block_size = 64

    def __init__(self, h = None, message_byte_length = 0):
        # Initial digest variables
        if h is None:
            self._h = [
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0,
            ]
        else:
            self._h = h

        # bytes object with 0 <= len < 64 used to store the end of the message
        # if the message length is not congruent to 64
        self._unprocessed = b''
        # Length in bytes of all data that has been processed so far
        self._message_byte_length = message_byte_length


    def _process_chunk(self, chunk, h0, h1, h2, h3, h4):
        """Process a chunk of data and return the new digest variables."""
        # print ('chunk', len(chunk))
        assert len(chunk) == 64

        w = [0] * 80

        # Break chunk into sixteen 4-byte big-endian words w[i]
        for i in range(16):
            w[i] = struct.unpack(b'>I', chunk[i*4:i*4 + 4])[0]

        # Extend the sixteen 4-byte words into eighty 4-byte words
        for i in range(16, 80):
            w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)

        # Initialize hash value for this chunk
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in range(80):
            if 0 <= i <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid bitwise not
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = ((rol(a, 5) + f + e + k + w[i]) & 0xffffffff,
                            a, rol(b, 30), c, d)

        # Add this chunk's hash to result so far
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

        return h0, h1, h2, h3, h4


    def update(self, arg):
        """Update the current digest.

        This may be called repeatedly, even after calling digest or hexdigest.

        Arguments:
            arg: bytes, bytearray, or BytesIO object to read from.
        """
        if isinstance(arg, (bytes, bytearray)):
            arg = io.BytesIO(arg)

        # Try to build a chunk out of the unprocessed data, if any
        chunk = self._unprocessed + arg.read(64 - len(self._unprocessed))

        # Read the rest of the data, 64 bytes at a time
        while len(chunk) == 64:
            self._h = self._process_chunk(chunk, *self._h)
            self._message_byte_length += 64
            chunk = arg.read(64)

        self._unprocessed = chunk
        return self


    def digest(self):
        """Produce the final hash value (big-endian) as a bytes object"""
        return b''.join(struct.pack(b'>I', h) for h in self._produce_digest())

    def hexdigest(self):
        """Produce the final hash value (big-endian) as a hex string"""
        return '%08x%08x%08x%08x%08x' % self._produce_digest()

    def _produce_digest(self):
        """Return finalized digest variables for the data processed so far."""
        # Pre-processing:
        message = self._unprocessed
        message_byte_length = self._message_byte_length + len(message)

        # append the byte '1' to the message
        message += b'\x80'

        # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
        # is congruent to 56 (mod 64)
        message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

        # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
        message_bit_length = message_byte_length * 8
        message += struct.pack(b'>Q', message_bit_length)

        # Process the final chunk
        # At this point, the length of the message is either 64 or 128 bytes.
        h = self._process_chunk(message[:64], *self._h)
        if len(message) == 64:
            return h
        return self._process_chunk(message[64:], *h)


def authsha1(key, data):
    """SHA-1 Hashing Function

    A custom SHA-1 hashing function implemented entirely in Python.

    Arguments:
        data: A bytes or BytesIO object containing the input message to hash.

    Returns:
        A hex SHA-1 digest of the input message.
    """
    return SHA1().update(key + data).digest()



lrot = lambda x, n: (x << n) | (x >> (32 - n))


class MD5():
    # r specifies the per-round shift amounts
    r = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
         5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

    # Use binary integer part of the sines of integers (Radians) as constants
    k = [int(math.floor(abs(math.sin(i + 1)) * (2 ** 32))) for i in range(64)]

    def __init__(self, message, message_byte_length = 0, state_array = None):
        if state_array:
            self.A = state_array[0]
            self.B = state_array[1]
            self.C = state_array[2]
            self.D = state_array[3]
            print("Set up intermediate state")
        else:
            #initial magic
            self.A, self.B, self.C, self.D = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)

        if message_byte_length:
            self._message_byte_length = message_byte_length + len(message)
        else:
            self._message_byte_length = len(message)

        print("self._message_byte_length", self._message_byte_length)

        while len(message) > 64:
            self._handle(message[:64])
            message = message[64:]

        self._unprocessed = message

    def _handle(self, chunk):
        w = list(struct.unpack('<' + 'I' * 16, chunk))

        a, b, c, d = self.A, self.B, self.C, self.D

        for i in range(64):
            if i < 16:
                f = (b & c) | ((~b) & d)
                g = i
            elif i < 32:
                f = (d & b) | ((~d) & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * i) % 16

            x = b + lrot((a + f + self.k[i] + w[g]) & 0xffffffff, self.r[i])
            a, b, c, d = d, x & 0xffffffff, b, c

        self.A = (self.A + a) & 0xffffffff
        self.B = (self.B + b) & 0xffffffff
        self.C = (self.C + c) & 0xffffffff
        self.D = (self.D + d) & 0xffffffff

    def digest(self):
        message = self._unprocessed
        # append the byte '1' to the message
        message += '\x80'

        # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
        # is congruent to 56 (mod 64)
        message += '\x00' * ((56 - (self._message_byte_length+1) % 64) % 64)

        # append length of message (before pre-processing), in bits, as 64-bit little-endian integer
        length = struct.pack('<Q', self._message_byte_length * 8)
        message += length

        while len(message):
            self._handle(message[:64])
            message = message[64:]

        return struct.pack('<IIII', self.A, self.B, self.C, self.D)

    def hexdigest(self):
        return binascii.hexlify(self.digest()).decode()


def authmd5(key, message):
    '''
        Returns a secret-key-prefix MD5 MAC
    '''
    return MD5(key+message).digest()
