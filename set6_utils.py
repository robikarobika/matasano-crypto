from pwn import *

from set5_utils import *

def int2bytes(num, size = 'all'):
    return pack(num, size ,endianness='big')

def bytes2int(b, size = 'all'):
    return unpack(b, size ,endianness='big')
