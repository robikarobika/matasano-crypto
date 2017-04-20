import random
from math import sqrt
from itertools import count, islice
import binascii

E_KEY = 65537

'''
Input: n - the key-size
Output: pk = (e, N); sk = (d, N)

keygen generates a (pk, sk) key-pair.
-- See https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation for more information.
-- For step #4, set e=E_KEY
'''
def keygen(n):
    e = E_KEY
    
    ##generate two random primes of length n bits

    p = gen_primes(n)
    q = gen_primes(n)

    ### REPLACE WITH IMPLEMENTATION
    N = p*q
    phi = (p-1)*(q-1)

    d = modinv(e , phi)
    # print d
    ### END

    
    sk = (d, N)
    pk = (e, N)
    return pk, sk

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y


def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m



def is_prime(p):
    if(p==2): return True
    if(not(p&1)): return False
    return pow(2,p-1,p)==1


def gen_primes(n):
    p = random.getrandbits(n)
    # print p

    if p % 2 ==0:
        p = p + 1

    while not is_prime(p):
        p = p + 2
        
    return p



'''
Input: sk - the secret key tuple; m - the message to sign
Output: sigma - the RSA signature of m with sk

-- See https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Signing_messages for more information.
'''
def sign(sk, m):
    if isinstance(m, str):
        b = bin(int(binascii.hexlify(m), 16))
        m = int(b, 2)

    d = sk[0]
    N = sk[1]

    sigma = pow(m,d,N)
    
    return sigma
    
'''
Input:  pk - the public key tuple; m - the original message;
        sigma - the RSA signature of m with the secrey key corresponding to pk
Output: True if sig is correct, False otherwise

-- See https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Signing_messages for more information.
'''
def verify(pk, m, sigma):

    if isinstance(m, str):
        b = bin(int(binascii.hexlify(m), 16))
        m = int(b, 2)

    e = pk[0]
    N = pk[1]

    sign_removed = pow(sigma, e, N)

    if sign_removed == m:
        return True
    else:
        return False

    ### REPLACE WITH IMPLEMENTATION
    
    ### END
    
'''
Input: pk - the public key tuple
Output: sigma - a valid (fake) signature forged directly from the public key
'''
def ForgeSig(pk):
    ### REPLACE WITH IMPLEMENTATION

    e = pk[0]
    N = pk[1]

    # sigma = 'testing forge1'

    # b = bin(int(binascii.hexlify(sigma), 16))
    # sigma_int = int(b, 2)

    # m_int = pow(sigma_int, e, N)
    # print m_int
    # m_str = binascii.unhexlify('%x' % m_int)
    # print m_str

    # ### END
    
    # return m_str, sigma_int

    sigma_int = 123

    # b = bin(int(binascii.hexlify(sigma), 16))
    # sigma_int = int(b, 2)

    m_int = pow(sigma_int, e, N)
    # print m_int
    # m_str = binascii.unhexlify('%x' % m_int)
    # print m_str

    ### END
    
    return m_int, sigma_int


def factors(n):    
    i = 2
    while i**2 <= n:
        if n % i:
            i += 1
        else:
            return i
    return n

'''
Input:  pk - the public key tuple; sk - the secret key tuple; 
        m the message to forge signature for
Output: sigma - a valid (fake) signature forged directly from the public key for message m
'''
def ForgeSigWithMsg(pk, sk, m):
    ### REPLACE WITH IMPLEMENTATION
    if isinstance(m, str):
        b = bin(int(binascii.hexlify(m), 16))
        m = int(b, 2)

    first_factor = factors(m)
    m1 = int(first_factor)
    m2 = int(m/first_factor)
    ### END
    # print m1, m2
    
    # NOTE: you cannot make ANY other use of sk
    # except for those two lines
    sig1 = sign(sk, m1)
    sig2 = sign(sk, m2)
    
    ### REPLACE WITH IMPLEMENTATION
    sigma = sig1*sig2
    ### END
    
    return sigma



if __name__ == "__main__":

    pk, sk = keygen(200)
    print pk

    print sk

    m = 'heythere'

    signed =  sign(sk, m)
    print signed
    verify = verify(pk, m, signed)
    print verify

    # forge_m, forge_s = ForgeSig(pk)
    # print ""
    # print verify(pk, forge_m, forge_s)

    # forge_s = ForgeSigWithMsg(pk, sk, m)
    # print verify(pk, m, forge_s)

    # print is_prime(982451653)
