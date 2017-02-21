# Set 4 writeup

## Challenge 25 Break "random access read/write" AES CTR

Because we can seek into the ciphertext and edit arbitrary characters, we we can simply guess each plaintext character.

For each byte in the ciphertext, I can try all 256 characters by replacing the ciphertext byte with my encrypted guess using the provided `edit()` function. If the new ciphertext exactly matches the original ciphertext, then I know my guess for the plaintext character is correct, since it encrypted to the same byte.

```
for i in xrange(len(ciphertext)):
  for c in candidates:
    new_ciphertext = edit(ciphertext, i, c)

    if new_ciphertext[i] == ciphertext[i]:
      result += c
```

My main gripe is that this program is veryyy slow and I'm not sure where the slowdown comes from, but I'm not concerned with optimising right now.  

## Challenge 26 CTR bitflipping

CTR is susceptible to an even simpler bitflipping attack than CBC.

I can simply send in the payload string as before `'\x00admin\x00true\x00'`, which will be inserted between `""comment1=cooking%20MCs;userdata="
" and ";comment2=%20like%20a%20pound%20of%20bacon"` and encrypted.

I can modify the ciphertext for the block-of-interest directly — I don't even need the previous ciphertext block as in CBC!

```
ciphertext[32] = chr(ord(ciphertext[32]) ^ 59)
ciphertext[38] = chr(ord(ciphertext[38]) ^ 61)
ciphertext[43] = chr(ord(ciphertext[43]) ^ 59)
```

will XOR in the ASCII codes for `;` and `=`, so when CTR decryption XORs this ciphertext against the keystream, the desired characters will be left.


## Challenge 27 Recover the key from CBC with IV=Key

Apparently, using the key as an IV is insecure, if an attacker can modify the ciphertext in-flight.

The challenge instructs us to:

```
Use your code to encrypt a message that is at least 3 blocks long:

AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
Modify the message (you are now the attacker):

C_1, C_2, C_3 -> C_1, 0, C_1
Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found.

As the attacker, recovering the plaintext from the error, extract the key:

P'_1 XOR P'_3
```

Why does this work? Well, by inserting all `\x00`'s' in block 2, when we CBC decrypt block 3 of C', we recover the intermediate state of C_1, since we XOR with all `\x00`. We also have the plaintext of C_1 in the first block. So, we can simply recover the IV by XORing the plaintext with the intermediate state.

```
P'_3 ^ IV = P'_1

IV = P'_1 ^ P'_3
```


## Challenge 28 Implement a SHA-1 keyed MAC

The way a MAC works is described in this diagram off wikipedia:
![MAC diagram](https://upload.wikimedia.org/wikipedia/commons/0/08/MAC.svg)


We run the message through the HMAC algo, and send both the message and MAC digest to the receiver. The receiver must verify that the message he received has not been tampered by running it through the same MAC algo, and checking it against the MAC digest he received.  

In this case, our HMAC algo is just secret-prefix, `SHA1(key || message)`.

I borrow a SHA1 implementation from https://github.com/ajalt/python-sha1.

The `authsha1(key, data)` function produces the MAC digest, and `validate_oracle(key, message, digest)` checks that the MAC digest of `message` matches `digest`.


## Challenge 29 Break a SHA-1 keyed MAC using length extension

This is a cool attack.

Here's a general idea of how SHA-1 works:

SHA1 operates on padded data.

The [RFC](https://tools.ietf.org/html/rfc3174) explains the padding scheme as follows:
` The purpose of message padding
   is to make the total length of a padded message a multiple of 512.
   SHA-1 sequentially processes blocks of 512 bits when computing the
   message digest.`

 1. '1' is appended to message.
 2. '0's are appended, depending on the original length of the message. Leave space for two 4-byte words at the end, so bring up the message to 448 bits (56 bytes).
We can do that with
   ```
       message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)
   ```
 If the message is already >56,

 3. Append the 2-word representation of len(message).
 If the message is 40 bytes long,  The two-word representation of 40 is hex `00000000 00000028.`

There are five internal state variables, h0, h1, h2, h3, h4. These are concatenated to give the final digest.

The h's are initialized to
```
0x67452301,
0xEFCDAB89,
0x98BADCFE,
0x10325476,
0xC3D2E1F0,
```

Then, each chunk is processed and the h's are updated as follows:

1. Split the 64-byte chunk into 16 4-byte words
2. Populate a word_array of size 80 with the 16 words, and then 64 more generated values.
3. Let `A = H0, B = H1, C = H2, D = H3, E = H4`.
4. Do 80 rounds of transformations on a, b, c, d, e.
5. Finally, update the internal digests
`H0 = H0 + A, H1 = H1 + B, H2 = H2 + C, H3 = H3 + D, H4 = H4 + E`.

So, when `update()` is called in `authsha1`, the internal states (the h's) are updated for every full 64-byte block, leaving the leftovers in `self._unprocessed`. Then, `digest()` is called, to pad the leftovers to 64 or 128 bytes, and do the last 1 or 2 internal state updates, returning the concatenated h's as the digest.

### The attack

The attack will mean I am able to successfully append some data to the message and create a forged digest, such that the receiver will think that I generated the digest by knowing the key and accept the message as untampered.

The steps for forging a digest are:

I need to guess the length of the key so that my message will have the correct padding.

1. Split the SHA1 digest of the true message into 5 pieces, which will be passed as `h0, h1, h2, h3, h4` to a new SHA1.

2. For each guess for the keylength, prepend key padding to the original message and append SHA1 padding.

  ```
  |keylen_guess|
  AAAAAAAAAAAAAA orig_message \x01\x00\x00...
  ```

3. Pass in the internal state variables and the length of the padded message to a new SHA1, telling the algorithm how many bytes have been processed so far(`message_byte_length`) and the current state. Update the SHA1 with the extension data, getting a forged digest.

  We're essentially forging the digest for:
  ```
  |keylen_guess|
  AAAAAAAAAAAAAA orig_message \x01\x00\x00... ;admin=true
  ```

3. Now, remove the key padding from the extended message, leaving the forged message:
```
orig_message \x01\x00\x00... ;admin=true
```
. Send this and its forged digest to the receiver to be verified. The receiver will prepend the key to this message and calculate the digest. When we guess the correct keylen, the padding we've added to the orig_message block will be correct, and the SHA1 will continue by hashing the next block, `;admin=true`, and find that the digest is the same as our forged one.


  ```
  padded_plaintext_no_key = padded_plaintext_with_key_extension[keylen_guess:]

  if validate_oracle(key, padded_plaintext_no_key, forged_digest):
    print "Found keylen_guess", keylen_guess
  ```

I successfully created a forged digest for the message `comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x98;admin=true` that the receiver validates!

## Challenge 30 Break an ~~MD4~~ MD5 keyed MAC using length extension

I decided I like MD5 better than MD4, and there's more implementations out there.

MD5 is susceptible to the same length extension attack as above because it follows the MD construction, which includes padding and the fact that the output of the hash gives all the state needed to continue, or extend, the hash.

Here's how MD5 works:

The padding scheme is very similar to SHA-1 — the only difference being that the length is added on as big-endian packed instead of little-endian packed.

There are four internal state variables - A, B, C, D, each 32 bits. These are initialized to
```
word A: 01 23 45 67
word B: 89 ab cd ef
word C: fe dc ba 98
word D: 76 54 32 10

```

We also use a table of 64 values generated from the `sine` function, `self.k`.

1. For each chunk, which is 512 bits, we unpack into 16 words of 32-bits.

2. Then, we do 64 transforms, split into four rounds. each transform taking: an incrementing-by-one index into the `sin` table, a function `f` specific to the round, a `lrot` value, and an index into our array of 16 words.

  At the end of each transform, the `ABCD` values are updated as follows:

  ```
    a, b, c, d = d, x & 0xffffffff, b, c
  ```
  where `x` is the result of the transform.

The message digest produced as output is the concat of A, B, C, D, 128 bits, or 16-bytes in length.

I use the implementation at https://github.com/FiloSottile/crypto.py/blob/master/2/md5.py, but it needs to be extended in several ways for this challenge.

The implementation must allow the caller to set the internal state variables so that I can continue the hash. I add
```
if state_array:
        self.A = state_array[0]
        self.B = state_array[1]
        self.C = state_array[2]
        self.D = state_array[3]
    else:
        #initial magic
        self.A, self.B, self.C, self.D = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
```

The implementation also must allow the caller to specify how many bytes have been processed so far, the `message_byte_length` option above.



## Challenge 31 Implement and break HMAC-SHA1 with an artificial timing leak

I use Tornado as my web framework.

I take in a `file` and `signature` URL param, and implement an `insecure_compare` function that converts the values to ascii, then byte-by-byte compares, adding a timing delay of 50ms.

I iterate through all possible bytes, making a request with my known bytes + byte_guess + padding.

I simply take the maximum delay each time, which would occur when I've guessed the byte correctly, causing another sleep of 50ms, for an added delay of 100ms.

## Challenge 32 Break HMAC-SHA1 with a slightly less artificial timing leak

When I have such a small timing leak (5ms), network delays make the previous exploit unreliable. I need to normalize over multiple runs (I choose 10) to be able to tell whether the maximum is indeed the correct HMAC byte.  
