# Set 2 writeup

## Challenge 9 Implement PKCS#7 padding
As the challenge states, "A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages."

The PKCS#7 padding scheme will append the number of bytes of padding to the end of the block.

I use the pwntools `pack()` function to pack the number of padding bytes.

## Challenge 10 Implement CBC mode


This challenge has us implement CBC mode of block encryption.

In CBC mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted. We need an IV for the first block of plaintext.

![CBC Encryption](https://upload.wikimedia.org/wikipedia/commons/d/d3/Cbc_encryption.png)

![CBC Decryption](https://upload.wikimedia.org/wikipedia/commons/6/66/Cbc_decryption.png)

In `set2_utils`, I create a CBC Cipher class that takes in a cipher and an IV. The `encrypt()` function will split the plaintext into blocks (usually size 16), and then do the encryption:

```
# Xor with previous block. First prev_xor_block is the IV.
pre_aes_block = xor(blocks[i], prev_xor_block)

# Encrypt with cipher algorithm
current_cipher_block = e.update(pre_aes_block)
prev_xor_block = current_cipher_block
ciphertext += current_cipher_block
```

The decryption takes each block of ciphertext, decrypts it, and XORs with the previous block of ciphertext to recover the plaintext.

```
for i in xrange(1, len(blocks)):
  decrypted_block = d.update(blocks[i])
  # print decrypted_block

  plaintext += xor(decrypted_block, blocks[i-1]) # where blocks[i-1] is the previous ciphertext block
```


I can verify I've done this correctly by decrypting 10.txt with a CBC Cipher with IV `'\x00'*16`.



## Challenge 11 An ECB/CBC detection oracle
This challenge asks us to detect whether we've encrypted a text with ECB or CBC, chosen at random.

Recall the properties of ECB vs CBC — ECB will take two identical plaintext blocks and produce two identical ciphertext blocks.

This is as simple as asking the oracle to encrypt a string that contains at least two consecutive blocks of identical characters. If the oracle chooses ECB, the ciphertext will have two adjacent identical blocks as well.

To ensure that we have at least two consecutive blocks of identical characters, we need to input at least 43 bytes. Why? Because the oracle pads the plaintext with 5-10 bytes, so we need to give some offset to ensure our identical plaintext blocks are properly aligned.

R = random_nfix
```
|--------16-----|
|-5-| |---11----| |--------16----| |--------16----|
RRRRR 00000000000 0000000000000000 0000000000000000  
```


## Challenge 12 Byte-at-a-time ECB decryption (Simple)

I have an oracle that produces `AES-128-ECB(your-string || unknown-string, random-key)`.

I can find unknown-string with this oracle. The idea is that,
1. First, I need to find the block size of the cipher.
2. Then, assuming I know it's using ECB, I can find the flag byte-by-byte. How? Since I control my-string, I can ensure each time that the oracle encrypts 15 bytes that I know + one unknown byte. I can then create a table of all possible ciphertexts of the 15 known bytes + 1 unknown byte, and compare the ciphertext the oracle returns to the ciphertexts in my table.


To find the block size, I feed in incrementing offsets to the oracle, until the ciphertext length increases. The size of the increase will be block_size, because of the padding.


Next, I need to get an offset of 15 known bytes to feed into the oracle. The first offset is just 15 filler variables, all A's.


```
U = unknown flag byte
K = known flag byte

Input to oracle, |-16-| bytes to be looked up in table:

          |----offset----|
          |--------16-----|
plaintext: AAAAAAAAAAAAAAAU UUUU.....

```


And I create a table of all possible ciphertexts of A...U.

```
for cand in candidates:
		# every candidate block of ciphertext is 16 bytes
		block_of_interest = oracle(offset+cand)[0:blocksize]
		cand_dict[block_of_interest] = cand
```

I then feed the block with the unknown byte to the oracle, padding with the same filler variables as my offset. Perform the table lookup.

```
oracle_block = oracle('A'*offset_len)[block_of_interest : block_of_interest + blocksize]


if oracle_block in cand_dict:
  next_byte = cand_dict[oracle_block]
  ```

At the next iteration, I decrease the number of filler variables by 1, since I have a known byte and want the next byte.


```
Input to oracle, |-16-| bytes to be looked up in table:
          |--------16-----|
plaintext: AAAAAAAAAAAAAAKU UUUU.....

```
When I have 16 known bytes in this manner, I no longer need filler variables in my offset; I can just use the previous 15 known bytes as my offset. Note that my lookup table can be populated with ciphertexts of 16 flag bytes.

Since I have 16-byte ciphertexts in my lookup table, I need to first align, then get the index of, the 16-byte block-of-interest that I'll look up in my table.

```
Input to oracle, |-16-| bytes to be looked up in table:

block_num:          0               1
                              block_of_interest
            alignment bytes  |--------16-----|
plaintext: AAAAAAAAAAAAAAAK  KKKKKKKKKKKKKKKU UUUU.....

```

Stopping after I run out of bytes, I find the answer is  
```
Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n
```

## Challenge 13  ECB cut-and-paste



## Challenge 14  Byte-at-a-time ECB decryption with random prefix

In this challenge, a random-length prefix is added to the attacker-controlled string, `AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)`. Thus, I need to know the length of the prefix to be able to conduct the same attack as Challenge 12.

Finding this length is not so hard.
1. First, I can find the block index of the last byte of the prefix with just two calls to the oracle.
2. Then, I find the offset of the last byte of the prefix within the last block.


```
ciphertext1 = prefix_oracle('')
ciphertext2 = prefix_oracle('A')
```

Because this is ECB mode, the first different block between `ciphertext1` and `ciphertext2` will be the last block of the prefix.

```
U = unknown flag byte
R = random prefix byte

plaintext1:
|--------16----||-enc to different value-|
RRRRRRRRRRRRRRRRRRRRUUUUUU....

plaintext2:
|--------16----||-enc to different value-|
RRRRRRRRRRRRRRRRRRRRAUUUUUU....
```

Now that I know what block the last byte of the prefix is in, `find_prefix_block_modulo_offset` finds the offset of the last byte of the prefix. I want to align two blocks of identical plaintext, to encrypt to two blocks of identical ciphertext. The amount of offset I use to align will tell me the offset of the prefix.

```
for i in xrange(0, blocksize):
  offset = 'A'*i + '\x00'*32
  ciphertext = prefix_oracle(offset)
```  

```
     |--offset-|
RRRRR00000000000 0000000000000000 0000000000000000 UUUUUU....

```
In the above example, the two 16-byte-aligned blocks of \x00's will encrypt to adjacent identical ciphertext, which I can detect.

Finally, `find_next_byte_with_prefix` will do the work. The offset is now
```
offset = 'A'*(extra_offset_for_prefix + offset_len)
```
, with offset_len always being 15 known bytes, as in Challenge 12.

The keys in my lookup table are no longer a fixed-length of blocksize — they include all known bytes now. Here, the len(offset) is **not always 15**, as in Challenge 12. Also, the length of my lookup table keys is **not always blocksize**; rather, the length of my keys increases with the number of known bytes. I could have implemented this more similarly to Challenge 12, which would have been less computationally expensive.

How do I produce ciphertext keys for my lookup table now? Here's what I feed into the oracle:
```
for cand in candidates:
  table_key = oracle(offset + knownbytes + cand)[prefix_location: prefix_location + len(offset) + len(knownbytes) + 1]
```


```
    |--lookup table key---------|
RRRRRAAAAAAAAAAA AAAAAAAAAAAAAAAU UUUU.....  
```

```
    |-------------------lookup table key---------|  
    |---offset-------|

extra_offset_for_prefix
    |          |
RRRRRAAAAAAAAAAA AAAAAKKKKKKKKKKK KKKKKKKKKKKKKKKU UUUU.....  

```

Calling `find_next_byte_with_prefix` byte-by-byte, I find the same flag as before.
 ```
Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n
```

## Challenge 15 PKCS#7 padding validation

Here's an easy one. We need only validate that the PKCS7 padding is correct.

```
byte = s[-1]
pad_length = unpack(byte, 'all')
if byte == 0 or s[-pad_length:] != byte * pad_length or byte == "":
```
I check if the last `pad_length` bytes of `s` are equal to the string of `byte` repeated `pad_length` times, as it should be in a properly padded string.  

## Challenge 16 CBC bitflipping attacks

We have a function that takes user input and url-encodes special characters, and we want to exploit the properties of CBC to allow us to insert the string ";admin=true;" without the ";" and "=" being validated out.

Recall that CBC takes each block of ciphertext and XORs it with the next block of decrypted ciphertext to recover the plaintext.

If I can modify at least two consecutive blocks of ciphertext, I can make the second block decrypt to whatever I want.

I know that `\x00 ^ \x59 = ;` and `\x00 ^ \x61 = '='` from [ascii chart](http://www.nthelp.com/ascii.htm).

```

user-controlled input:
      0                     1
AAAAAAAAAAAAAAAA  \x00admin\x00true\x00

ciphertext:
XXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXX

modified ciphertext:
\x59XXXXX\x61XXXX\x59XXXX XXXXXXXXXXXXXXXX

In XOR step of CBC decryption, the 2nd block would normally XOR to recover \x00admin\x00true\x00, but now that I've done an additional XOR on three bytes by modifying ciphertext, the 2nd block XORs to a plaintext of \x59admin\x61true\x59.
```

Done with set2!
