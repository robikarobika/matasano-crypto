# Set 1 writeup

## Challenge 1.1 Convert hex to base64
The first challenge is pretty straightforward, using python's built-in functions or [pwntools](https://github.com/Gallopsled/pwntools), as I use heavily in these challenges.

The functions `a2b_hex`, `unhexlify`, and `''.decode("hex")` all do the same thing. They take in an ascii string of the form "[0-9a-f]\*" and decode it. The string decodes to
`I'm killing your brain like a poisonous mushroom`.

We can then use `binascii.b2a_base64()` to convert the byte string to a base64 representation.

## Challenge 1.2 Fixed XOR

This challenge uses iterators to do a fixed-length xor.

The `chr()` function takes an ASCII integer code in the range 0-255 and returns a character string.

The `ord()` function does the inverse, taking a character and returning its integer. We want to xor these integers.

Thus, `''.join([chr(ord(i)^ord(j)) for i, j in zip(s1, s2)])` will first xor the integers of each character of the input strings with `ord()`. Then it will convert back into a character string with `chr()`.

## Challenge 1.3 Single-byte XOR cipher

Extending the last challenge, we can create a variable-length input xor function. Or, we can use pwntools `xor()`.

I iterate through all 255 possible single character xor keys, scoring each decrypted word based on character frequency.
```
for c in result:
  c = c.lower()
  if c in character_frequency:
    word_score += character_frequency[c]

cand_words.append((result, word_score, char))
```



## Challenge 1.4 Detect single-character XOR

This challenge asks us to find which of the 60-character strings in the file has been encrypted by single-character XOR.

Using the `find_singlechar_key_xor` utility function created in the last challenge, I can iterate through all the file strings and find the possible single-character xor key and word score of each line.

The line turns out to decode to 'Now that the party is jumping\n', xored against the byte 5.


## Challenge 1.5 Implement repeating-key XOR

This is a cop-out. Pwntools implements repeating-key xor in its `utils.fiddling` library.

We can use python [itertools](https://docs.python.org/2/library/itertools.html) for this as well,
```
	return ''.join([chr(ord(i)^ord(j)) for i, j in it.izip(s1, it.cycle(s2))])
```

## Challenge 1.6 Break repeating-key XOR

This challenge asks us to solve repeating-key xor, aka the Vigenere cipher.

There are several steps to doing this.
1. First, we need to find the xor key length. the period of the cipher.
2. Next, we need to find the key character-by-character, using the single-byte xor cipher we made in Challenge 1.3.

In the first step I calculate the Hamming distance (number of diff bits between two strings) of two consecutive ciphertext blocks (of some guessed length). The correct keylength will create blocks of minimum Hamming distance.

The challenge tells us to try values from 2 to 40 for the guessed key length. I calculate the hamming distance of all combinations of 4 blocks.
```
pairs = list(it.combinations(blocks, 2))
hamsum = it.starmap(hamming, pairs)
```

`it.starmap` computes the `hamming` function using arguments obtained from the iterable `pairs`.
I then normalize the Hamming distance for keysize.
```
normalized = float(reduce(lambda x, y: x+y, hamsum))/keysize
```
and find the keylength with the minimum normalized hamming distance is 29.

The second step is to find the key, character-by-character. I split the ciphertext into blocks of len(keysize) and transpose them, so that I have a list of all the 1st, 2nd, etc... chars of each block. Each of these transposed messages has been single-char xored, so I can just find each single-char key and concatenate the chars to get the full xor key.

![Vigenere cipher](writeup_resources/vigenere.png)

```
blocks = [x[i:i+keysize] for i in range(0, len(x), keysize)]

blocks = it.izip_longest(*blocks, fillvalue='0')

block_list = [''.join(msg) for msg in blocks]

char_freqs = [find_singlechar_key_xor(''.join(msg))[2]
for msg in block_list]
```

I need to use `izip_longest` because the last block is shorter than the others, and `izip_longest` pads the shortest elements of the iterable.

The key made by joining the single-char keys is `Terminator X: Bring the noise`.


## Challenge 1.7 AES in ECB mode

This challenge introduces the AES block cipher and the ECB mode. The ECB mode is problematic because it is stateless and deterministic — the same block of plaintext will encrypt to the same ciphertext.

I use the [`cryptography`](https://cryptography.io) module in Python because it's being actively developed, although the PyCrypto library is more popular.

You initialize AES, a symmetric cipher, with
```
cipher = Cipher(algorithm = algorithms.AES("YELLOW SUBMARINE"), mode = modes.ECB(), backend=default_backend())
```
.

To decrypt text, you use a `decryptor` object and the update() and finalize() methods.

```
d = cipher.decryptor()
decrypted_text = d.update(file) + d.finalize()
```

## Challenge 1.8 Detect AES in ECB mode

Because ECB is deterministic, I can detect which of the strings in 8.txt is encrypted using ECB. The properties of the plaintext, such as low Hamming distance, will remain in the ciphertext. Thus, I can use minimum Hamming distance to find the correct line, similar to Challenge 6.

I create a scoring function, `hamming_score_line(line)`, which will return the hamsum of a line of ciphertext.

```
min_line_num = min(lines, key=hamming_score_line)[0]
```

will be the correct answer, 133.

## References

[1] [pwntools](https://github.com/Gallopsled/pwntools)
