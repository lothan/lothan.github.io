---
title: "Day 09 - Santas Secrets"
date: 2021-12-19T17:35:43-06:00
---

## Challenge Description

Santa built a service to allow elves to encrypt secret data without having access to the keys.

[(Download Files)](files/server.py)

## Overview

We're given a python webserver with an encrypted flag and the key that was used to encrypt it, but we can only read the encrypted flag and use the key to encrypt data, not read the key itself. Using a bug in python data encoding, we can overwrite successive bytes of the key, use it to encrypt known data, and brute force the entire key, using it to decrypt the flag.  

## Writeup

The encryption server allows for a few commands, `write_data`, `read_data`, `write_key`, and `encrypt`. All operate on indexed 16-byte keyslots and dataslots, so here are a few example commands:

* To write ascii data to dataslot 1

`write_data 1 16_bytes_of_data ascii`

* To read from dataslot `1`:

`read_data 1`

* To write a secret key in hex to keyslot 4 (different from dataslot 4)

`write_key 4 7365637265745f6b65795f636f646521 hex`

* To encrypt using keyslot 4, the data in dataslot 1 and saving it in dataslot 0

`encrypt 4 1 0`

The initial state of the machine is set up using these commands. There's a random 16 byte key in keyslot 5 and our flag is encrypted using that key in dataslots 0 and 1.

```python
        se.run_cmd(f"write_key 5 {os.urandom(SLOT_SIZE).hex()} hex")
        se.run_cmd(f"write_data 0 {FLAG[:16]} ascii")
        se.run_cmd(f"write_data 1 {FLAG[16:]} ascii")
        se.run_cmd(f"encrypt 5 0 0")
        se.run_cmd(f"encrypt 5 1 1")
```

Looking at how the server handles these commands and the first thing that stands out is that all the keyslots and dataslots are two big byte arrays, rather than, say, a list of bytes. 

```python
NUM_SLOTS = 8
SLOT_SIZE = 16

class SecurityEngine():
        def __init__(self):
                self.keyslots  = bytearray(SLOT_SIZE * NUM_SLOTS)
                self.dataslots = bytearray(SLOT_SIZE * NUM_SLOTS)
```

The next strangeness is that you can write keys using hex or ascii, but the server doesn't use `data.encode("ASCII")`, just `data.encode()`. Python uses UTF-8 by default for `.encode()` so it is possible to write a key that is longer than 16 bytes by using unicode characters. We can use this bug to brute force the key in keyslot 5 and get our flag. 

```python
        def cmd_write_key(self, slot_idx, data, encoding):
                """write data to a chosen keyslot"""

                try: slot_idx = self._parse_slot_idx(slot_idx)
                except: return "ERROR: Invalid index"

                try: data = self._parse_data_string(data, encoding)
                except: return "ERROR: Invalid data length or encoding"

                self.keyslots[SLOT_SIZE*slot_idx:SLOT_SIZE*slot_idx+len(data)] = data

                return f"keyslot[{slot_idx}] <= {data.hex()}"
                
        def _parse_data_string(self, data, encoding):
                if encoding == "hex":
                        if len(data) != SLOT_SIZE * 2:
                                raise Exception("Invalid data length")
                        return bytes.fromhex(data)
                elif encoding == "ascii":
                        if len(data) != SLOT_SIZE:
                                raise Exception("Invalid data length")
                        return data.encode()
                raise Exception("Invalid encoding")
```

To brute force, we overwrite all but one byte of the key and encrypt a known plaintext with it. Then we can brute force the last byte by trying all 256 possible bytes and see which produces the same ciphertext. Knowing the last byte, we can brute force the second to last byte, on and on.

Obviously we can't un-overwrite the key, so we first send our commands, overwriting one byte of the key at a time, then brute force the key from the output.

```
> cat msg
read_data 0
read_data 1
encrypt 5 2 3
read_data 2
write_key 4 ϏAAAAAAAAAAAAAAA ascii
encrypt 5 2 3
read_data 2
write_key 4 ϏϏAAAAAAAAAAAAAA ascii
encrypt 5 2 3
read_data 2
write_key 4 ϏϏϏAAAAAAAAAAAAA ascii
encrypt 5 2 3
read_data 2
write_key 4 ϏϏϏϏAAAAAAAAAAAA ascii
encrypt 5 2 3
read_data 2
write_key 4 ϏϏϏϏϏAAAAAAAAAAA ascii
encrypt 5 2 3
read_data 2
write_key 4 ϏϏϏϏϏϏAAAAAAAAAA ascii
encrypt 5 2 3
read_data 2
write_key 4 ϏϏϏϏϏϏϏAAAAAAAAA ascii
encrypt 5 2 3
read_data 2
write_key 4 ϏϏϏϏϏϏϏϏAAAAAAAA ascii
encrypt 5 2 3
read_data 2
write_key 4 ϏϏϏϏϏϏϏϏϏAAAAAAA ascii
encrypt 5 2 3
read_data 2
write_key 4 ϏϏϏϏϏϏϏϏϏϏAAAAAA ascii
encrypt 5 2 3
read_data 2
write_key 4 ϏϏϏϏϏϏϏϏϏϏϏAAAAA ascii
encrypt 5 2 3
read_data 2
write_key 4 ϏϏϏϏϏϏϏϏϏϏϏϏAAAA ascii
encrypt 5 2 3
read_data 2
write_key 4 ϏϏϏϏϏϏϏϏϏϏϏϏϏAAA ascii
encrypt 5 2 3
read_data 2
write_key 4 ϏϏϏϏϏϏϏϏϏϏϏϏϏϏAA ascii
encrypt 5 2 3
read_data 2
write_key 4 ϏϏϏϏϏϏϏϏϏϏϏϏϏϏϏA ascii
encrypt 5 2 3
read_data 2
> nc santas-secrets.advent2021.overthewire.org 1209 < msg > output.txt
> head output.txt
5e9c669210723542bf58239a03df5572
57e96709a95ddb8e520158efcb2eddc5
dataslot[2] <= AES(key=keyslot[5], data=dataslot[3])
f93dab5aeeb7314e21995b8ea81c17af
keyslot[4] <= cf8f414141414141414141414141414141
dataslot[2] <= AES(key=keyslot[5], data=dataslot[3])
29b2f8c5a47cd028aefbe7fac8f6c03f
keyslot[4] <= cf8fcf8f4141414141414141414141414141
dataslot[2] <= AES(key=keyslot[5], data=dataslot[3])
b91e052ad1f88222b3ec9d8aab39e5c1
```

Using the following script to brute force the key:

```python
from Cryptodome.Cipher import AES  # pip3 install pycryptodomex

with open("output.txt") as f:
    lines = f.readlines()

flag1 = bytes.fromhex(lines.pop(0).strip())
flag2 = bytes.fromhex(lines.pop(0).strip())

ciphertexts = []
keyparts = ['']
for i, l in enumerate(lines):
    if i % 3 == 0:
        continue
    if i % 3 == 1:
        ciphertexts.insert(0, l.strip())
    if i % 3 == 2:
        keyparts.insert(0,l. strip().split(" <= ")[1][32:]) # sorry it's ugly

print("ciphertexts:", len(ciphertexts))
for ct in ciphertexts:
    print(ct)

print("keyparts", len(keyparts))
for kp in keyparts:
    print(kp)

i = 0
key = b''
plaintext = bytes.fromhex('00000000000000000000000000000000')
while len(key) != 16:
    print("testing against ct:", ciphertexts[i])
    print("with keypart", keyparts[i])
    for b in range(256):
        test_key = bytes.fromhex(keyparts[i]) + bytes([b]) + key
        # print("keypart:", test_key.hex())
        ciphertext = AES.new(key=test_key, mode=AES.MODE_ECB).encrypt(plaintext)
        if ciphertext == bytes.fromhex(ciphertexts[i]):
            print("found byte of key: ", bytes([b]).hex())
            # print("with ciphertext:", ciphertext.hex())
            i += 1
            key = bytes([b]) + key
            break
    print("current key:", key.hex())

print("flag: ")
print(AES.new(key=key, mode=AES.MODE_ECB).decrypt(flag1).decode(), end="")
print(AES.new(key=key, mode=AES.MODE_ECB).decrypt(flag2).decode(), end="")
```

```
> python3 brute-key.py
ciphertexts: 16
3bf33bfad227f6c0c2f47df77a449561
faa78fb2cc9e8e35115cc4fa21cf39f1
12b398d692afdf8d0e4465f53c8a95ec
f5fca8bcb1b07430a89982db45c7e18d
5bed5eb82a3d5023bbfaaeff3d8e0caf
5566b05dd140266afb814ef1f74ae4cf
c5778daf79147119b4c040dac34973fa
e9ef830fae37bca4d328664cae648c39
c0560043fa597e22861b577d19af555c
cb629a7a857f7bf3ba974db50b87b662
ded2b0769b207fc3f0ee2f38932c9218
4ba0e0968a152cff03f12ebbc6f06af4
2f09b0fc1f54ca4064e16a98e97acc1a
b91e052ad1f88222b3ec9d8aab39e5c1
29b2f8c5a47cd028aefbe7fac8f6c03f
f93dab5aeeb7314e21995b8ea81c17af
keyparts 16
cf8fcf8fcf8fcf8fcf8fcf8fcf8f41
cf8fcf8fcf8fcf8fcf8fcf8f4141
cf8fcf8fcf8fcf8fcf8f414141
cf8fcf8fcf8fcf8f41414141
cf8fcf8fcf8f4141414141
cf8fcf8f414141414141
cf8f41414141414141
4141414141414141
41414141414141
414141414141
4141414141
41414141
414141
4141
41

testing against ct: 3bf33bfad227f6c0c2f47df77a449561
with keypart cf8fcf8fcf8fcf8fcf8fcf8fcf8f41
found byte of key:  13
current key: 13
testing against ct: faa78fb2cc9e8e35115cc4fa21cf39f1
with keypart cf8fcf8fcf8fcf8fcf8fcf8f4141
found byte of key:  da
current key: da13
testing against ct: 12b398d692afdf8d0e4465f53c8a95ec
with keypart cf8fcf8fcf8fcf8fcf8f414141
found byte of key:  9d
current key: 9dda13
testing against ct: f5fca8bcb1b07430a89982db45c7e18d
with keypart cf8fcf8fcf8fcf8f41414141
found byte of key:  9a
current key: 9a9dda13
testing against ct: 5bed5eb82a3d5023bbfaaeff3d8e0caf
with keypart cf8fcf8fcf8f4141414141
found byte of key:  07
current key: 079a9dda13
testing against ct: 5566b05dd140266afb814ef1f74ae4cf
with keypart cf8fcf8f414141414141
found byte of key:  d4
current key: d4079a9dda13
testing against ct: c5778daf79147119b4c040dac34973fa
with keypart cf8f41414141414141
found byte of key:  a7
current key: a7d4079a9dda13
testing against ct: e9ef830fae37bca4d328664cae648c39
with keypart 4141414141414141
found byte of key:  30
current key: 30a7d4079a9dda13
testing against ct: c0560043fa597e22861b577d19af555c
with keypart 41414141414141
found byte of key:  15
current key: 1530a7d4079a9dda13
testing against ct: cb629a7a857f7bf3ba974db50b87b662
with keypart 414141414141
found byte of key:  93
current key: 931530a7d4079a9dda13
testing against ct: ded2b0769b207fc3f0ee2f38932c9218
with keypart 4141414141
found byte of key:  01
current key: 01931530a7d4079a9dda13
testing against ct: 4ba0e0968a152cff03f12ebbc6f06af4
with keypart 41414141
found byte of key:  54
current key: 5401931530a7d4079a9dda13
testing against ct: 2f09b0fc1f54ca4064e16a98e97acc1a
with keypart 414141
found byte of key:  e4
current key: e45401931530a7d4079a9dda13
testing against ct: b91e052ad1f88222b3ec9d8aab39e5c1
with keypart 4141
found byte of key:  62
current key: 62e45401931530a7d4079a9dda13
testing against ct: 29b2f8c5a47cd028aefbe7fac8f6c03f
with keypart 41
found byte of key:  9f
current key: 9f62e45401931530a7d4079a9dda13
testing against ct: f93dab5aeeb7314e21995b8ea81c17af
with keypart 
found byte of key:  d9
current key: d99f62e45401931530a7d4079a9dda13
flag: 
AOTW{n0oO_d0nt_0v3rfl0w_my_bufs}
```