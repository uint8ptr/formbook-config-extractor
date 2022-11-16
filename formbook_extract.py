#!/usr/bin/env python
# https://github.com/JPCERTCC/MalConfScan/blob/master/utils/formbookscan.py

import re
from struct import pack, unpack
from sys import argv

from Crypto.Hash import SHA

from formbook_decryption import FormBookDecryption

CONFIG_PATTERN = '83 c4 0c 6a 14 e8 ? ? ? ? 83 c0 02 50 8d ? ? 51 e8 ? ? ? ? 83 c4 0c 6a 14 e8 ? ? ? ? 83 c0 02 50 8d ? ? 52'
HASHES_PATTERN = '68 ? ? 00 00 8d ? ? ? 00 00 e8'
STRINGS_PATTERN = '6a 00 50 c6 85 ? ? ? ? 00 e8 ? ? ? ? 83 c4 0c 68 ? ? 00 00 e8'

u32 = lambda x: unpack('<I', x)[0]

def find_pattern(pattern, data):
    s = b''

    for token in pattern.split():
        if token == '?': s += b'.'
        else: s += b'\\x' + token.encode()

    regex = re.compile(s, re.DOTALL)
    result = re.search(regex, data)

    if result != None:
        return result.start()

def sha1_revert(digest):
    tuples = unpack('<IIIII', digest)
    output_hash = bytearray()
    for item in tuples:
        output_hash += pack('>I', item)
    return output_hash

def formbook_compute_sha1(input_buffer):
    sha1 = SHA.new()
    sha1.update(input_buffer)
    return sha1_revert(sha1.digest())

fname = sys.argv[1]

with open(fname, 'rb') as f:
    data = f.read()

offset = find_pattern(CONFIG_PATTERN, data) + 6
key1_offset = u32(data[offset:offset+4]) + offset + 11
key1 = data[key1_offset:key1_offset+40]
offset += 23

key2_offset = u32(data[offset:offset+4]) + offset + 11
key2 = data[key2_offset:key2_offset+40]
offset += 21

# config data
config_size = u32(data[offset:offset+4])
offset += 5

config_offset = u32(data[offset:offset+4]) + offset + 11
config = data[config_offset:config_offset + (config_size*2)]
offset += 33

url_size = data[offset]

# strings data
offset = find_pattern(STRINGS_PATTERN, data) + 19
strings_size = u32(data[offset:offset+4])
offset += 5

strings_offset = u32(data[offset:offset+4]) + offset + 11
strings_data = data[strings_offset:strings_offset + (strings_size*2)]

# hashes data
offset = find_pattern(HASHES_PATTERN, data)
offset += 1

hashes_size = u32(data[offset:offset+4])
offset += 11

hashes_offset = u32(data[offset:offset+4]) + offset + 11
hashes_data = data[hashes_offset:hashes_offset + (hashes_size*2)]

# decrypt buffers
fd = FormBookDecryption()
rc4_key1 = fd.decrypt_func1(key1, 20)
rc4_key2 = fd.decrypt_func1(key2, 20)

encbuf2_s1 = fd.decrypt_func1(hashes_data, hashes_size)
encbuf8_s1 = fd.decrypt_func1(config, config_size)
encbuf9_s1 = fd.decrypt_func1(strings_data, strings_size)

encbuf2_s1_key = formbook_compute_sha1(encbuf8_s1)
encbuf2_s2_key = formbook_compute_sha1(rc4_key2)
encbuf8_s1_key = formbook_compute_sha1(encbuf9_s1)

encbuf2_s2 = fd.decrypt_func2(encbuf2_s1, encbuf2_s1_key)
encbuf8_s2 = fd.decrypt_func2(encbuf8_s1, encbuf8_s1_key)

n = 1
for i in range(config_size):
    enc_c2_uri = fd.decrypt_func2(encbuf8_s2[i:i + url_size], rc4_key2)
    c2_uri = fd.decrypt_func2(enc_c2_uri, rc4_key1)

    if c2_uri.startswith(b'www'):
        print(f'C&C URI {n}: {repr(c2_uri[:-1].decode())}')
        n += 1

encrypted_hashes_array = fd.decrypt_func2(encbuf2_s2, encbuf2_s2_key)
rc4_key_pre_final = formbook_compute_sha1(encrypted_hashes_array)
rc4_key_final = fd.decrypt_func2(rc4_key2, rc4_key_pre_final)

offset = 0
i = 0
while offset < len(encbuf9_s1):
    str_len = encbuf9_s1[offset]
    offset += 1
    dec_str = fd.decrypt_func2(encbuf9_s1[offset:offset + str_len], rc4_key_final)
    print(f'Encoded string {i}: {repr(dec_str[:-1].decode())}')
    offset += str_len
    i += 1