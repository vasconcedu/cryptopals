#!/usr/bin/python3

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

from my_cryptopals_utils import * 

# This challenge consists in implementing
# AES CBC mode using ECB instead of simply 
# specifying CBC mode on cipher configuration

# For testing: file 10.txt is intelligible 
# when decrypted against "YELLOW SUBMARINE"
# with an IV of all ASCII 0 (\x00\x00\x00 &c)

TEST_PLAINTEXT = "The Art of Manliness" # Additional test string 
TEST_KEY = "YELLOW SUBMARINE"
TEST_IV = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

def __main__():

    print("[+] Cryptopals 10 - Implement CBC mode\n")

    print("[+] Running tests...\n")

    # Test #1
    ciphertext = encrypt_plaintext_in_cbc_mode(TEST_PLAINTEXT, TEST_KEY, TEST_IV)
    print("[+] Test #1: Encrypt string '{}': {}".format(bytes(TEST_PLAINTEXT, 'utf-8'), raw_bytes_to_base_64(ciphertext)))

    # Test #2
    plaintext = decrypt_plaintext_in_cbc_mode(ciphertext, TEST_KEY, TEST_IV)
    print("[+] Test #2: Decrypt string '{}': {}".format(raw_bytes_to_base_64(ciphertext), plaintext))

    # Test #3
    file_ciphertext = open('10.txt', 'r').read()
    file_plaintext = decrypt_plaintext_in_cbc_mode(base_64_to_raw_bytes(file_ciphertext), TEST_KEY, TEST_IV)
    print("[+] Test #3: Decrypt file: {}".format(bytes.decode(file_plaintext, 'utf-8')))

__main__()
