#!/usr/bin/python3

from Crypto.Cipher import AES

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

from my_cryptopals_utils import * 

# This challenge consists in 
# decrypting AES in ECB mode, 
# ciphertext is 7.txt. 

# Challenge tip: Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

INPUT_KEY = "YELLOW SUBMARINE"
INPUT_CIPHERTEXT = open('7.txt', 'r').read()

print("[+] Cryptopals 07 - AES in ECB mode\n")

print("[+] Decrypting...\n")

print("[+] Plaintext is:\n")

plaintext = AES.new(INPUT_KEY, AES.MODE_ECB).decrypt(base_64_to_raw_bytes(INPUT_CIPHERTEXT))

print(plaintext)
