#!/usr/bin/python3

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

from my_cryptopals_utils import * 

# This challenge consists in 
# decrypting AES in ECB mode, 
# ciphertext is 7.txt. 

# Challenge tip: Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

INPUT_KEY = "YELLOW SUBMARINE"

# TODO 
