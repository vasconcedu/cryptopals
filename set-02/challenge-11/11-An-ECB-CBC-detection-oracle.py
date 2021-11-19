#!/usr/bin/python3

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

from my_cryptopals_utils import * 

print("[+] Cryptopals 11 - An ECB/CBC detection oracle\n")

print("[+] Test #1: Generate pseudo-random key: {}\n".format(generate_random_key()))

# TODO 
