#!/usr/bin/python3

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

from my_cryptopals_utils import * 

# This challenge consists in implementing
# PKCS#7 padding

SAMPLE_PLAINTEXT_INPUT = "YELLOW SUBMARINE"
SAMPLE_PLAINTEXT_OUTPUT = "YELLOW SUBMARINE\x04\x04\x04\x04"

print("[+] Cryptopals 09 - Implement PKCS#7 padding\n")

padded_plaintext = pkcs_7_padding(SAMPLE_PLAINTEXT_INPUT, 20)

print("[+] Padded plaintext (raw bytes) is: {}\n".format(bytes(padded_plaintext, 'utf-8')))
print("[+] Matches expected output? {}".format(padded_plaintext == SAMPLE_PLAINTEXT_OUTPUT))
