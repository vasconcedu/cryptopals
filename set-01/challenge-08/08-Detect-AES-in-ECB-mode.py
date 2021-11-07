#!/usr/bin/python3

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

from my_cryptopals_utils import * 

# This challenge consists in detecting 
# AES in ECB mode. One of the strings contained
# in 8.txt has been encrypted using AES-ECB. 
# The goal is to find it 

# Tip: Remember that the problem with ECB is 
# that it is stateless and deterministic; the same
# 16 byte plaintext block will always produce 
# the same 16 byte ciphertext. 

# Rationale for solution: this means there
# will be a greater absolute amount of repeating 
# 16-byte blocks on ciphertext produced in ECB mode
# than on randomly generated bit arrays => count 
# occurrences of repeating blocks and take the one
# with the greatest absolute amount as the 
# ciphertext in question (i.e. best candidate)

print("[+] Cryptopals 08 - Detect AES in ECB mode\n")

most_repetitions = 0
most_repetitions_line = "" 

for line in open('8.txt', 'r').readlines():

    line = line.strip()

    raw_bytes_line = hex_to_raw_bytes(line)

    # Compute repetitions 
    repetitions = count_repeating_blocks(raw_bytes_line)

    if repetitions > most_repetitions:
        most_repetitions = repetitions
        most_repetitions_line = line

print("[+] Best candidate is: {}\n".format(most_repetitions_line))
print("[+] Number of repeated bytes: {}\n".format(most_repetitions))
