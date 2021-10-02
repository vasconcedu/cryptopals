#!/usr/bin/python3

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

from my_cryptopals_utils import * 

# This challenge consists in implementing 
# a bitwise XOR of two input buffers

# Test vector 
INPUT_A = "1c0111001f010100061a024b53535009181c"
INPUT_B = "686974207468652062756c6c277320657965"
ANSWER_C = "746865206b696420646f6e277420706c6179"

def __main__():
    # test_my_cryptopals_utils()

    print("[+] Cryptopals 02 - Fixed XOR")
    print("[+] Testing...\n")
    print("[+] Input A is: {}".format(INPUT_A))
    print("[+] Input B is: {}".format(INPUT_B))
    print("[+] Answer C is: {}\n".format(ANSWER_C))

    print("[+] Test #1: (Input A) XOR (Input B) is: {}, matches answer? {}".format(
        raw_bytes_to_hex(
            xor(
                hex_to_raw_bytes(INPUT_A),
                hex_to_raw_bytes(INPUT_B)
            )
        ),
        raw_bytes_to_hex(
            xor(
                hex_to_raw_bytes(INPUT_A),
                hex_to_raw_bytes(INPUT_B)
            )
        ) == ANSWER_C
    ))

__main__()
