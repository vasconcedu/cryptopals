#!/usr/bin/python3

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

from my_cryptopals_utils import * 

# This challenge consists in converting 
# an input hex string into its corresponding 
# base64 representation

# Notwithstanding, I have also implemented 
# a few other methods which might be useful later on 

# Check out answers on 
# ../my_cryptopals_utils.py

# Test vector 
INPUT_HEX = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
ANSWER_BASE64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

# Main function: tests the above methods 
def __main__():
    print("[+] Cryptopals 01 - Convert hex to Base64")
    print("[+] Testing...\n")
    print("[+] Hex input is: {}".format(INPUT_HEX))
    print("[+] Base64 answer is: {}\n".format(ANSWER_BASE64))

    print("[+] Test #1: hex input to raw bytes: {}".format(
            str(hex_to_raw_bytes(INPUT_HEX))
        ))
    
    print("[+] Test #2: raw bytes back to hex (input): {}, matches original input? {}".format(
            str(raw_bytes_to_hex(hex_to_raw_bytes(INPUT_HEX))),
            raw_bytes_to_hex(hex_to_raw_bytes(INPUT_HEX)) == INPUT_HEX
        ))

    print("[+] Test #3: hex to Base64: {}, matches Base64 answer? {}".format(
        hex_to_base_64(INPUT_HEX),
        hex_to_base_64(INPUT_HEX) == ANSWER_BASE64
    ))

    print("[+] Test #4: Base64 to hex: {}, matches original input? {}".format(
        base_64_to_hex(ANSWER_BASE64),
        base_64_to_hex(ANSWER_BASE64) == INPUT_HEX
    ))

    print("[+] Test #5: Base64 to raw bytes: {}".format(
        base_64_to_raw_bytes(ANSWER_BASE64)
    ))

    print("[+] Test #6: raw bytes back to Base64: {}, matches Base64 answer? {}".format(
        raw_bytes_to_base_64(hex_to_raw_bytes(INPUT_HEX)),
        raw_bytes_to_base_64(hex_to_raw_bytes(INPUT_HEX)) == ANSWER_BASE64
    ))

__main__()
