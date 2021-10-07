#!/usr/bin/python3

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

from my_cryptopals_utils import * 

# This challenge consists in 
# implementing repeating-key XOR

INPUT_PLAINTEXT = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
INPUT_KEY = "ICE"

ANSWER_CIPHERTEXT = """0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"""

def __main__():

    print("[+] Cryptopals 05 - Implement repeating-key XOR\n")

    print("[+] Running tests...\n")

    print("[+] Test #1: encryption. E({}, {}) = {}, matches answer ciphertext? {}".format(
        INPUT_PLAINTEXT,
        INPUT_KEY,
        raw_bytes_to_hex(RepeatingKeyXOR().encrypt(bytes(INPUT_PLAINTEXT, 'utf-8'), bytes(INPUT_KEY, 'utf-8'))),
        raw_bytes_to_hex(RepeatingKeyXOR().encrypt(bytes(INPUT_PLAINTEXT, 'utf-8'), bytes(INPUT_KEY, 'utf-8'))) == ANSWER_CIPHERTEXT
    ))

    print("[+] Test #2: decryption. D({}, {}) = {}, matches input plaintext? {}".format(
        ANSWER_CIPHERTEXT,
        INPUT_KEY,
        RepeatingKeyXOR().decrypt(hex_to_raw_bytes(ANSWER_CIPHERTEXT), bytes(INPUT_KEY, 'utf-8')).decode('utf-8'),
        RepeatingKeyXOR().decrypt(hex_to_raw_bytes(ANSWER_CIPHERTEXT), bytes(INPUT_KEY, 'utf-8')).decode('utf-8') == INPUT_PLAINTEXT
    ))

__main__()
