#!/usr/bin/python3

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

from my_cryptopals_utils import * 

PLAINTEXT = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"

def __main__():

    print("[+] Cryptopals 11 - An ECB/CBC detection oracle\n")

    print("[+] Test #1: Generate pseudo-random key: {}\n".format(generate_random_key()))

    print("[+] Test #2: Encryption oracle:\n")

    print("    [+] Calibrating encryption oracle...")

    # Oracle calibration
    cbc_boundary = 0
    for i in range(0, 100):
        mode, ciphertext = encryption_oracle(PLAINTEXT)
        if mode == MODE_CBC:
            repeating_blocks_count = count_repeating_blocks(ciphertext)
            if cbc_boundary < repeating_blocks_count:
                cbc_boundary = repeating_blocks_count

    for i in range(0, 10):
        mode, ciphertext = encryption_oracle(PLAINTEXT)
        print("    [+] Mode: {}, Ciphertext: {}".format("CBC" if mode == MODE_CBC else "ECB", ciphertext))
        detected_mode = "ECB" if count_repeating_blocks(ciphertext) > cbc_boundary else "CBC"
        print("    [+] Detection oracle yields: {}\n".format(detected_mode))

__main__()
