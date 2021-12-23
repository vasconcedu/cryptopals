#!/usr/bin/python3

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

import time
from my_cryptopals_utils import * 

# This challenge consists in breaking 
# Byte-at-a-time ECB decryption (with both
# append and prepend)

MODE_ORACLE_PLAINTEXT = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"

def __main__():

    print("[+] Cryptopals 14 - Byte-at-a-time ECB decryption (Harder)\n")

    print("[+] Test #1: Check if encryption function works:\n")

    for i in range(1, 10):
        print("    [+] Round #{}: {}".format(i, consistent_key_ecb_encryption_harder("allyourbasearebelongtous")))

    print("\n[+] Test #2: Attack:\n")

    # Step 1. Find block size

    print("[+] Searching block size...")
    probable_block_size = find_block_size(consistent_key_ecb_encryption)
    print("[+] Probable block size is: {} bytes\n".format(probable_block_size))

    # Step 2. Infer encryption mode: 

    print("[+] Detecting encryption mode...")

    # 2.1. Oracle calibration

    cbc_boundary = 0
    for i in range(0, 100):
        mode, ciphertext = encryption_oracle(MODE_ORACLE_PLAINTEXT)
        if mode == MODE_CBC:
            repeating_blocks_count = count_repeating_blocks(ciphertext)
            if cbc_boundary < repeating_blocks_count:
                cbc_boundary = repeating_blocks_count

    # 2.2. Mode detection 

    ciphertext = consistent_key_ecb_encryption(MODE_ORACLE_PLAINTEXT)
    detected_mode = "ECB" if count_repeating_blocks(ciphertext) > cbc_boundary else "CBC"
    print("[+] Detection oracle yields: {}\n".format(detected_mode))

    # 2.3. Cryptanalysis

    # TODO 

__main__()
