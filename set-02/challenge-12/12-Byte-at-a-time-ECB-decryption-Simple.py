#!/usr/bin/python3

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

from my_cryptopals_utils import * 

# This challenge consists in breaking 
# Byte-at-a-time ECB decryption 

def __main__():

    print("[+] Cryptopals 12 - Byte-at-a-time ECB decryption (Simple)\n")

    # It works!
    # print(consistent_key_ecb_encryption("Homem de Pedra"))

    # 1. Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway. 
    print("[+] Searching block size...")
    probable_block_size = find_block_size(consistent_key_ecb_encryption)
    print("[+] Probable block size is: {} bytes".format(probable_block_size))

    # 2. Detect that the function is using ECB. You already know, but do this step anyways. 
    print("[+] Detecting encryption mode...")

    # 2.1. Oracle calibration
    cbc_boundary = 0
    for i in range(0, 100):
        mode, ciphertext = encryption_oracle("qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
        if mode == MODE_CBC:
            repeating_blocks_count = count_repeating_blocks(ciphertext)
            if cbc_boundary < repeating_blocks_count:
                cbc_boundary = repeating_blocks_count

    # 2.2. Mode detection 
    ciphertext = consistent_key_ecb_encryption("qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
    detected_mode = "ECB" if count_repeating_blocks(ciphertext) > cbc_boundary else "CBC"
    print("[+] Detection oracle yields: {}\n".format(detected_mode))

    # 3. TODO 

__main__() 
