#!/usr/bin/python3

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

from my_cryptopals_utils import * 

# This challenge consists in breaking 
# Byte-at-a-time ECB decryption 

MODE_ORACLE_PLAINTEXT = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"

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
        mode, ciphertext = encryption_oracle(MODE_ORACLE_PLAINTEXT)
        if mode == MODE_CBC:
            repeating_blocks_count = count_repeating_blocks(ciphertext)
            if cbc_boundary < repeating_blocks_count:
                cbc_boundary = repeating_blocks_count

    # 2.2. Mode detection 
    ciphertext = consistent_key_ecb_encryption(MODE_ORACLE_PLAINTEXT)
    detected_mode = "ECB" if count_repeating_blocks(ciphertext) > cbc_boundary else "CBC"
    print("[+] Detection oracle yields: {}\n".format(detected_mode))

    # 3.  Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.

    input_block = ""
    for i in range(0, probable_block_size - 1):
        input_block = input_block + "A"

    # It turns out consistent_key_ecb_encryption(input_block) will put the first 
    # byte of the mysterious appended text after input_block, resulting in the 16th
    # position of the ciphertext containing the encrypted byte corresponding to the
    # first byte of the mysterious appended text! 

    # TODO Eureka! Implement 

__main__() 
