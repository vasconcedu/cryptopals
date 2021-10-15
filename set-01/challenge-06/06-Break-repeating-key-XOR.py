#!/usr/bin/python3

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

from my_cryptopals_utils import * 

# This challenge consists in 
# breaking repeating-key XOR 

INPUT_CIPHERTEXT = open('6.txt', 'r').read()

def __main__():

    print("[+] Cryptopals 06 - Break repeating-key XOR\n")

    print("[+] Running tests...\n")

    print("[+] Test #1: Hamming distance. H(4, 5) = {}, should be 1".format(hamming_distance_bytes(4, 5))) # 1
    print("[+] Test #2: Hamming distance. H(4, 6) = {}, should be 1".format(hamming_distance_bytes(4, 6))) # 1
    print("[+] Test #3: Hamming distance. H(5, 6) = {}, should be 2".format(hamming_distance_bytes(5, 6))) # 2
    print("[+] Test #4: Hamming distance. H(33, 87) = {}, should be 5".format(hamming_distance_bytes(33, 87))) # 5

    print("[+] Test #5: Hamming distance. H('w', '$') = {}, should be 4".format(hamming_distance(bytes('w', 'utf-8'), bytes('$', 'utf-8')))) # 4
    print("[+] Test #6: Hamming distance. H('this is a test', 'wokka wokka!!!') = {}, should be 37".format(hamming_distance(bytes('this is a test', 'utf-8'), bytes('wokka wokka!!!', 'utf-8')))) # 37

    print("\n[+] Running cryptanalysis, using PRINTABLE_LETTER_COUNT_BEST_FIT single-byte XOR heuristic...\n")

    key = RepeatingKeyXORCryptanalysis(
        base_64_to_raw_bytes(INPUT_CIPHERTEXT), # Ciphertext 
        2, # Lower bound key size
        40, # Upper bound key size 
        verbose=False 
    ).break_ciphertext(count_threshold=.5) # For best fit, it seems that the lower the better 

    print("[+] Best key is:\n\n[+] Hex: {}\n[+] Base64: {}\n[+] Raw: {}".format(raw_bytes_to_hex(key), raw_bytes_to_base_64(key), key))

    print("\n[+] Attempting to decrypt ciphertext using best key...")

    # Now I DO deserve some expensive wine this weekend 
    print("\n[+] Ciphertext is:\n\n{}".format(RepeatingKeyXOR().decrypt(base_64_to_raw_bytes(INPUT_CIPHERTEXT), key).decode('utf-8')))

__main__()
