#!/usr/bin/python3

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

from my_cryptopals_utils import * 

# This challenge consists in performing 
# cryptanalysis to break a single-byte XOR
# cipher using frequency analysis (English)

CIPHERTEXT = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

def __main__():

    print("[+] Cryptopals 03 - Single-byte XOR cipher")
    print("[+] Analyzing...\n")

    print("\n[+] Mean Absolute Error heuristic...\n")

    candidates = SingleByteXORCryptanalysis(hex_to_raw_bytes(CIPHERTEXT), 
        strategy=SingleByteXORCryptanalysis.MEAN_ABSOLUTE_ERROR,
        strategy_bundle={
            'error_threshold': 0.001 
        },
        verbose=False
    ).break_ciphertext()

    print("[+] Best candidates are:\n")
    for c in candidates:
        print("[+] {}".format(c))

    print("\n[+] Printable letter count heuristic...\n")

    candidates = SingleByteXORCryptanalysis(hex_to_raw_bytes(CIPHERTEXT), 
        strategy=SingleByteXORCryptanalysis.PRINTABLE_LETTER_COUNT,
        strategy_bundle={
            'count_threshold': .79 
        },
        verbose=False 
    ).break_ciphertext()

    print("[+] Best candidates are:\n")
    for c in candidates:
        print("[+] {}".format(c))

    print("\n[+] Printable letter count best fit heuristic...\n")

    candidates = SingleByteXORCryptanalysis(hex_to_raw_bytes(CIPHERTEXT), 
        strategy=SingleByteXORCryptanalysis.PRINTABLE_LETTER_COUNT_BEST_FIT,
        strategy_bundle={
            'count_threshold': .79 
        },
        verbose=False 
    ).break_ciphertext()

    print("[+] Best candidate is:\n")
    for c in candidates:
        print("[+] {}".format(c))

__main__()
