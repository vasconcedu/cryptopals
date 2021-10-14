#!/usr/bin/python3

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

from my_cryptopals_utils import * 

# This challenge consists in detecting 
# a string among a handful of 60-character 
# strings which has been encrypted using 
# single-character XOR 

INPUT_FILE = '4.txt'

def __main__():

    print("[+] Cryptopals 04 - Detect single-character XOR")
    print("[+] Attempting to identify string...\n")

    with open(INPUT_FILE, 'r') as input_file:
        for line in input_file:
            
            ciphertext = line.strip()

            # Now see if D(line) makes sense based on 
            # the printable letter count heuristic 

            candidates = SingleByteXORCryptanalysis(hex_to_raw_bytes(ciphertext), 
                strategy=SingleByteXORCryptanalysis.PRINTABLE_LETTER_COUNT_BEST_FIT,
                strategy_bundle={
                    'count_threshold': .7 
                },
                verbose=False 
            ).break_ciphertext()

            if len(candidates) >= 1:
                print("[+] Ciphertext {} yielded the following candidates:\n".format(ciphertext))
                for candidate in candidates:
                    print("[+]     {}".format(candidate))
                print("\n")

__main__()
