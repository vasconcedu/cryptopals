#!/usr/bin/python3

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

from my_cryptopals_utils import * 

# This challenge consists in 
# breaking repeating-key XOR 

INPUT_CIPHERTEXT = """0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"""

def __main__():

    print("[+] Cryptopals 05 - Implement repeating-key XOR\n")

    print("[+] Running tests...\n")

    print("[+] Test #1: Hamming distance. H(4, 5) = {}, should be 1".format(hamming_distance_bytes(4, 5))) # 1
    print("[+] Test #2: Hamming distance. H(4, 6) = {}, should be 1".format(hamming_distance_bytes(4, 6))) # 1
    print("[+] Test #3: Hamming distance. H(5, 6) = {}, should be 2".format(hamming_distance_bytes(5, 6))) # 2
    print("[+] Test #4: Hamming distance. H(33, 87) = {}, should be 5".format(hamming_distance_bytes(33, 87))) # 5

    print("[+] Test #5: Hamming distance. H('w', '$') = {}, should be 4".format(hamming_distance(bytes('w', 'utf-8'), bytes('$', 'utf-8')))) # 4
    print("[+] Test #6: Hamming distance. H('this is a test', 'wokka wokka!!!') = {}, should be 37".format(hamming_distance(bytes('this is a test', 'utf-8'), bytes('wokka wokka!!!', 'utf-8')))) # 37

    print("\n[+] Running cryptanalysis...\n")

    # TODO change 
    RepeatingKeyXORCryptanalysis(hex_to_raw_bytes(INPUT_CIPHERTEXT), 2, 40).break_ciphertext()

__main__()
