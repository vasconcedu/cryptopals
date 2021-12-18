#!/usr/bin/python3

import sys
sys.path.append("../..") # Adds root folder to Python modules path 

import time
from my_cryptopals_utils import * 

# This challenge consists in performing an ECB cut-and-paste attack against 
# a piece of ciphertext whose format is know a priori
#
# Attacker has access to ciphertext and to the ciphertext generation function 
# => goal is to tamper with the ciphertext in order to change it and still
# obtain valid plaintext (with particular intended properties) after decryption

SAMPLE_INPUT = "foo=bar&baz=qux&zap=zazzle"

def __main__():
        
    print("[+] Cryptopals 13 - EBC cut-and-paste\n")

    # Test parser 

    print("[+] Test #1: KeyValueParser\n")

    print("    [+] Sample input: {}".format(SAMPLE_INPUT))
    key_value_parser = KeyValueParser(SAMPLE_INPUT)
    print("    [+] Parsed input: {}".format(key_value_parser.parse()))

    # It works! 

    print("\n[+] Test #2: User\n")

    print("    [+] User #1 is foo@bar.com:\n")
    user_1 = User("foo@bar.com") # "profile_for"
    print("        [+] Object: {}".format(user_1.get_dictionary()))
    print("        [+] Encoded: {}".format(user_1.get_encoded()))

    print("\n    [+] User #2 is foo&@bar=.com:\n")
    user_2 = User("foo&@bar=.com")
    print("        [+] Object: {}".format(user_2.get_dictionary()))
    print("        [+] Encoded: {}".format(user_2.get_encoded()))

    # It works! 

    print("\n[+] Test #3: ********** ECB cut-and-paste attack **********\n")

    print("    [+] Preliminary tests:\n")

    victim = User("victim@foo.bar")
    print("        [+] Object: {}".format(victim.get_dictionary()))
    print("        [+] Encoded: {}".format(victim.get_encoded()))

    # Encrypt/decrypt 
    ciphertext = encrypt_encoded_user(victim.get_encoded()) # Attacker should have access to this!!! 
    print("        [+] (Ciphertext {})".format(raw_bytes_to_hex(ciphertext)))
    print("        [+] Decrypted ciphertext: {}".format(decrypt_encoded_user(ciphertext)))

    # It works! 

    print("\n    [+] Searching block size...")
    probable_block_size = find_block_size(consistent_key_ecb_encryption)
    print("    [+] Probable block size is: {} bytes\n".format(probable_block_size))

    known_ending = b"&uid=10&role=user"

    print("    [+] Searching last block of plaintext based on known ending `{}`...".format(known_ending))
    last_block_ciphertext = slice_in_blocks_of_n_size(ciphertext, probable_block_size, truncate=False)[-1]
    last_block = None 

    for i in range(1, probable_block_size + 1):
        
        candidate_block = known_ending[-i:]
        
        while len(candidate_block) < probable_block_size:
            candidate_block = candidate_block + b"\x04"
        
        candidate_block_ciphertext = encrypt_encoded_user(candidate_block)

        if candidate_block_ciphertext == last_block_ciphertext:
            last_block = candidate_block

    print("    [+] Found viable candidate. Probable last block of plaintext is: {}".format(last_block))
    print("    [+] (Ciphertext {})".format(raw_bytes_to_hex(last_block_ciphertext)))

    admin_plaintext = last_block.replace(b"user\x04", b"admin")
    admin_ciphertext = encrypt_encoded_user(admin_plaintext)
    print("\n    [+] Changing role to admin. Plaintext is: {}".format(admin_plaintext))
    print("    [+] (Ciphertext {})".format(raw_bytes_to_hex(admin_ciphertext)))

    tampered_ciphertext_blocks = slice_in_blocks_of_n_size(ciphertext, probable_block_size, truncate=False)
    tampered_ciphertext_blocks[-1] = admin_ciphertext

    tampered_ciphertext = b''.join(tampered_ciphertext_blocks)
    print("\n    [+] Done. Tampered ciphertext is: {}".format(raw_bytes_to_hex(tampered_ciphertext)))

    print("    [+] Decrypting tampered ciphertext yields: {}\n".format(decrypt_encoded_user(tampered_ciphertext)))

__main__()
