#!/usr/bin/python3

import base64
import operator 
import math
import secrets
import random 

from Crypto.Cipher import AES
from collections import Counter

# Useful conversion methods resulting 
# from challenge 01 - Convert hex to Base64

# Targeted at reading hex input into the routine 
def hex_to_raw_bytes(hex): 
    return bytes.fromhex(hex)

# Targeted at outputting in hex format 
def raw_bytes_to_hex(raw_bytes):
    return bytes.hex(raw_bytes)

# Targeted at outputting in Base64 format 
def raw_bytes_to_base_64(raw_bytes):
    return base64.encodebytes(raw_bytes).strip().decode('utf-8')

# Targeted at reading Base64 input into the routine 
def base_64_to_raw_bytes(base_64):
    return base64.b64decode(base_64)

# Targeted at converting between output formats (hex to Base64)
def hex_to_base_64(hex):
    return raw_bytes_to_base_64(hex_to_raw_bytes(hex))

# Targeted at converting between output formats (Base64 to hex)
def base_64_to_hex(base_64):
    return raw_bytes_to_hex(base_64_to_raw_bytes(base_64))

# Buffer bitwise XOR resulting from 
# challenge 02 - Fixed XOR 

def xor(a, b): # Raw byte array arguments 
    c = []
    for i in range(0, len(a)):
        c.append(operator.xor(a[i], b[i]))
    return bytes(c)

# Hamming distance routine between two bytes
# resulting from challenge 06 - Break repeating 
# key XOR

def hamming_distance_bytes(a, b):
    d = 0
    for i in [1, 2, 4, 8, 16, 32, 64, 128]: # Masks 
        if (a & i) != (b & i):
            d = d + 1
    return d 

# Hamming distance routine between two byte arrays
# resulting from challenge 06 - Break repeating 
# key XOR

def hamming_distance(a, b):
    d = 0
    for i in range(0, len(a)):
        d = d + hamming_distance_bytes(a[i], b[i])
    return d 

# Slice array a in given number of blocks n, from
# challenge 06 - Break repeating key XOR. By default, 
# this will truncate array a in case the length of 
# the last portion of bytes is lower than the 
# required number of bytes for even block sizes. To 
# prevent truncation, use truncate=False

# TODO there seems to be a bug here, needs further testing
# Spotted it, the mistake is actually at the call (see count_repeating_blocks)

def slice_in_blocks_of_n_size(a, n, truncate=True):

    blocks = []
    lower_index = 0
    upper_index = n

    while upper_index < len(a):
        blocks.append(a[lower_index:upper_index])
        lower_index = upper_index
        upper_index = upper_index + n

    if lower_index < len(a) and truncate == False:
        blocks.append(a[lower_index:])

    return blocks

# Count repeating blocks in ciphertext, 
# from challenge 08 - Detect AES in ECB mode 
def count_repeating_blocks(a): # a: byte array

    blocks = slice_in_blocks_of_n_size(a, 2) # TODO this is wrong, yields 16 bits, but should yield 16 bytes instead. It works, but is conceptually wrong

    repetitions = 0

    for block_i in blocks: # For each block 
        for block_j in blocks: # Count how many times it occurs 
            if block_j == block_i:
                repetitions = repetitions + 1 

    return repetitions

# Perfoms PKCS#7 padding of string a 
# to block size s, from challenge 
# 07 - AES in ECB mode 
def pkcs_7_padding(a, s):
    b = a 
    while len(b) % s != 0:
        b = b + "\x04"
    return b

# Perfoms PKCS#7 unpadding of string, 
# from challenge 10 - Implement CBC mode
def pkcs_7_unpad(a):
    return a.replace(b"\x04", b"")

# Encrypt block using AES in ECB mode, 
# from challenge 10 - Implement CBC mode
def encrypt_block_in_ecb_mode(b, k): # b: plaintext block, k: key 
    return AES.new(k, AES.MODE_ECB).encrypt(b)

# Decrypt block using AES in ECB mode, 
# from challenge 10 - Implement CBC mode
def decrypt_block_in_ecb_mode(b, k): # b: plaintext block, k: key 
    return AES.new(k, AES.MODE_ECB).decrypt(b)

# Decrypt ciphertext using AES in CBC mode, 
# from challenge 10 - Implement CBC mode
def decrypt_plaintext_in_cbc_mode(c, k, iv): # c: ciphertext string, k: key string, iv: initialization vector bytes 

    p = [] # Ciphertext

    # Step 1. split ciphertext into blocks 
    # of 128 bits (or 16 bytes)
    b = slice_in_blocks_of_n_size(c, 16, truncate=False)

    # Step 2. Set initial IV,
    iv_i = iv
    # then for each block: 
    for b_i in b:
        
        # Step 2.1. Compute c_i = ECB(b_i, k)
        c_i = decrypt_block_in_ecb_mode(b_i, k)

        # Step 2.2. p_i = iv_i ^ c_i
        p_i = xor(iv_i, c_i)

        # Step 2.3. Update IV
        iv_i = b_i
    
        # Step 2.4. p += p_i (append p_i to plaintext)
        p.append(p_i)

    p = b''.join(p)

    # Step 3. Unpad 
    return pkcs_7_unpad(p)

# Encrypt plaintext using AES in CBC mode, 
# from challenge 10 - Implement CBC mode
def encrypt_plaintext_in_cbc_mode(p, k, iv): # p: plaintext string, k: key string, iv: initialization vector bytes 

    c = [] # Ciphertext

    # Step 1. Pad to 16 bytes 
    p = pkcs_7_padding(p, 16)

    # Step 2. split plaintext into blocks 
    # of 128 bits (or 16 bytes)
    b = slice_in_blocks_of_n_size(p, 16, truncate=False)

    # Step 3. Set initial IV,
    iv_i = iv
    # then for each block:
    for b_i in b:
        # Step 3.1. Compute p_i = iv_i ^ b_i
        p_i = xor(iv_i, bytes(b_i, 'utf-8'))

        # Step 3.2. c_i = ECB(p_i, k)
        c_i = encrypt_block_in_ecb_mode(p_i, k)

        # Step 3.3. Update IV
        iv_i = c_i
    
        # Step 3.4. c += c_i (append c_i to ciphertext)
        c.append(c_i)

    return b''.join(c)

# Random key generation, from challenge 11 - 
# An ECB/CBC detection oracle
def generate_random_key():
    k = []
    for i in range(0, 16):
        k.append(secrets.randbelow(256))
    return bytes(k)

# Encryption oracle function, from 
# challenge 11 - An ECB/CBC detection oracle
MODE_CBC = 0
MODE_ECB = 1

def encryption_oracle(plaintext):
    
    append_before_count = secrets.choice([5, 6, 7, 8, 9, 10])
    append_after_count = secrets.choice([5, 6, 7, 8, 9, 10])

    append_before = secrets.token_bytes(append_after_count)
    append_after = secrets.token_bytes(append_after_count)

    appended_plaintext = "{}{}{}".format(append_before, plaintext, append_after)

    mode = secrets.randbelow(2) # Either 0 or 1 

    ciphertext = None 

    if mode == MODE_CBC:
        ciphertext = encrypt_plaintext_in_cbc_mode(appended_plaintext, generate_random_key(), generate_random_key())
    else:
        appended_plaintext = pkcs_7_padding(appended_plaintext, 16) # Blocks must be 16 bytes in length 
        ciphertext = encrypt_block_in_ecb_mode(appended_plaintext, generate_random_key())

    return mode, ciphertext


""" [BEGIN] Challenge 12 """


# Consistent random key ECB encryption function, from challenge
# 12 - Byte-at-a-time ECB decryption (Simple)
CONSISTENT_RANDOM_KEY = generate_random_key()

def consistent_key_ecb_encryption(plaintext): 

    # Text to append to plaintext,
    # before encrypting 
    text_to_append_base_64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

    text_to_append_raw_bytes = base_64_to_raw_bytes(text_to_append_base_64).decode() # Had to add decode here o/w was getting Python string from bytes object directly (started with character 'b' and all, messed up the whole thing)

    key = CONSISTENT_RANDOM_KEY

    full_plaintext = pkcs_7_padding("{}{}".format(plaintext, str(text_to_append_raw_bytes)), 16)

    ciphertext = encrypt_block_in_ecb_mode(full_plaintext, key)

    return ciphertext

# Consistent random key ECB encryption function, from challenge
# 14 - Byte-at-a-time ECB decryption (Harder). This time, adds
# a random bytes prefix to the plaintext 
CONSISTENT_RANDOM_KEY = generate_random_key()

def consistent_key_ecb_encryption_harder(plaintext): 

    # Random bytes prefix 
    random_bytes_prefix = secrets.token_bytes(secrets.randbelow(20))

    # Text to append to plaintext,
    # before encrypting 
    text_to_append_base_64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

    text_to_append_raw_bytes = base_64_to_raw_bytes(text_to_append_base_64).decode() # Had to add decode here o/w was getting Python string from bytes object directly (started with character 'b' and all, messed up the whole thing)

    key = CONSISTENT_RANDOM_KEY

    full_plaintext = pkcs_7_padding("{}{}{}".format(random_bytes_prefix, plaintext, str(text_to_append_raw_bytes)), 16)

    ciphertext = encrypt_block_in_ecb_mode(full_plaintext, key)

    return ciphertext

# Find out given encryption function's block size,
# from challenge 12 - Byte-at-a-time ECB decryption (Simple)
def find_block_size(f, verbose=False):
    
    possible_block_sizes = [] 
    
    for i in range(0, 100):

        my_plaintext = "q"
        first_n_blocks = None

        while True: 
    
            ciphertext = f(my_plaintext)

            # It turns out after my_plaintext's length reaches block size
            # the first (n = block size) bytes of the ciphertext will start 
            # repeating on and on, every encryption round from that point on 

            # To evidence, toggle this:
            # print("[+] Ciphertext: {}".format(ciphertext))
            if first_n_blocks != None and ciphertext.startswith(first_n_blocks): # Might still coincide. Hence running several times to account for it (reduce probability of occurrence)
                if verbose:
                    print("    [+] Run #{}: block size is likely {} bytes".format(i, len(first_n_blocks)))
                possible_block_sizes.append(len(first_n_blocks))
                break 
            
            first_n_blocks = ciphertext[:len(my_plaintext)]

            my_plaintext = my_plaintext + "q"

    occurence_count = Counter(possible_block_sizes)
    return occurence_count.most_common(1)[0][0]

# Cryptanalysis of AES in ECB mode, from 
# challenge 12 - Byte-at-a-time ECB decryption (Simple)
def aes_ecb_cryptanalysis_simple(f, probable_block_size=16):

    plaintext = ""

    input_offset_length = probable_block_size - 1

    while True: 

        # 3.  Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.

        input_offset = "q" * input_offset_length
        
        if input_offset_length == 0:
            input_offset_length = probable_block_size - 1
        else:
            input_offset_length = input_offset_length - 1 

        ciphertext = f(input_offset)

        # 4. Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation. 
        
        for i in range(0, 255):
            
            trial_plaintext = input_offset + plaintext + chr(i)
            trial_ciphertext = f(trial_plaintext)

            # 5. Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string. 
        
            if trial_ciphertext.startswith(ciphertext[:len(trial_plaintext)]):
                plaintext = plaintext + chr(i)
                break
            
        if len(plaintext) == len(ciphertext): # Stop condition 
            break

    return plaintext, len(plaintext)


""" [END] Challenge 12 """


# Single-byte XOR cryptanalysis routine resulting
# from challenge 03 - Single-byte XOR cipher

class SingleByteXORCryptanalysis:

    # Table from https://www3.nd.edu/~busiforc/handouts/cryptography/letterfrequencies.html
    LETTER_FREQUENCIES = { 
        'a': .084966, 'b': .020720, 'c': .045388, 'd': .033844, 'e': .111607, 'f': .018121, 'g': .024705, 'h': .030034, 'i': .075448, 'j': .001965, 'k': .011016, 'l': .054893, 'm': .030129, 'n': .066544, 'o': .071635, 'p': .031671, 'q': .001962, 'r': .075809, 's': .057351, 't': .069509, 'u': .036308, 'v': .010074, 'w': .012899, 'x': .002902, 'y': .017779, 'z': .002722
    }

    ZEROED_LETTER_FREQUENCIES = { 
        'a': .0, 'b': .0, 'c': .0, 'd': .0, 'e': .0, 'f': .0, 'g': .0, 'h': .0, 'i': .0, 'j': .0, 'k': .0, 'l': .0, 'm': .0, 'n': .0, 'o': .0, 'p': .0, 'q': .0, 'r': .0, 's': .0, 't': .0, 'u': .0, 'v': .0, 'w': .0, 'x': .0, 'y': .0, 'z': .0
    }

    ZEROED_LETTER_COUNT = { 
        'a': 0, 'b': 0, 'c': 0, 'd': 0, 'e': 0, 'f': 0, 'g': 0, 'h': 0, 'i': 0, 'j': 0, 'k': 0, 'l': 0, 'm': 0, 'n': 0, 'o': 0, 'p': 0, 'q': 0, 'r': 0, 's': 0, 't': 0, 'u': 0, 'v': 0, 'w': 0, 'x': 0, 'y': 0, 'z': 0
    }

    # Quite helpful to enhance candidate results (check if plaintext contains any of the following)
    BAD_CHARS = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0b, 0x0c, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1f, 0x7f]

    MEAN_ABSOLUTE_ERROR = 'mean_absolute_error'
    PRINTABLE_LETTER_COUNT = 'printable_letter_count'
    PRINTABLE_LETTER_COUNT_BEST_FIT = 'printable_letter_count_best_fit'

    ciphertext = None
    strategy = None
    strategy_bundle=None
    candidates = None
    verbose = None

    def __init__(self, ciphertext, strategy='mean_absolute_error', strategy_bundle={}, verbose=False):
        
        self.ciphertext = ciphertext
        self.strategy = strategy
        self.strategy_bundle = strategy_bundle
        self.verbose = verbose 
        self.candidates = [] # Key candidates

    def break_ciphertext(self):

        self.candidates = [] # Reset candidates 

        for k in range(0, 255): # For each viable key 

            letter_dictionary = None 

            if self.strategy == self.MEAN_ABSOLUTE_ERROR:
                letter_dictionary = self.ZEROED_LETTER_FREQUENCIES.copy()
            elif self.strategy == self.PRINTABLE_LETTER_COUNT or self.strategy == self.PRINTABLE_LETTER_COUNT_BEST_FIT:
                letter_dictionary = self.ZEROED_LETTER_COUNT.copy()

            key = bytes(chr(k) * len(self.ciphertext), 'utf-8') # Candidate key
            plaintext = xor(self.ciphertext, key) # Calculated plaintext 

            if self.verbose: # Print candidate key along with the corresponding plaintext
                print("[my_cryptopals_utils][SingleByteXORCryptanalysis] key:'{}', plaintext: {}".format(chr(k), plaintext))

            if (self.strategy == self.MEAN_ABSOLUTE_ERROR and self.mean_absolute_error_cryptanalysis(plaintext, self.strategy_bundle['error_threshold'], letter_dictionary)) or ((self.strategy == self.PRINTABLE_LETTER_COUNT or self.strategy == self.PRINTABLE_LETTER_COUNT_BEST_FIT) and self.printable_letter_count_cryptanalysis(plaintext, self.strategy_bundle['count_threshold'], letter_dictionary)):
                    self.candidates.append({
                        'key': k,
                        'plaintext': plaintext
                    })

        if self.strategy == self.PRINTABLE_LETTER_COUNT_BEST_FIT:
            self.candidates = self.printable_letter_count_best_fit()

        return self.candidates

    # Much better than MAE 
    def printable_letter_count_cryptanalysis(self, plaintext, count_threshold, plaintext_letter_count):
        
        for l in plaintext:
            
            # Keep printable letter counts
            if int(l) in range(97, 123): # From 'a' to 'z'
                plaintext_letter_count[chr(l)] = plaintext_letter_count[chr(l)] + 1

            if int(l) in range(65, 91): # From 'A' to 'Z'
                plaintext_letter_count[chr(l + 32)] = plaintext_letter_count[chr(l + 32)] + 1

        printable_count = 0

        for l in plaintext_letter_count:
            printable_count = printable_count + plaintext_letter_count[l]

        if printable_count >= (len(plaintext) * count_threshold):
            return True 

        return False

    
    # Work on top of printable_letter_count_cryptanalysis
    # results to get best fit candidates only       
    # TODO I could actually use this to enhance MAE too 
    def printable_letter_count_best_fit(self):

        best_fit_score = math.inf
        best_fit_candidate = None

        for candidate in self.candidates:

            candidate_score = 0

            for l in candidate['plaintext']:

                if int(l) in self.BAD_CHARS: # Bad chars (probably not in plaintext)
                    candidate_score = candidate_score + 1

                if int(l) == 32: # Space, good sign 
                    candidate_score = candidate_score - 1

            if candidate_score < best_fit_score:
                best_fit_score = candidate_score
                best_fit_candidate = candidate

        return [best_fit_candidate]
    
    # This is not satisfactory at all, at least as is 
    # TODO check out idea on printable_letter_count_best_fit
    def mean_absolute_error_cryptanalysis(self, plaintext, error_threshold, plaintext_letter_frequencies):

        spaces_occur = False 

        for l in plaintext:
            
            # Keep printable letter frequencies 
            if int(l) in range(97, 123): # From 'a' to 'z'
                plaintext_letter_frequencies[chr(l)] = plaintext_letter_frequencies[chr(l)] + 1. / len(plaintext)

            if int(l) in range(65, 91): # From 'A' to 'Z'
                plaintext_letter_frequencies[chr(l + 32)] = plaintext_letter_frequencies[chr(l + 32)] + 1. / len(plaintext)

            # Check for space occurrences. This enhances MAE peformance A LOT
            if l == 32: # Space 
                spaces_occur = True

        # Calculate mean absolute error of the dictionary with respect to the expected frequencies 
        error = self.mean_absolute_error(plaintext_letter_frequencies, self.LETTER_FREQUENCIES)

        if error <= error_threshold and spaces_occur: # Good candidate: error < threshold and space characters occur
            return True
            
        return False

    def mean_absolute_error(self, p, q):
        s = 0.
        for k in p:
            s = abs(p[k] - q[k])
        return s / len(p)

# Repeating-key XOR encryption/decryption routines 
# resulting from challenge 05 - Implement repeating-key 
# XOR

class RepeatingKeyXOR:

    def __init__(self):
        return

    def encrypt(self, plaintext, key):

        expanded_key = self.expand_key(key, len(plaintext))
        return xor(plaintext, expanded_key)

    def decrypt(self, ciphertext, key):

        expanded_key = self.expand_key(key, len(ciphertext))
        return xor(ciphertext, expanded_key)

    def expand_key(self, key, length):

        expanded_key = ''

        for i in range(0, length):
            expanded_key = expanded_key + chr(key[i % len(key)])

        return bytes(expanded_key, 'utf-8')

# Repeating-key XOR cryptanalysis routine resulting
# from challenge 06 - Break repeating-key XOR 

class RepeatingKeyXORCryptanalysis:

    ciphertext = None 
    key_size_lower = None
    key_size_upper = None
    verbose = None

    def __init__(self, ciphertext, key_size_lower, key_size_upper, verbose=False):
        self.ciphertext = ciphertext
        self.key_size_lower = key_size_lower
        self.key_size_upper = key_size_upper
        self.verbose = verbose

    def break_ciphertext(self, count_threshold=.6):

        key_size, _ = self.search_key_size()
        blocks = slice_in_blocks_of_n_size(self.ciphertext, key_size, truncate=False)
        key = []

        for i in range(0, key_size):

            single_byte_xor_ciphertext_list = []

            for block in blocks:
                if i < len(block):
                    single_byte_xor_ciphertext_list.append(block[i])

            single_byte_xor_ciphertext = bytes(single_byte_xor_ciphertext_list)
            candidate = SingleByteXORCryptanalysis(single_byte_xor_ciphertext, 
                strategy=SingleByteXORCryptanalysis.PRINTABLE_LETTER_COUNT_BEST_FIT,
                strategy_bundle={
                    'count_threshold': count_threshold
                },
                verbose=False 
            ).break_ciphertext()

            if(self.verbose):
                print("[my_cryptopals_utils][RepeatingKeyXORCryptanalysis] Best candidate is: {}\n".format(candidate[0]))
            
            if candidate[0] != None:
                key.append(candidate[0]['key'])
            else:
                key.append(95) # Watch out! Could not break this byte! 95 => '_'

        return bytes(key)

    def search_key_size(self):

        best_normalized_average_distance = math.inf
        best_key_size = None

        for key_size in range(self.key_size_lower, self.key_size_upper + 1):

            # Sliding window 
            blocks = slice_in_blocks_of_n_size(self.ciphertext, key_size)
            distance = 0

            for i in range(0, len(blocks) - 1):
                distance = distance + hamming_distance(blocks[i], blocks[i + 1])

            average_distance = distance / float(len(blocks))
            normalized_average_distance = average_distance / float(key_size)

            if self.verbose:
                print("[my_cryptopals_utils][RepeatingKeyXORCryptanalysis] key size: {}, normalized average Hamming distance: {}".format(key_size, normalized_average_distance))

            if normalized_average_distance < best_normalized_average_distance:
                best_normalized_average_distance = normalized_average_distance
                best_key_size = key_size

        if self.verbose:
            print("[my_cryptopals_utils][RepeatingKeyXORCryptanalysis] *** best key size: {}, best normalized average Hamming distance: {} ***".format(best_key_size, best_normalized_average_distance))

        return best_key_size, best_normalized_average_distance

# Challenge 13 - ECB cut-and-paste parser 

class KeyValueParser:

    key_value_string = None
    parsed_object = None

    def __init__(self, key_value_string):
        self.key_value_string = key_value_string

    def parse(self):
        
        parsed_object = {}
        key_values = self.key_value_string.split("&")

        for key_value in key_values:
            key = key_value.split("=")[0]
            value = key_value.split("=")[1]

            parsed_object[key] = value

        return parsed_object

    def get_key_value_string(self):
        return self.key_value_string

    def set_key_value_string(self, key_value_string):
        self.key_value_string = key_value_string

    def get_parsed_object(self):
        return self.parsed_object

# Challenge 13 - ECB cut-and-paste user class 

UID_COUNTER = 0

class User: # "profile_for"

    email = None
    uid = None
    role = None
    encoded = None
    dictionary = None

    def __init__(self, email, uid=None):
        
        global UID_COUNTER # Could have made this a bit more elegant, but I'm happy... 

        # E-mail
        self.email = email.replace("&", "").replace("=", "") # Strip special characters 
        
        # UID TODO chnage back, having trouble, probably with this (yep, length is varying...)
        if uid == None:
            # self.uid = UID_COUNTER
            # UID_COUNTER = UID_COUNTER + 1
            self.uid = 10
        
        # Role
        self.role = 'user' # Hardcoded 

        # As encoded string 
        self.encoded = "email={}&uid={}&role={}".format(self.email, self.uid, self.role)

        # As dictionary 
        self.dictionary = KeyValueParser(self.encoded).parse()
    
    def get_encoded(self):
        return self.encoded

    def get_dictionary(self):
        return self.dictionary

# Challenge 13 - ECB cut-and-paste encrypt/decrypt 
# encoded user functions

ENCODED_USER_ENCRYPTION_KEY = generate_random_key()

def encrypt_encoded_user(encoded):
    return encrypt_block_in_ecb_mode(pkcs_7_padding(encoded, 16), ENCODED_USER_ENCRYPTION_KEY)

def decrypt_encoded_user(ciphertext):
    return pkcs_7_unpad(decrypt_block_in_ecb_mode(ciphertext, ENCODED_USER_ENCRYPTION_KEY))

# Test if my_cryptopals_utils was imported successfully 
def test_my_cryptopals_utils():
    print('[my_cryptopals_utils] Good to go!')
