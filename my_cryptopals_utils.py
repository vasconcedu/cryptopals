#!/usr/bin/python3

import base64
import operator 

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

    MEAN_ABSOLUTE_ERROR = 'mean_absolute_error'
    PRINTABLE_LETTER_COUNT = 'printable_letter_count'
    PRINTABLE_LETTER_COUNT_BEST_FIT = 'printable_letter_count'

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

            if (self.strategy == self.MEAN_ABSOLUTE_ERROR and self.mean_absolute_error_cryptanalysis(plaintext, self.strategy_bundle['error_threshold'], letter_dictionary)) or (self.strategy == self.PRINTABLE_LETTER_COUNT and self.printable_letter_count_cryptanalysis(plaintext, self.strategy_bundle['count_threshold'], letter_dictionary)):
                    self.candidates.append({
                        'key': k,
                        'plaintext': plaintext
                    })

        return self.candidates

    def printable_letter_count_cryptanalysis(self, plaintext, count_threshold, plaintext_letter_count):
        
        for l in plaintext:
            
            # Keep printable letter counts
            if int(l) in range(97, 123): # From 'a' to 'z'
                plaintext_letter_count[chr(l)] = plaintext_letter_count[chr(l)] + 1

        printable_count = 0

        for l in plaintext_letter_count:
            printable_count = printable_count + plaintext_letter_count[l]

        if printable_count >= (len(plaintext) * count_threshold):
            return True 

        return False

    def printable_letter_count_cryptanalysis_best_fit(self, plaintext, count_threshold, plaintext_letter_count):
        
        for l in plaintext:
            
            # Keep account of printable letters
            if int(l) in range(97, 123): # From 'a' to 'z'
                plaintext_letter_count[chr(l)] = plaintext_letter_count[chr(l)] + 1

        printable_letter_count = 0

        for l in plaintext_letter_count:
            printable_letter_count = printable_letter_count + plaintext_letter_count[l]

        if printable_letter_count >= (len(plaintext) * count_threshold):
            return True 

        return False
    
    def mean_absolute_error_cryptanalysis(self, plaintext, error_threshold, plaintext_letter_frequencies):

        spaces_occur = False 

        for l in plaintext:
            # Keep letter frequencies 
            if int(l) in range(97, 123): # From 'a' to 'z'
                plaintext_letter_frequencies[chr(l)] = plaintext_letter_frequencies[chr(l)] + 1. / len(plaintext)

            # Check for space occurrences 
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

# Test if my_cryptopals_utils was imported successfully 
def test_my_cryptopals_utils():
    print('[my_cryptopals_utils] Good to go!')
