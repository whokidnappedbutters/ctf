#!/usr/bin/python

import string
import hashlib
import itertools
import base64
import time

FREQ = {}
for i in range(256):
    FREQ[i] = 0

# Letter frequencies from Wikipedia
FREQ[97] = .08167 	
FREQ[98] = .01492 	
FREQ[99] = .02782 	
FREQ[100] = .04253 	
FREQ[101] = .12702 	
FREQ[102] = .02228
FREQ[103] = .02015
FREQ[104] = .06094
FREQ[105] = .06966 	
FREQ[106] = .00153	
FREQ[107] = .00772 	
FREQ[108] = .04025
FREQ[109] = .02406
FREQ[110] = .06749
FREQ[111] = .07507
FREQ[112] = .01929 	
FREQ[113] = .00095	
FREQ[114] = .05987
FREQ[115] = .06327
FREQ[116] = .09056
FREQ[117] = .02758	
FREQ[118] = .00978
FREQ[119] = .02361
FREQ[120] = .00150 	
FREQ[121] = .01974 	
FREQ[122] = .00074 	

def hex_to_string(s):
    return s.decode("hex")

def base64_encode_string(s):
    return base64.b64encode(s)

def hex_to_base64(s):
    return base64.b64encode(s.decode('hex'))

def xor_strings(s1, s2):
    if len(s1) != len(s2):
        return None
    if (len(s1) % 2) != 0:
        return None
    x1 = int(s1, 16)
    x2 = int(s2, 16)
    return format(x1^x2, '02x')

def xor_hex_string_with_int(s, x):
    if (len(s) % 2) != 0:
        return None
    newstring = ''
    for i in range(len(s)/2):
        begin = i*2
        end = begin + 2
        y = int(s[begin:end], 16) ^ x
        newstring = newstring + format(y, '02x')
    return newstring

# Compute the frequency of each letter in a string
def letter_frequency_in_ascii_string(s):
    # Use dictionary to store the letter frequencies
    freq = {}
    # Initialize data struct member counts
    for c in range(256):
        freq[c] = 0
    # Calculate the frequencies
    for c in s:
        c = c.lower()
        freq[ord(c)] = freq[ord(c)] + 1
    return freq    

def frequency_absolute_distance(f, length):
    sum = 0
    for c in range(256):
        sum = sum + abs(length * FREQ[c] - f[c])
    return sum
 
def frequency_squared_distance(f, length):
    sum = 0
    for c in range(256):
        d = length * FREQ[c] - f[c]
        d = d * d
        sum = sum + d
    return sum

# Use frequency analysis to figure out what character was used to
# XOR a string.
def frequency_attack1(s):

    distances = {}

    # Loop through all the possible XOR characters as integers
    for i in range(256):
        newstring = xor_hex_string_with_int(s, i)
        f = letter_frequency_in_ascii_string(newstring.decode('hex'))
        distances[i] = frequency_absolute_distance(f, len(s)/2)
   
    # Determine the min value
    k = min(distances, key=distances.get)
    print("Min distance produced by: {0}".format(k)) 

    # Decrypt the string
    newstring = xor_hex_string_with_int(s, k)
    return newstring

#
# LSB Oracle attack.  This function will compute P given a file
# with the lsb values and the value of N
#

def lsb_attack (lsbfile, N):

    infile = open(lsbfile, 'r')
    digits = infile.read()
    print("Number of digits: {0}".format(len(digits)))

    count = 1
    begin_numerator = 0
    end_numerator = 0
    for digit in digits:
        digit = int(digit)
        begin_numerator = 2 * begin_numerator
        end_numerator = 2 * end_numerator
        denominator = pow(2, count) 

        if denominator > N:
            break

        count = count + 1

        if digit == 1:
            begin_numerator = begin_numerator + 1
        else:    
            end_numerator = end_numerator + 1

    begin = N * begin_numerator / denominator
    end = N * (denominator - end_numerator) / denominator

    # TODO: Need to check the padding and remove it before returning the hex string.  This may 
    # involve looping through the potential results to find the correctly padded string

    return format(begin, '02x')

#
# Brute force attacks to find partial hash collisions
#

def brute_sha1_suffix (prefix, length):

    characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()-_;:,<.>/?'
    count = 0
    for suffix in itertools.combinations_with_replacement(characters, length):

        # Create the next string to check
        newstring = prefix + ''.join(suffix)

        # Output something every once in a while so we know the script isn't hung
        count = count + 1
        if count >= 1000000:
            print("New String: {0}".format(newstring))
            count = 0        
 
        # Compute the sha1 hash
        hash_object = hashlib.sha1(newstring)

        # Look to see if hex digits end in \xffffff
        hex_dig = str(hash_object.hexdigest())
        idx = hex_dig.find('ffffff', len(hex_dig)-6) 
        if idx == (len(hex_dig) - 6):
            return newstring
    
    return None

