#!/usr/bin/python

import hashlib
import itertools
import base64
import time

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

def xor_frequency_attack1(s):
    freq = {}
    freq{'a'} = 8 	
    freq{'b'} = 1 	
    freq{'c'} = 3 	
    freq{'d'} = 4 	
    freq{'e'} = 13 	
    freq{'f'} = 2 	
    freq{'g'} = 2 	
    freq{'h'} = 6 	
    freq{'i'} = 7 	
    freq{'j'} 	0 	
    freq{'k'} = 1 	
    freq{'l'} = 4 	
    freq{'m'} = 2 	
    freq{'n'} = 7 	
    freq{'o'} = 8 	
    freq{'p'} = 2 	
    freq{'q'} = 0 	
    freq{'r'} = 6 	
    freq{'s'} = 6 	
    freq{'t'} = 9 	
    freq{'u'} = 3 	
    freq{'v'} = 1 	
    freq{'w'} = 2 	
    freq{'x'} = 0 	
    freq{'y'} = 2 	
    freq{'z'} = 0 	

    
 

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

