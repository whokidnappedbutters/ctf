#!/usr/bin/python

import sys
sys.path.append('../')

from util import *

s = '1c0111001f010100061a024b53535009181c'

mystr = xor_hex_string_with_int(s, 0)
print("New string: {0}".format(mystr))

mystr = xor_hex_string_with_int(s, 1)
print("New string: {0}".format(mystr))

s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
frequency_attack1(s)

