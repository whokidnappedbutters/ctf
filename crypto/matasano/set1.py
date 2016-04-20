#!/usr/bin/python

import sys
sys.path.append('../lib/')

import util
import base64

def problem1():
    mystring = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    encoded = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    s = util.hex_to_base64(mystring)
    print("Answer 1: {0}".format(s))

    if s != encoded:
        print("Answer 1 incorrect")
        return False

    return True

def problem2():
    s1 = '1c0111001f010100061a024b53535009181c'
    s2 = '686974207468652062756c6c277320657965'
    answer = '746865206b696420646f6e277420706c6179'

    x = util.xor_strings(s1, s2)
    if x is None:
        print("Problem 2: problem with input strings")
        return False

    print("Answer 2: {0}".format(x))
    if x != answer:
        print("Answer 2 incorrect")
        return False
    return True

def problem3():

    answer = "Cooking MC's like a pound of bacon"
    s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

    s = util.frequency_attack1(s)
    s = s.decode('hex')
    print("Answer 3: {0}".format(s))

    if s != answer:
        print("Answer 3 incorrect")
        return False
    return True


def main():

    ret = problem1()
    if not ret:
        return

    ret = problem2()
    if not ret:
        return

    ret = problem3()
    if not ret:
        return

    print("All problems solved correctly")


# Start here
main() 
