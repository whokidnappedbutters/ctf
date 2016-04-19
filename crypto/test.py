#!/usr/bin/python

from util import *

def main(mystring, string_length):
    collision = brute_sha1_suffix(mystring, string_length - len(mystring))
    print("String with collision: {0}".format(collision))

# Start here
main('NYy0AeKDSL', 15)
