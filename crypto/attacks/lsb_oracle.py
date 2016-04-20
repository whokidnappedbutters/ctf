#!/usr/bin/python

import sys

sys.path.append('../lib/')

from util import *
import hashlib
import time
import socket
import re

SERVER = 'rabit.pwning.xxx'
PORT = 7763

# BEGIN should be >= 1
#BEGIN = 1
#END = 400
BEGIN = 800
END = 1024

def send_value(s, N, C, exp):
    # Send first value
    N = int(N)
    C = int(C)
    x = pow(exp, 2, N)
    C = C * x
    C = C % N
    C = str(C)
    s.send(C)
    s.send("\n")

def main():

    # Open output file 
    outfile = open('bytes.txt', 'a')

    # Connect to server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER, PORT))

    # Retrieve the first prompt
    data = s.recv(1024)
    print("Data: {0}".format(data))

    # Retrieve the second prompt
    data = s.recv(1024)
    print("Data: {0}".format(data))

    #
    # Before we can query the oracle, we need to find a string with a sha1 hash that
    # ends in 0xffffff.  The server provides us with a prefix that we need to append 
    # 6 letters to.  We will find an appropriate string via brute force attack.
    #
    match = re.search(r'Give me a string starting with (\S+), of length (\S+), such that its sha1 sum ends in ffffff', data)

    # Extract the prefix and length from the data sent from the server
    hash_prefix = match.group(1)
    hash_length = int(match.group(2))
    print("Prefix to match on: {0}".format(hash_prefix))
    print("Length of hash string: {0}".format(hash_length))

    challenge1 = brute_sha1_suffix(hash_prefix, hash_length - len(hash_prefix))
    s.send(challenge1)

    #
    # The server will tell us the modulus used to encrypt the data.  The exponent (from
    # the provided python code, is 2)
    #
    data = s.recv(2048)
    print("Data: {0}".format(data))
    match = re.search(r'Welcome to the LSB oracle! N = (\S+)', data)
    N = match.group(1)
    print("Value of N: {0}\n".format(N))

    # The server also provides a piece of data that was encrypted
    data = s.recv(2048)
    print("Data: {0}".format(data))
    match = re.search(r'Encrypted Flag: (\S+)', data)
    C = match.group(1)
    print("Value of C: {0}\n".format(C))
    
    N = int(N)
    # There is a begin and end here because the server would reset the socket before I could
    # get all the data needed to decrypt the message.  So, this script needs to be run 
    # several times until all the data is retrieved.
    for i in range(BEGIN, END):

        # Determine which exponent we are currently at, then re-encrypt and send data
        exp = pow(2, i)
        send_value(s, N, C, exp)

        # The server will tell us the least significant bit of the decrypted message
        data = s.recv(2048)
        match = re.search(r'lsb is (\S)', data)
        outfile.write(match.group(1))
        outfile.flush()

        # Server will prompt for another ciphertext
        data = s.recv(2048)

    # Clean up handles
    outfile.close()
    s.close()

main()

