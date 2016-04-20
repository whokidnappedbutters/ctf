#!/usr/bin/python

from util import *
import hashlib
import time
import socket
import re



def send_value(s, N, C, exp):
	# Send first value
	N = int(N)
	C = int(C)
	x = pow(exp, 2, N)
	C = C * x
	C = C % N
	C = str(C)
	#print("Testing ciphertext: {0}".format(C))
	s.send(C)
	s.send("\n")

def main():

	outfile = open('bytes.txt', 'a')

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('rabit.pwning.xxx', 7763))

	data = s.recv(1024)
	print("Data: {0}".format(data))

	data = s.recv(1024)
	print("Data: {0}".format(data))

	match = re.search(r'Give me a string starting with (\S+), of length (\S+), such that its sha1 sum ends in ffffff', data)

	hash_prefix = match.group(1)
	hash_length = match.group(2)

	print("Prefix to match on: {0}".format(hash_prefix))
	print("Length of hash string: {0}".format(hash_length))

	challenge1 = find_hash_string(hash_prefix)
	s.send(challenge1)

        # retrieve N
	data = s.recv(2048)
	print("Data: {0}".format(data))
	match = re.search(r'Welcome to the LSB oracle! N = (\S+)', data)
	N = match.group(1)
	print("Value of N: {0}\n".format(N))

	# Encrypted data
	data = s.recv(2048)
	print("Data: {0}".format(data))
	match = re.search(r'Encrypted Flag: (\S+)', data)
	C = match.group(1)
	print("Value of C: {0}\n".format(C))
	
	N = int(N)
	for i in range(1024,1025):

		exp = pow(2, i)
		send_value(s, N, C, exp)

		# Prompt for our ciphertext
		data = s.recv(2048)
		print("Data: {0}".format(data))
 		
		match = re.search(r'lsb is (\S)', data)
		lsb = int(match.group(1))
		print("Value of lsb: {0}".format(lsb))	
		if lsb == 0:
			outfile.write('0')
			outfile.flush()
		else:
			outfile.write('1')
			outfile.flush()

		print("Diff:  {0}\n".format((N / exp)))	

		data = s.recv(2048)
		print("Data: {0}".format(data))

		if exp >= N:
			print("Number of iterations: {0}".format(i))
			break

	outfile.close()
	s.close()

main()

