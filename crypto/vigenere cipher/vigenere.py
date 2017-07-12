#!/usr/bin/python

import fileinput, re
from collections import defaultdict

KEY_LENGTHS = range(2,20)
NUM_LETTERS = 26
letters = {'A':0, 'B':1, 'C':2, 'D':3, 'E':4, 'F':5, 'G':6, 'H':7, 'I':8, 'J':9, 'K':10, 'L':11, 'M':12, 'N':13, 'O':14, 'P':15, 'Q':16, 'R':17, 'S':18, 'T':19, 'U':20, 'V':21, 'W':22, 'X':23, 'Y':24, 'Z':25}


for KEY_LENGTH in KEY_LENGTHS:

	code = ""
	testWords = {''}
	results = defaultdict(list)

	# Function that decodes vigenere cipher
	def decode(code, key):
		message = ""
		key = key.upper()
		for i in range(0, len(code)):
			keyIndex = i % KEY_LENGTH
			mIndex = (letters[code[i]]-letters[key[keyIndex]]) % NUM_LETTERS
			message += chr(mIndex+65)
		return message


	# Get encoded text
	for line in fileinput.input():
		code += line;
	code = re.sub(r"[^A-Z]", '', code)
	print "========== Encrypted =========="
	print code + "\n"

	# Get keys and decode messages
	for key in fileinput.input():
		key = re.sub(r"[^A-Za-z]", '', key)
	
		if (len(key) == KEY_LENGTH):
			score = 0
			decoded = decode(code, key)
			print "========== Decrypyed ("+key+") =========="
			print decoded
			for test1 in testWords:
				if (re.search(test1, decoded)):
					score += 1
			if (score >= 1):
				print "SUCCESS!!!"
				results[score].append(decoded+" ("+key+")")			

	# Print results
	out = open("output", 'a')
	for k in sorted(results):
		for r in results[k]:		
			out.write(r+"\n\n")
	out.close()
