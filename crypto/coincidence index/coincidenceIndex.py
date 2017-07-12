#!/usr/bin/python

import fileinput, re
from collections import defaultdict

NUM_LETTERS = 26
KEY_LENGTHS = range(1, 20)

for KEY_LENGTH in KEY_LENGTHS:
	letterCount = 0

	strings = []

	for i in range(0, KEY_LENGTH):
		strings.append(defaultdict(int))

	for line in fileinput.input('input'):
		line = re.sub(r'[^A-Za-z]', '', line)	
		for c in line:
			strings[letterCount % KEY_LENGTH][c] += 1
			letterCount += 1

	letterCount /= KEY_LENGTH
	totalIC = 0.0

	for index in strings:
		IC = 0.0
	
		for c in index:
			IC += index[c] * (index[c] - 1)	

		IC /= (float(letterCount) * float(letterCount - 1) / float(NUM_LETTERS))
		
		totalIC += IC

	IC = totalIC/KEY_LENGTH

	print (str(KEY_LENGTH)+": Coincidence index = " + str(IC)+"\n")
