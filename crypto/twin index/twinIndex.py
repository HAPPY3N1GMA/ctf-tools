#!/usr/bin/python

import fileinput, re

NUM_LETTERS = 26
prev = ''
curr = ''
doubleCount = 0
letterCount = 0
TI = 0.0

for line in fileinput.input():
	line = re.sub(r'[^A-Za-z]', '', line)
	line.upper()
	for i in range(0, len(line)):
		letterCount += 1
		curr = line[i]
		if (curr == prev):
			doubleCount += 1
		prev = curr

TI = (float(doubleCount) / float(letterCount - 1)) * float(NUM_LETTERS)
print TI
