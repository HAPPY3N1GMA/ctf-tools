#!/usr/bin/python

import fileinput, re
from collections import defaultdict

KEY_LENGTH = 4
NUM_LETTERS = 26
letter = defaultdict(int)
letterCount = 0
code = ""

for line in fileinput.input():
	code += line;

code = re.sub(r"[^A-Z]", '', code)

for index in range(0, KEY_LENGTH):
	for i in range(index, len(code), KEY_LENGTH):
		letter[code[i]] += 1;
		letterCount += 1;
	
	print "=========== LETTER INDEX "+str(index+1)+" ==========="
	
	for l in sorted(letter, key=letter.get, reverse=True):
		freq = float(letter[l]) / float(letterCount)
		print l+": "+str(letter[l])+" (num), "+str(freq)+" (freq)"
		letter[l] = 0
		
	letterCount = 0
	
	print
