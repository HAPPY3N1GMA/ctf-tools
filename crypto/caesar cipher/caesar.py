#!/usr/bin/python

cipher = raw_input()

for i in range(1, 26):
	plain = ""
	for c in cipher:
		if (ord(c) >= 97 and ord(c) <= 122):
			newC = ((ord(c)-97 + i) % 26) + 97
			plain += chr(newC)
		elif (ord(c) >= 65 and ord(c) <= 90):
			newC = ((ord(c)-65 + i) % 26) + 65
			plain += chr(newC)
		else:
			plain += c
	print plain
