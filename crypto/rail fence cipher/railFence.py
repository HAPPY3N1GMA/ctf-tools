#!/usr/bin/python

# CREDIT GOES TO GEORG FOR THE FOUNDATIONS OF THIS SCRIPT
# http://stackoverflow.com/questions/14519227/rail-fence-cipher-looking-for-a-better-solution
# I added the ability to start the railfence cipher at different rails.

import re

message = "Nwh whdjwh qm uepen, T tjb fsmt tixgi jsrsh sigm gs mpzp xwqf iahxpv iw fslkt. pehgpxf{qtextz_glacz_elt_neinrw_qsg_bums_dcp}"

def fence(lst, numrails, start):
    fence = [[None] * len(lst) for n in range(numrails)]
    rails = range(0 + start, numrails-1) + range(numrails-1, 0, -1) + range(0, start)
    for n, x in enumerate(lst):
        fence[rails[n % len(rails)]][n] = x
    return [c for rail in fence for c in rail if c is not None]

def encode(text, n):
    return ''.join(fence(text, n))

def decode(text, n, start):
    rng = range(len(text))
    pos = fence(rng, n, start)
    return ''.join(text[pos.index(n)] for n in rng)

def shift (text, n):
	newText = text[n:]
	newText += text[:n]
	return newText


for i in range (0, len(message)):
	newMessage = shift(message, i)
	for i in range(2, 20):
		for k in range (1, i):
			d = decode(newMessage, i, k)
			if (re.findall('easyctf{', d)):
				print d+"\n"
