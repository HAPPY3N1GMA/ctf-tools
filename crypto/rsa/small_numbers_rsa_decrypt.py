#!/usr/bin/python

# Finds gcd which is returned as the first value
def gcd(a, b):
	print "gcd of "+str(a)+" and "+str(b)
	if (a == 0):
		return (b, 0, 1)
	else:
		g, y, x = gcd (b % a, a)
		return (g, x - (b//a) * y, y)

# Finds the modular multiplicative inverse
def modinv(a, m):
	g, x, y = gcd(a, m)
	if g != 1:
		raise Exception('modular inverse does not exist')
	else:
		return x % m

# MODIFY VALUES BELOW
p = # CHANGE
q = # CHANGE

# Calculate n, the modulus for the keys
n = p * q

# This value is usally kept private
phi = (p - 1) * (q - 1)

# An integer that is co-prime with phi (the public key)
e = #CHANGE

# Find the modular multiplicative inverse
# d * e = 1 (mod phi)
# This is the private key
d = modinv(e, phi)
print "found mod inverse"

# The cipher text message
c = # CHANGE

# The decrypted message
m = c ** d % n

# Print result
print "p = "+str(p)
print "q = "+str(q)
print "n = "+str(n)
print "phi = "+str(phi)
print "e = "+str(e)
print "d = "+str(d)
print "c = "+str(c)
