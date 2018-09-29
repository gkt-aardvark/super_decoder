#!/usr/bin/env python 
#examples of some OUIs
#f0:ab:54 mitsumi
#a0:63:91 Netgear
#10:56:11 Arris
#00:30:44 Cradlepoint
#try those and also a2:63:91, which is common for netgear extenders and guestnets
#02:30:44, common for cradlepoint second wifi
#12:56:11, 22:56:11, 42:56:11, etc which are common on Arris for xfinity
#
from sqlite3 import Connection
from sys import argv

def mutator (mac):
	
	#category of some common variations, default is "variations on first byte" seen later
	category = {0: 'Registered OUI', 1: 'Second nibble - 2', 2: 'Second nibble - 6', 3: 'Second nibble - 10'}
	
	#macvendors database taken from oui.txt from IEEE
	OUI_CON = Connection('./databases/macvendors.db')
	OUI_CUR = OUI_CON.cursor()
	
	#strip down the input mac or oui to just 6 hex digits, in text, uppercased
	oui = mac.replace(':', '').replace('-', '').replace('.', '').upper()[0:6]
	
	#pull first and second nibbles
	n1 = int(oui[0], 16) * 16
	n2 = int(oui[1], 16)
	
	#define all possible byte variations for later matchin
	bytes = [n1 + n2, (n1 + n2) - 2, (n1 + n2) - 6, (n1 + n2) - 10,\
			n2 - 2, (0x10 + n2) - 2, (0x20 + n2) - 2, (0x30 + n2) - 2,\
			(0x40 + n2) - 2, (0x50 + n2) - 2, (0x60 + n2) - 2,
			(0x70 + n2) - 2, (0x80 + n2) - 2, (0x90 + n2) - 2,\
			(0xa0 + n2) - 2, (0xb0 + n2) - 2, (0xc0 + n2) - 2,\
			(0xd0 + n2) - 2, (0xe0 + n2) - 2, (0xf0 + n2) - 2]
	
	#uppercase and convert to hex strings and add back the rest of the oui
	bytes = [hex(byte)[2:].upper() + oui[2:] for byte in bytes]
	
	#look for all of them in the database using enumerate
	#using enumerate will keep a running tab of the current index to be
	#able to use the category dictionary above without if statements
	for index, byte in enumerate(bytes):
		OUI_CUR.execute('SELECT vendor FROM macvendors WHERE mac="{}";'.format(byte))
		hit = OUI_CUR.fetchone()
		if hit != None:
			result, oui_match = hit[0].rstrip(), byte
			OUI_CON.close()
			return (oui, oui_match, result, category.get(index, 'Variations on first byte')) #default category
	
	return (oui, 'None', 'No Vendor Found', 'Unknown - Possibly random')
	

if __name__ == '__main__':
	mac = argv[1]
	results = mutator(mac)
	print 'Original MAC: {}'.format(mac)
	print 'Original OUI: {}'.format(results[0])
	print 'Matching OUI: {}'.format(results[1])
	print 'Vendor: {}'.format(results[2])
	print 'Category: {}'.format(results[3])