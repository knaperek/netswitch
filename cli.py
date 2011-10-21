#!/usr/bin/env python3

import sys
import switch
import time

dev_list = [b'eth0', b'eth1']
#dev_list = [b'eth0', b'eth1']

#
# Functions
#
last_cmdline = '' # historia: predchadzajuci prikaz
def readCommand(): # Reading command line with auto history
	global last_cmdline
	cmdline = input('> ')
	if not cmdline:
		print('> ' + last_cmdline)	
		cmdline = last_cmdline
	else:
		last_cmdline = cmdline		
	return cmdline
	

##################################################################################
# 									main()
##################################################################################

def main():
	try:
		s = switch.Switch(dev_list)
	except switch.SwitchException as switch_exception:
		print('Chyba:', switch_exception)
		sys.exit(1)

	print('*'*70)
	print(' Network Switch '.center(70, '*'))
	print(' Autor: Jozef Knaperek '.center(70, '*'))
	print('*'*70)
	print()

	try:
		while 1:
			cmdline = readCommand()
			words = cmdline.split()
			if not words:
				continue
			cmd, params = words[0], words[1:]

			if cmd == 'show':
				if not params:
					print('Help: show [arp | filters | stats]') # todo
					continue
				elif params[0] == 'arp':
					s.printMACtable()
				elif params[0] == 'filters':
					s.printFilters()
				elif params[0] == 'stats':
					print('statistiky') # todo
				


	except KeyboardInterrupt:
		print('Ukoncene pouzivatelom')

	print('Program skoncil.')


#####################################################################
#							START
#####################################################################
if __name__ == '__main__':
	main()
