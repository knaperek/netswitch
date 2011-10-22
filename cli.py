#!/usr/bin/env python3

import sys
import switch
import time

dev_list = ['eth0', 'eth1']

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
			words = cmdline.split(' ', 1) # oddeli prikaz a parametre
			if not words:
				continue
			cmd, params = words[0], words[1:]

			if params:
				param = params[0] # ak su dalsie parametre, tak su v jednom retazci

			if cmd == 'show':
				if not params:
					print('Help: show [mac | filters | stats]') # todo
					continue
				if param == 'mac':
					s.printMACtable()
				elif param == 'filters':
					s.printFilters()
				elif param == 'stats':
					s.printStats()

			elif cmd == 'addfilter':
				if not params:
					print('Help: addfilter <filter rule>')
					continue
				if not s.addFilter(param):
					print('Error: Bad filter syntax!')

			elif cmd == 'delfilter':
				if not params:
					print('Help: rmfilter <#number>')
					continue
				filterid = int(param) - 1
				if filterid < 0 or not s.delFilter(filterid):
					print('Error: non-existing filter #ID')

			elif cmd == 'reset':
				if not params:
					s.delAllFilters()
					s.flushMACtable()
					s.resetStats()

			elif cmd == 'flush':
				if not params:
					print('Help: flush [mac | filters | stats]')
				elif param == 'mac':
					s.flushMACtable()
				elif param == 'filters':
					s.delAllFilters()
				elif param == 'stats':
					s.resetStats()

			else: # unknown command
				print('Unknown command')

	except (KeyboardInterrupt, EOFError):
		print('Ukoncene pouzivatelom')

	print('Program skoncil.')


#####################################################################
#							START
#####################################################################
if __name__ == '__main__':
	main()
