#!/usr/bin/env python3

import sys
import switch
import time

default_dev_list = ['eth0', 'eth1']

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
	dev_list = sys.argv[1:]
	if len(dev_list) < 2:
		dev_list = default_dev_list
	try:
		s = switch.Switch(dev_list)
	except switch.SwitchException as switch_exception:
		print('Chyba:', switch_exception)
		sys.exit(1)

	print('*'*70)
	#print(' Network Switch '.center(70, '*'))
	print((' Network Switch: ' + ' -- '.join(dev_list) + ' ').center(70, '*'))
	print('*'*70)
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
				help_show =	lambda: print('Help: show [mac | filters | stats]')
				if not params:
					help_show()
					continue
				for p in param.split():
					if p == 'mac':
						s.printMACtable()
					elif p == 'filters':
						s.printFilters()
					elif p == 'stats':
						s.printStats()
					else:
						help_show()
						break

			elif cmd == 'addfilter':
				help_addfilter = lambda: print('Help: addfilter <filter rule>')
				if not params:
					help_addfilter()	
					continue
				if not s.addFilter(param):
					print('Error: Bad filter syntax!')
					help_addfilter()

			elif cmd == 'delfilter':
				help_delfilter = lambda: print('Help: delfilter <#number>')
				if not params:
					help_delfilter()
					continue
				filterid = int(param) - 1
				if filterid < 0 or not s.delFilter(filterid):
					print('Error: non-existing filter #ID')
					help_delfilter()
				print('Filter successfully added')

			elif cmd == 'reset':
				if not params:
					s.delAllFilters()
					s.flushMACtable()
					s.resetStats()
				else:
					print('Help: reset')

			elif cmd == 'flush':
				help_flush = lambda: print('Help: flush [mac | filters | stats]')
				if not params:
					help_flush()
				elif param == 'mac':
					s.flushMACtable()
				elif param == 'filters':
					s.delAllFilters()
				elif param == 'stats':
					s.resetStats()
				else:
					help_flush()

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
