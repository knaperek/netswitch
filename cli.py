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

	help_show =	lambda: print('Usage: show [mac | filters | stats]')
	help_addfilter = lambda: print('Usage: addfilter <filter rule>\nAddress variables: Siface, Diface, Smac, Dmac, Sip, Dip, Sport, Dport\nLogic variables: arp, ip, icmp, igmp, tcp, udp\nOperators: (), ==, !=, not, >, <, >=, <=')
	help_delfilter = lambda: print('Usage: delfilter <#number>')
	help_reset = lambda: print('Usage: reset')
	help_flush = lambda: print('Usage: flush [mac | filters | stats]')

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
				if not params:
					help_addfilter()	
					continue
				if not s.addFilter(param):
					print('Error: Bad filter syntax!')
					help_addfilter()

			elif cmd == 'delfilter':
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
					help_reset()

			elif cmd == 'flush':
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

			elif cmd == 'help':
				print('--- Help ---')
				print('Commands: show, addfilter, delfilter, reset, flush, quit.')
				print('Hint: press <enter> to repeat previously entered command.')
				print()
				print('show: shows various information. Can be used with multiple parameters at once.')
				help_show()
				print()
				print('addfilter: adds filter rule for frame filtering.')
				help_addfilter()
				print()
				print('delfilter: deletes specified filter rule.')
				help_delfilter()
				print()
				print('reset: sets switch to default state (deletes mac table, statistics and filters).')
				help_reset()
				print()
				print('flush: cleans up specified buffer (mac table, statistics or filters)')
				help_flush()
				print()
				print('quit: exits the program')
				print('Usage: quit')
				print()
			elif cmd == 'quit':
				break

			else: # unknown command
				print('Unknown command')

	except (KeyboardInterrupt, EOFError):
		print('Aborted by user')

	print('Program ended.')


#####################################################################
#							START
#####################################################################
if __name__ == '__main__':
	main()
