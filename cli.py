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
	cmdline = input('> ').strip()
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

	help_show =	lambda: print('Usage: show [mac | filters | stats | all]')
	help_addfilter = lambda: print('Usage: addfilter <filter rule>\nAddress variables: Siface, Diface, Smac, Dmac, Sip, Dip, Sport, Dport\nLogic variables: arp, ip, icmp, igmp, tcp, udp\nOperators: (), ==, !=, not, >, <, >=, <=')
	help_delfilter = lambda: print('Usage: delfilter <#number>')
	help_reset = lambda: print('Usage: reset')
	help_flush = lambda: print('Usage: flush [mac | filters | stats | all]')

	try:
		while 1:
			cmdline = readCommand()
			words = cmdline.split(' ', 1) # oddeli prikaz a parametre
			if not words:
				continue
			cmd, params = words[0], words[1:]

			if params:
				param = params[0] # ak su dalsie parametre, tak su v jednom retazci

			if 'show'.startswith(cmd):
				if not params:
					help_show()
					continue
				for p in param.split():
					if 'mac'.startswith(p):
						s.printMACtable()
					elif 'filters'.startswith(p):
						s.printFilters()
					elif 'stats'.startswith(p):
						s.printStats()
					elif 'all'.startswith(p):
						s.printMACtable()
						s.printFilters()
						s.printStats()
					else:
						help_show()
						break

			elif 'addfilter'.startswith(cmd):
				if not params:
					help_addfilter()	
					continue
				if not s.addFilter(param):
					print('Error: Bad filter syntax!')
					help_addfilter()

			elif 'delfilter'.startswith(cmd):
				if not params:
					help_delfilter()
					continue
				filterid = int(param) - 1
				if filterid < 0 or not s.delFilter(filterid):
					print('Error: non-existing filter #ID')
					help_delfilter()
				print('Filter successfully added')

			elif 'reset'.startswith(cmd):
				if not params:
					s.flushMACtable()
					s.delAllFilters()
					s.resetStats()
				else:
					help_reset()

			elif 'flush'.startswith(cmd):
				if not params:
					help_flush()
				elif 'mac'.startswith(param):
					s.flushMACtable()
				elif 'filters'.startswith(param):
					s.delAllFilters()
				elif 'stats'.startswith(param):
					s.resetStats()
				elif 'all'.startswith(param): # same as reset
					s.flushMACtable()
					s.delAllFilters()
					s.resetStats()
				else:
					help_flush()

			elif 'help'.startswith(cmd):
				print('-'*80)
				print(' Help '.center(80, '-'))
				print('-'*80)
				print('\nCOMMANDS: show, addfilter, delfilter, reset, flush, quit.')
				print('Hint: press <enter> to repeat previously entered command.')
				print('\n> show: shows various information. Can be used with multiple parameters at once.')
				help_show()
				print('\n> addfilter: adds filter rule for frame filtering.')
				help_addfilter()
				print('\n> delfilter: deletes specified filter rule.')
				help_delfilter()
				print('\n> reset: sets switch to default state (deletes mac table, statistics and filters). Same as flush all.')
				help_reset()
				print('\n> flush: cleans up specified buffer (mac table, statistics or filters)')
				help_flush()
				print('\n> quit: exits the program')
				print('Usage: quit')
				print()
			elif 'quit'.startswith(cmd):
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
