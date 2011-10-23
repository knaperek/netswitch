#!/usr/bin/env python3

import sys
import switch
import time

SW = 80 # Screen Width
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

def help_show():
	print('Usage: show [mac | filters | stats | all]\n')

def help_addfilter():
	print("""Usage: addfilter <filter rule>
	Address variables: Siface, Diface, Smac, Dmac, Sip, Dip, Sport, Dport
	Logic variables: arp, ip, icmp, igmp, tcp, udp
	Well-known ports: SSH, Telnet, HTTP, HTTPS, FTP, TFTP, SFTP, POP3,
			  IMAP, IMAPS, SMTP, LDAP, DNS, NTP, SNMP, RIP
	Operators: (), ==, !=, not, >, <, >=, <=')\n""")

def help_delfilter():
	print('Usage: delfilter <#number>\n')

def help_reset():
	print('Usage: reset\n')

def help_flush():
	print('Usage: flush [mac | filters | stats | all]\n')

def help_loop():
	print('Usage: loop <command>\n')

def processCommand(cmdline, s):
	words = cmdline.split(' ', 1) # oddeli prikaz a parametre
	if not words:
		return
	cmd, params = words[0], words[1:]
	cmd = cmd.lower()

	if params:
		param = params[0] # ak su dalsie parametre, tak su v jednom retazci

	if 'show'.startswith(cmd):
		if not params:
			help_show()
			return
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
			return
		if not s.addFilter(param):
			print('Error: Bad filter syntax!')
			help_addfilter()
		else:
			print('Filter added.\n')

	elif 'delfilter'.startswith(cmd):
		if not params:
			help_delfilter()
			return
		filterid = int(param) - 1
		if filterid < 0 or not s.delFilter(filterid):
			print('Error: non-existing filter #ID')
			help_delfilter()
		else:
			print('Filter #{0} deleted.\n'.format(filterid + 1))

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
		print('\nCOMMANDS: show, addfilter, delfilter, reset, flush, loop, quit.')
		print('Hint: press <enter> to repeat previously entered command.\n')
		print('> SHOW: shows various information. Can be used with multiple parameters at once.')
		help_show()
		print('> ADDFILTER: adds filter rule for frame filtering.')
		help_addfilter()
		print('> DELFILTER: deletes specified filter rule.')
		help_delfilter()
		print('> RESET: sets switch to default state (deletes mac table, statistics and filters).')
		help_reset()
		print('> FLUSH: cleans up specified buffer (mac table, statistics or filters)')
		help_flush()
		print('> LOOP: runs specified command every second until Ctrl+C is pressed.')
		help_loop()
		print('> QUIT: exits the program')
		print('Usage: quit')
		print()
		print('-'*80)
		print()

	elif 'quit'.startswith(cmd):
		raise EOFError()

	else: # unknown command
		print('Unknown command')


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

	print('_'*SW)
	print('|'+' '*(SW-2)+'|')
	print('|'+' Multilayer Network Switch '.center(SW-2, ' ')+'|')
	print('|'+' '*(SW-2)+'|')
	print('|'+' Autor: Jozef Knaperek '.center(SW-2, ' ')+'|')
	print('|'+' '*(SW-2)+'|')
	print('|' + ('[' + ']<==>['.join(dev_list) + ']').center(SW-2) + '|')
	print('|' + '_'*(SW-2) + '|')
	print()

	try:
		while 1:
			cmdline = readCommand()
			if cmdline:
				words = cmdline.split(' ', 1) # oddeli prikaz a parametre
				if not words:
					return
				cmd, params = words[0], words[1:]
				cmd = cmd.lower()

				if 'loop'.startswith(cmd):
					if not params:
						help_loop()
						continue
					try:
						while 1:
							processCommand(params[0], s)
							time.sleep(1)

					except KeyboardInterrupt:
						print('\nLoop ended.\n') # ukoncenie opakovania prikazu

				else:
					processCommand(cmdline, s)

	except (KeyboardInterrupt, EOFError):
		print('Aborted by user')

	print('Program ended.')


#####################################################################
#							START
#####################################################################
if __name__ == '__main__':
	main()
