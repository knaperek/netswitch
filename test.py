#!/usr/bin/env python3

import sys
import switch
import time

dev_list = [b'eth0', b'eth1']
#dev_list = [b'eth0', b'eth1']

try:
	s = switch.Switch(dev_list)
except switch.SwitchException as switch_exception:
	print('Chyba:', switch_exception)
	sys.exit(1)

print('Zaciatok hlavnej slucky')
try:
	while 1:
		time.sleep(3)
except KeyboardInterrupt:
	print('Ukoncene pouzivatelom')

print('koniec hlavneho vlakna')


