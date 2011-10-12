#!/usr/bin/env python3

import sys
import switch
import pcapo

dev_list = [b'eth0', b'eth1']
#dev_list = [b'eth0', b'eth1']

try:
	s = switch.Switch(dev_list)
except pcapo.PcapDeviceException as pcap_exception:
	print('Chyba:', pcap_exception)
	sys.exit(1)


