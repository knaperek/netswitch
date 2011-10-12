#! /usr/bin/env python3

##########################################################################
# Main program
##########################################################################
import pcapo
import sys

def main():

	#ph1 = libpcap()
	#ph2 = libpcap()

	#device

	ph = pcapo.libpcap()
	device = ph.lookupdev()
	if not device:
		print('Device not found!')
		sys.exit(1)
	print('Device:', device)
	lookupnet = ph.lookupnet(device)
	if lookupnet:
		network, netmask = lookupnet
		print('Network:', network)
		print('Netmask:', netmask)
	else:
		print('Error: lookupnet')

# pcap_open_live(...)
	if not ph.open_live(device):
		print(ph.getLastError())
		sys.exit(1)

	if not ph.setdirection(1):
		print('Error setdirection')
		sys.exit(1)


# pcap_next
	counter = 0
	while 1:
		try:
			frame = ph.next()
			if not frame:
				continue
			print('\n************* Frame #{0} Captured! [{1} bytes] ************'.format(counter, len(frame)))
			counter += 1
			pcapo.Dumphex(frame)

			# written = libp.pcap_inject(handle, frame, frame_caplen);
			# print('Paket Injection returned:', written)
		except KeyboardInterrupt:
			print('Aborted by user!')
			break

	ph.close()
	print('ales klar')

if __name__ == '__main__':
	main()
