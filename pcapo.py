#!/usr/bin/env python3

import ctypes
from ctypes import *
import sys
import struct
import socket

# constants
PCAP_ERRBUF_SIZE = 256
SIZEOF_PCAP_PKTHDR = 24

class libpcap:
	def __init__(self):
		self.__libpcap = CDLL('libpcap.so') # nacita sa kniznica
		self.__error_buffer = create_string_buffer(PCAP_ERRBUF_SIZE) # pomocny buffer na error hlasky
		self.__pcaphdr_buffer = create_string_buffer(SIZEOF_PCAP_PKTHDR) # buffer na strukturu pcap_pkthdr
		self.__libpcap.pcap_lookupdev.restype = c_char_p # zmena navratovej hodnoty funkcie na string zero retazec. (Defaultna navratova hodnota je int)
		self.__libpcap.pcap_next.restype = POINTER(c_char) # zmena navratovej hodnoty funkcie na general char pointer (that can also point to binary data). (Defaultna navratova hodnota je int)
		self.__handle = None

	#
	# Original libpcap functions (wrapped):	
	#
	def lookupdev(self):
		assert(self.__libpcap)
		assert(self.__error_buffer)
		dev = self.__libpcap.pcap_lookupdev(self.__error_buffer)
		if dev == None:
			print('Chyba 1:', self.__error_buffer.value.decode('utf-8'))
			return None
		return dev #.decode('utf-8') # konverzia na string

	def lookupnet(self, dev):
		assert(self.__libpcap)
		assert(self.__error_buffer)
		assert(sizeof(c_uint) == 4)
		netp = c_uint()
		maskp = c_uint()
		# print('idem lookupovat net pre device', dev)
		ret = self.__libpcap.pcap_lookupnet(dev, byref(netp), byref(maskp), self.__error_buffer)
		if ret == -1:
			print('Chyba 2:', self.__error_buffer.value.decode('utf-8'))
			return None
		return socket.inet_ntoa(struct.pack('<I', netp.value)), socket.inet_ntoa(struct.pack('<I', maskp.value))
	
	def open_live(self, dev):
		assert(self.__libpcap)
		assert(self.__error_buffer)
		# print('otvaram live pre device', dev, type(dev))
		self.__handle = self.__libpcap.pcap_open_live(dev, 1600, 1, 10000, self.__error_buffer)
		# print('handle type:', type(self.__handle), 'value:', self.__handle)
		if not self.__handle:
			print('Chyba 3: nemozem otvorit device', self.__error_buffer.value.decode('utf-8'))
			return False
		return True
		# return bool(self.__handle)

	def setdirection(self, direction_code):
		assert(self.__libpcap)
		assert(self.__handle)
		ret = self.__libpcap.pcap_setdirection(self.__handle, direction_code)
		assert(ret == 0) # musi fungovat filter na zachytavanie only INBOUND ramcov

	def next(self):
		assert(self.__libpcap)
		assert(self.__pcaphdr_buffer)
		assert(self.__handle)
		frameptr = self.__libpcap.pcap_next(self.__handle, self.__pcaphdr_buffer)
		if not frameptr: # ak bol vrateny NULL pointer (=> paket nebol zachyteny, napr. bol odfiltrovany)
			return None
		s_pcaphdr = struct.unpack('<16s2I', self.__pcaphdr_buffer.raw) # prvych 16 bytov je struct timeval - pre timestamp
		frame_caplen = s_pcaphdr[1]
		frame_len = s_pcaphdr[2]
		assert(frame_caplen == frame_len) # chceme zachytit cely frame!
		return frameptr[:frame_caplen]

	def inject(self, frame):
		assert(self.__libpcap)
		assert(self.__handle)
		return self.__libpcap.pcap_inject(self.__handle, frame, len(frame));
		
	def close(self):
		assert(self.__libpcap)
		if self.__handle:
			self.__libpcap.pcap_close(self.__handle)
			self.__handle = None

#
# Extra functions:
#
def Dumphex(data_buffer):
	byty = tuple(map(lambda x: '{0:02X}'.format(x), data_buffer))
	for i in range(len(byty)//16 + 1):
		print(*byty[i*16:(i+1)*16])
		#print(' '.join(byty[i*16:(i+1)*16]))
		

##########################################################################
# body
##########################################################################



def main():
	ph = libpcap()
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

# pcap_open_live(...)
	if not ph.open_live(device):
		sys.exit(1)

	ph.setdirection(1)


# pcap_next

	counter = 0
	while 1:
		try:
			frame = ph.next()
			if not frame:
				continue
			print('\n**************** Frame #{0} Captured! [{1} bytes] ********************'.format(counter, len(frame)))
			counter += 1
			Dumphex(frame)

			# written = libp.pcap_inject(handle, frame, frame_caplen);
			# print('Paket Injection returned:', written)
		except KeyboardInterrupt:
			print('Aborted by user!')
			break

	ph.close()
	print('ales klar')

if __name__ == '__main__':
	main()
