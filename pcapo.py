#!/usr/bin/env python3

import ctypes
from ctypes import *
import sys
import struct
import socket

# constants
PCAP_ERRBUF_SIZE = 256
SIZEOF_PCAP_PKTHDR = 24
LIBPCAP_LIBRARY_NAME = 'libpcap.so'

class PcapDeviceException(Exception):
	def __init__(self, errmsg):
		self.__errmsg = errmsg

	def __str__(self):
		return repr(self.__errmsg)

class libpcap:
	def __init__(self):
		""" Initializes object's variables and loads libpcap library. """

		self.__libpcap = CDLL(LIBPCAP_LIBRARY_NAME) # libpcap library loading
		self.__error_buffer = create_string_buffer(PCAP_ERRBUF_SIZE) # pomocny buffer na error hlasky
		self.__pcaphdr_buffer = create_string_buffer(SIZEOF_PCAP_PKTHDR) # buffer na strukturu pcap_pkthdr
		self.__libpcap.pcap_lookupdev.restype = c_char_p # zmena navratovej hodnoty funkcie na string zero retazec. (Defaultna navratova hodnota je int)
		self.__libpcap.pcap_next.restype = POINTER(c_char) # zmena navratovej hodnoty funkcie na general char pointer (that can also point to binary data). (Defaultna navratova hodnota je int)
		self.__handle = None

	def getLastError(self):
		""" Returns string containing a message with last error details. Call this method after some of libpcap methods below fails. """	

		return self.__error_buffer.value.decode('utf-8')

	#
	# Original libpcap functions (wrapped):	
	#
	def lookupdev(self):
		""" Returns found device as bytes object or None. """

		assert(self.__libpcap)
		assert(self.__error_buffer)
		dev = self.__libpcap.pcap_lookupdev(self.__error_buffer)
		return dev

	def lookupnet(self, dev):
		""" Returns a tuple containing the pair of network and mask or None indicating failure. """
		assert(self.__libpcap)
		assert(self.__error_buffer)
		assert(sizeof(c_uint) == 4)
		netp = c_uint()
		maskp = c_uint()
		ret = self.__libpcap.pcap_lookupnet(dev, byref(netp), byref(maskp), self.__error_buffer)
		if ret == -1:
			return None
		return socket.inet_ntoa(struct.pack('<I', netp.value)), socket.inet_ntoa(struct.pack('<I', maskp.value))
	
	def open_live(self, dev):
		""" Returns bool value reprezenting success/fail. Requires dev name as object of bytes type. """

		assert(self.__libpcap)
		assert(self.__error_buffer)
		self.__handle = self.__libpcap.pcap_open_live(dev, 1600, 1, 10000, self.__error_buffer) # opening live for device dev
		if not self.__handle:
			raise PcapDeviceException(self.getLastError())
		return bool(self.__handle)

	def setdirection(self, direction_code):
		""" Returns bool value reprezenting success/fail. Requires direction code as int object. For meaning of the values, please see libpcap documentation. """

		assert(self.__libpcap)
		assert(self.__handle)
		ret = self.__libpcap.pcap_setdirection(self.__handle, direction_code)
		if ret:
			raise PcapDeviceException(self.getLastError())
		return bool(ret == 0) # return value indicates if the call was successful

	def next(self):
		""" Returns captured frame as object of bytes type, or None. """

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
		return bytes(frameptr[:frame_caplen]) # s konverziou na unmutable (~hashable) typ

	def inject(self, frame):
		""" Returns the number of injected bytes. """

		assert(self.__libpcap)
		assert(self.__handle)
		return self.__libpcap.pcap_inject(self.__handle, frame, len(frame));
		
	def close(self):
		""" Makes cleanup. Please call this method at the end. """

		assert(self.__libpcap)
		if self.__handle:
			self.__libpcap.pcap_close(self.__handle)
			self.__handle = None

#
# Extra functions:
#
def Dumphex(data_buffer):
	""" Prints binary data buffer in hexadecimal format with 16 bytes per line. """

	byty = tuple(map(lambda x: '{0:02X}'.format(x), data_buffer))
	for i in range(len(byty)//16 + 1):
		print(*byty[i*16:(i+1)*16])
		#print(' '.join(byty[i*16:(i+1)*16])) # maybe faster ?
		

##########################################################################
# demo test body
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
	print('End.')

if __name__ == '__main__':
	main()
