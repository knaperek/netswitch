import pcapo
import sys
import threading
import time
import struct

class SwitchException(Exception):
	def __init__(self, errmsg):
		self.__errmsg = errmsg

	def __str__(self):
		return repr(self.__errmsg)


class Switch:
	
	MACtable_lock = threading.Lock()

	def __init__(self, device_list):
		
		self.__mactable = dict()
		self.__ports = dict()
		self.__filters = list()
		try: # inicializacia portov (interfejsov)
			for dev in device_list:
				self.__ports[dev] = pcapo.libpcap()
				self.__ports[dev].open_live(bytes(dev))
				self.__ports[dev].setdirection(1)
		except pcapo.PcapDeviceException as errmsg:
			raise SwitchException('Fatal error during switch initialization:' + str(errmsg))
		self.start_switching()
		self.start_aging()	
	
	def start_switching(self):
		for dev in self.__ports: # spustanie threadov pre kazdy port (interface)
			hThread = threading.Thread(target=lambda: self.listenOnDevice(dev))
			hThread.daemon = True
			hThread.start()
	
	def start_aging(self):
		hThread = threading.Thread(target=lambda: self.doAging())
		hThread.daemon = True
		hThread.start()

	def doAging(self):
		while 1:
			time.sleep(1)
			with self.MACtable_lock: # zamok na MAC tabulku
				for value in self.__mactable.values():
					value[1] -= 1
				oldkeys = [key for key, value in self.__mactable.items() if value[1] <= 0]
				for oldkey in oldkeys:
					self.__mactable.pop(oldkey) # odstranenie stareho zaznamu

			#self.printMACtable() # debug

	def listenOnDevice(self, listen_dev):
		ph = self.__ports[listen_dev]
		counter = 0
		while 1:
			frame = ph.next()
			if not frame:
				continue
			#print('***** Frame #{0} Captured [{1} bytes] on interface {2} *******'.format(counter, len(frame), listen_dev))
			counter += 1
			#pcapo.Dumphex(frame)
			#self.printMACtable()
			
			# aktualizovanie zaznamu v MAC tabulke
			dstmac, srcmac = frame[:6], frame[6:12]
			timeleft = 300 # todo
			with self.MACtable_lock: # zamok na MAC tabulku
				self.__mactable[srcmac] = [listen_dev, timeleft] # obnovenie/pridanie zaznamu MAC tabulky

			# preposlanie dalej
			with self.MACtable_lock: # zamok na MAC tabulku
				target_dev = self.__mactable.get(dstmac, [None, None])[0]
			if target_dev: # cielove zariadenie je v mac tabulke
				if target_dev != listen_dev: # ak sa cielove zariadenie nenachadza na segmente, z ktoreho ramec prichadza
					self.sendFrame(listen_dev, target_dev, frame)
			else: # cielove zariadenie nie je v mac tabulke => flooding
				for idev in [key for key in self.__ports if key != listen_dev]: # pre vsetky porty okrem toho, z ktoreho ramec prisiel
					self.sendFrame(listen_dev, idev, frame)

	def sendFrame(self, fromdev, todev, frame): # fromdev is required for filtering!
		# initialization of variables (default values)
		l3offset, l4offset = 0,0
		Siface, Diface, Smac, Dmac, Sip, Dip, Sport, Dport = (None,)*8
		ip, icmp, igmp, tcp, udp = (False,)*5
		l3type = None

		# L1:
		Siface, Diface = fromdev[:], todev[:] # todo: osetrit bytes vs str (comparision!)

		# L2:
		Dmac, Smac = bytes2hexstr(frame[:6], sep=':'), bytes2hexstr(frame[6:12], sep=':')

		frameEth, frame802 = False, False # inicializacia na false
		TypeLen = ntohs(frame[12:14])
		if TypeLen >= 0x600: # (1536) Ethernet II
			l3offset = 14
			l3type = TypeLen
			frameEth, frame802 = True, False
		else: # (<= 0x5DC ~ 1500) 802.3
			if frame[14] == 0xAA: # (DSAP == 0xAA) => SNAP header following
				l3offset = 22
				l3type = ntohs(frame[20:22])
				frame802, frameEth = True, False
			else:
				print('Error: unsupported frame type')
				# return # unsupported frame type

		# L3:
		if l3type == 0x800: # IPv4
			ip = True
			transport_protocol = frame[l3offset+9]
			Sip = bytes2decstr(frame[l3offset+12:l3offset+16], sep='.') # Source IP
			Dip = bytes2decstr(frame[l3offset+16:l3offset+20], sep='.') # Destination IP
			l4offset = l3offset + 20
			if transport_protocol == 1:
				icmp = True
			elif transport_protocol == 2:
				igmp = True
			elif transport_protocol == 6:
				tcp = True
			elif transport_protocol == 17:
				udp = True
			
		# L4:
		if tcp or udp:
			Sport = ntohs(frame[l4offset+0:l4offset+2])
			Dport = ntohs(frame[l4offset+2:l4offset+4])

		# Constants:
		SSH = 22
		Telnet = 23
		HTTP = 80
		HTTPS = 443
		FTP = 21
		TFTP = 69
		SFTP = 115
		POP3 = 995
		IMAP = 143
		IMAPS = 993
		SMTP = 25
		LDAP = 389
		DNS = 53
		NTP = 123
		SNMP = 161
		RIP = 520
		
		# aplikovanie filtrov
		for filt in self.__filters:
			try:
				if eval(filt):
					return # ramec bol odfiltrovany
			except:
				pass # filter zlyhal, ramec sa povazuje za nevyhovujuci danemu pravidlu

		# ramec nebol na zaklade pravidiel odfiltrovany a bude preposlany
		self.__ports[todev].inject(frame)
	
	def printMACtable(self):
		print('_'*70)
		print('*'*70)
		print(' MAC Table '.center(70, '*'))
		print('*'*70)
		print('MAC address', '\tIface', '\tTTL', sep='\t')
		print('-'*70)
		with self.MACtable_lock:
			for key, value in self.__mactable.items():
				print(bytes2hexstr(key, sep=':'), value[0].decode('utf-8'), value[1], sep='\t')
		print('_'*70)

	def flushMACtable(self):
		with self.MACtable_lock:
			self.__mactable.clear()


	# ****************************************************************************
	# 						filter management
	# ****************************************************************************

	def checkFilter(self, strfilter): # checks filter syntax
		#initialization of all variables and constants
		SSH, Telnet, HTTP, HTTPS, FTP, TFTP, SFTP, POP3, IMAP, IMAPS, SMTP, LDAP, DNS, NTP, SNMP, RIP = (1,)*16
		Sport, Dport = 1, 1
		Siface, Diface, Smac, Dmac, Sip, Dip = ('string', )*6
		ip, icmp, igmp, tcp, udp = (False,)*5
		try:
			eval(strfilter)
		except:
			return False # filter syntax error
		return True # fiter syntax (likely) ok
		
	def addFilter(self, strfilter):
		if self.checkFilter(strfilter):
			self.__filters.append(strfilter)
			return True
		else:
			return False # filter syntax error

	def delFilter(self, iFilter):
		try:
			self.__filters.pop(iFilter)
		except IndexError:
			#print('Non-existing filter id!')
			return False # Non-existing filter id
		return True

	def delAllFilters(self):
		self.__filters = list()
	
	def printFilters(self):
		print('_'*70)
		print('*'*70)
		print(' Filters '.center(70, '*'))
		print('*'*70)
		print('#\tFilter rule')
		print('-'*70)
		#print(' Filters '.center(70, '*'))
		#print('#: Filter rule')
		#print('-'*70)
		num = 0
		for filt in self.__filters:
			num += 1
			print('{0}\t{1}'.format(num, filt))
		print()


	##################################################################
	#				Statistiky
	##################################################################
	
	def printStats():
		pass

	def resetStats():
		pass


def bytes2hexstr(bytes_buffer, sep=''):
	""" Converts binary bytes buffer to hexa string reprezentation """	
	return sep.join(map(lambda x: '{0:02X}'.format(x), bytes_buffer))

def bytes2decstr(bytes_buffer, sep=''):
	""" Converts binary bytes buffer to decadic string reprezentation """	
	return sep.join(map(lambda x: '{0}'.format(x), bytes_buffer))

def ntohs(bytes_buffer):
	if len(bytes_buffer) == 2:
		return struct.unpack('!H', bytes_buffer)[0]
	else:
		print('ntohs error') # debug
		return 0

