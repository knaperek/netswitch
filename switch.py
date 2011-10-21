import pcapo
import sys
import threading
import time
from socket import ntohs

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
		self.__filters = dict()
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

			self.printMACtable() # debug

	def listenOnDevice(self, dev):
		ph = self.__ports[dev]
		counter = 0
		while 1:
			frame = ph.next()
			if not frame:
				continue
			#print('***** Frame #{0} Captured [{1} bytes] on interface {2} *******'.format(counter, len(frame), dev))
			counter += 1
			#pcapo.Dumphex(frame)
			#self.printMACtable()
			
			# aktualizovanie zaznamu v MAC tabulke
			dstmac, srcmac = frame[:6], frame[6:12]
			timeleft = 10 # todo
			with self.MACtable_lock: # zamok na MAC tabulku
				self.__mactable[srcmac] = [dev, timeleft] # obnovenie/pridanie zaznamu MAC tabulky

			# preposlanie dalej
			with self.MACtable_lock: # zamok na MAC tabulku
				target_dev = self.__mactable.get(dstmac, [None, None])[0]
			if target_dev: # cielove zariadenie je v mac tabulke
				if target_dev != dev: # ak sa cielove zariadenie nenachadza na segmente, z ktoreho ramec prichadza
					self.sendFrame(target_dev, frame)
			else: # cielove zariadenie nie je v mac tabulke => flooding
				for destdev in [key for key in self.__ports if key != dev]: # pre vsetky porty okrem toho, z ktoreho ramec prisiel
					self.sendFrame(dev, destdev, frame)

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
			else if transport_protocol == 2:
				igmp = True
			else if transport_protocol == 6:
				tcp = True
			else if transport_protocol == 17:
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
		print('*' * 15 + ' MAC Table ' + '*' * 15)
		print('MAC address', '\tIface', 'TTL', sep='\t')
		with self.MACtable_lock:
			for key, value in self.__mactable.items():
				print(bytes2hexstr(key, sep=':'), value[0].decode('utf-8'), value[1], sep='\t')

	# **************************
	# 		filter management
	# **************************
	def addFilter(strfilter):
		self.__filters.append(strfilter)

	def delFilter(iFilter):
		try:
			self.__filters.pop(iFilter)
		except IndexError:
			print('Non-existing filter id!')
	
	def printFilters():
		print('#: filter rule')
		print('---------------')
		num = 0
		for filt in self.__filters:
			num += 1
			print('{0}: {1}'.format(num, filt))


def bytes2hexstr(bytes_buffer, sep=''):
	""" Converts binary bytes buffer to hexa string reprezentation """	
	return sep.join(map(lambda x: '{0:02X}'.format(x), bytes_buffer))

def bytes2decstr(bytes_buffer, sep=''):
	""" Converts binary bytes buffer to decadic string reprezentation """	
	return sep.join(map(lambda x: '{0}'.format(x), bytes_buffer))
