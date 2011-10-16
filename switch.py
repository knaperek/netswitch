import pcapo
import sys
import threading
import time

# class Port(threading.Thread):
#
#	MAC_Table = dict()
#	Switch_Lock = threading.Lock()
#
#	def __init__(self, interface_name):
#		super().__init__()
#		self.__interface_name = interface_name
#		MAC_Table[interface_name] = 

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
		# try: # inicializacia portov (interfejsov)
		for dev in device_list:
			self.__ports[dev] = pcapo.libpcap()
			self.__ports[dev].open_live(dev)
			self.__ports[dev].setdirection(1)
		#except pcapo.PcapDeviceException as errmsg:
			#raise SwitchException('Fatal error during switch initialization:' + errmsg)
		#	raise SwitchException(str(errmsg))
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
				for oldkey in [key for key, value in self.__mactable.items() if value[1] <= 0]:
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
			timestamp = 10 # todo
			with self.MACtable_lock: # zamok na MAC tabulku
				self.__mactable[srcmac] = [dev, timestamp] # obnovenie/pridanie zaznamu MAC tabulky

			# preposlanie dalej
			with self.MACtable_lock: # zamok na MAC tabulku
				target_dev = self.__mactable.get(dstmac, [None, None])[0]
			if target_dev: # cielove zariadenie je v mac tabulke
				if target_dev != dev: # ak sa cielove zariadenie nenachadza na segmente, z ktoreho ramec prichadza
					self.sendFrame(target_dev, frame)
			else: # cielove zariadenie nie je v mac tabulke => flooding
				for device in [key for key in self.__ports if key != dev]: # pre vsetky porty okrem toho, z ktoreho ramec prisiel
					self.sendFrame(device, frame)

	def sendFrame(self, dev, frame):
		self.__ports[dev].inject(frame)
		
	
	def printMACtable(self):
		print('*' * 15 + ' MAC Table ' + '*' * 15)
		print('MAC address', '\tIface', 'TTL', sep='\t')
		with self.MACtable_lock:
			for key, value in self.__mactable.items():
				print(bytes2hexstr(key, sep=':'), value[0].decode('utf-8'), value[1], sep='\t')


def bytes2hexstr(bytes_buffer, sep=''):
	""" Converts binary bytes buffer to hexa string reprezentation """	
	return sep.join(map(lambda x: '{0:02X}'.format(x), bytes_buffer))

