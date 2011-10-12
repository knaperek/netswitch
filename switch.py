import pcapo
import sys
import threading

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
	
	Switch_lock = threading.Lock()

	def __init__(self, device_list):
		
		self.__ports = dict()
		# try: # inicializacia portov (interfejsov)
		for dev in device_list:
			self.__ports[dev] = pcapo.libpcap()
			self.__ports[dev].open_live(dev)
			self.__ports[dev].setdirection(1)
		#except pcapo.PcapDeviceException as errmsg:
			#raise SwitchException('Fatal error during switch initialization:' + errmsg)
		#	raise SwitchException(str(errmsg))
		
		for dev in self.__ports: # spustanie threadov pre kazdy port (interface)
			hThread = threading.Thread(target=lambda: self.listenOnDevice(dev))
			# hThread.daemon = True
			hThread.start()


	def listenOnDevice(self, dev):
		ph = self.__ports[dev]
		counter = 0
		while 1:
			frame = ph.next()
			if not frame:
				continue
			print('***** Frame #{0} Captured [{1} bytes] on interface {2} *******'.format(counter, len(frame), dev))
			counter += 1
			pcapo.Dumphex(frame)


	def sendFrame(self, dev, frame):
		self.__ports[dev].inject(frame)
		
		

