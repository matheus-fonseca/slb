#!/usr/bin/env python

import socket
import os
import json
import logging
import logging.config
import fcntl
import struct
import array

from ctypes import (
	Structure, Union, POINTER,
	pointer, get_errno, cast,
	c_ushort, c_byte, c_void_p, c_char_p, c_uint, c_int, c_uint16, c_uint32
)
import ctypes.util
import ctypes


socket._GLOBAL_DEFAULT_TIMEOUT = 3
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
LOG_CONFIG_FILE=os.path.join(BASE_DIR, os.pardir, 'conf', 'slb_logging_conf.json')

"""
	Util Classes
"""

class TerminalColor:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	ENDC = '\033[0m'
	
class Singleton(type):
	_instances = {}
	def __call__(cls, *args, **kwargs):
		if cls not in cls._instances:
			cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
		
		return cls._instances[cls]

class SlbLogger():
	__metaclass__ = Singleton
	
	def __init__(self):
		self._setup_logging()
	
	def get_logger(self, name):
		return logging.getLogger(name)  
	
	def _setup_logging(self):
		path = LOG_CONFIG_FILE
		if os.path.exists(path):
			with open(path, 'rt') as f:
				config = json.load(f)
			
			try:
				info_log_filename = config['handlers']['info_file_handler']['filename']
				config['handlers']['info_file_handler']['filename'] = os.path.join(BASE_DIR, os.pardir, info_log_filename)
				error_log_filename = config['handlers']['error_file_handler']['filename']
				config['handlers']['error_file_handler']['filename'] = os.path.join(BASE_DIR, os.pardir, error_log_filename)
			except KeyError:
				pass
			
			logging.config.dictConfig(config)
		else:
			logging.basicConfig(level=logging.INFO)
	
"""
	Exceptions
"""

class SlbError(Exception):
	def __init__(self,  message):
		super(SlbError, self).__init__(message)

class ConfigurationFileIOError(SlbError):
	pass

class ConfigurationFileParseError(SlbError):
	pass

class ConfigurationInvalidParamError(SlbError):
	pass

class ConfigurationRedundancyError(SlbError):
	pass

class ConfigurationInvalidError(SlbError):
	pass

class InternalError(SlbError):
	pass

class SCPError(SlbError):
	pass

"""
	Util Functions
"""

def is_valid_hostname(address):
	try:
		socket.gethostbyname(address)
		return True
	except socket.error:
		return False
	
def is_valid_port(port):
	return 1 <= port <= 65535

def format_ip(addr):
	return str(ord(addr[0])) + '.' + str(ord(addr[1])) + '.' + str(ord(addr[2])) + '.' + str(ord(addr[3]))

def get_local_host_addresses():
	max_possible = 128  # arbitrary. raise if needed.
	bytes = max_possible * 32
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	names = array.array('B', '\0' * bytes)
	outbytes = struct.unpack('iL', fcntl.ioctl(
			s.fileno(),
			0x8912,  # SIOCGIFCONF
			struct.pack('iL', bytes, names.buffer_info()[0])
		))[0]
	namestr = names.tostring()
	
	ips = []
	for i in range(0, outbytes, 40):
		#name = namestr[i:i+16].split('\0', 1)[0]
		ip   = namestr[i+20:i+24]
		ips.append(format_ip(ip))
		
	return ips

def get_local_host_devices():
	max_possible = 128  # arbitrary. raise if needed.
	bytes = max_possible * 32
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	names = array.array('B', '\0' * bytes)
	outbytes = struct.unpack('iL', fcntl.ioctl(
			s.fileno(),
			0x8912,  # SIOCGIFCONF
			struct.pack('iL', bytes, names.buffer_info()[0])
		))[0]
	namestr = names.tostring()

	return namestr

"""
	Get network devices Functions/Classes
	
	CREDITS FOR Per Rovegard <https://twitter.com/provegard>

	Source: http://programmaticallyspeaking.com/getting-network-interfaces-in-python.html
"""

class _struct_sockaddr(Structure):
	_fields_ = [
		('sa_family', c_ushort),
		('sa_data', c_byte * 14),]

class _struct_sockaddr_in(Structure):
	_fields_ = [
		('sin_family', c_ushort),
		('sin_port', c_uint16),
		('sin_addr', c_byte * 4)]
	
class _struct_sockaddr_in6(Structure):
	_fields_ = [
		('sin6_family', c_ushort),
		('sin6_port', c_uint16),
		('sin6_flowinfo', c_uint32),
		('sin6_addr', c_byte * 16),
		('sin6_scope_id', c_uint32)]
	
class _union_ifa_ifu(Union):
	_fields_ = [
		('ifu_broadaddr', POINTER(_struct_sockaddr)),
		('ifu_dstaddr', POINTER(_struct_sockaddr)),]

class _struct_ifaddrs(Structure):
	pass

_struct_ifaddrs._fields_ = [
	('ifa_next', POINTER(_struct_ifaddrs)),
	('ifa_name', c_char_p),
	('ifa_flags', c_uint),
	('ifa_addr', POINTER(_struct_sockaddr)),
	('ifa_netmask', POINTER(_struct_sockaddr)),
	('ifa_ifu', _union_ifa_ifu),
	('ifa_data', c_void_p),]
 
libc = ctypes.CDLL(ctypes.util.find_library('c'))
 
def _ifap_iter(ifap):
	ifa = ifap.contents
	while True:
		yield ifa
		if not ifa.ifa_next:
			break
		ifa = ifa.ifa_next.contents

def _getfamaddr(sa):
	family = sa.sa_family
	addr = None
	if family == socket.AF_INET:
		sa = cast(pointer(sa), POINTER(_struct_sockaddr_in)).contents
		addr = socket.inet_ntop(family, sa.sin_addr)
	elif family == socket.AF_INET6:
		sa = cast(pointer(sa), POINTER(_struct_sockaddr_in6)).contents
		addr = socket.inet_ntop(family, sa.sin6_addr)
	return family, addr
 
class _NetworkInterface(object):
	def __init__(self, name):
		self.name = name
		self.index = libc.if_nametoindex(name)
		self.addresses = {}
		
	def __str__(self):
		return "%s [index=%d, IPv4=%s, IPv6=%s]" % (
			self.name, self.index,
			self.addresses.get(socket.AF_INET),
			self.addresses.get(socket.AF_INET6))
	
def get_local_host_devices():
	ifap = POINTER(_struct_ifaddrs)()
	result = libc.getifaddrs(pointer(ifap))
	if result != 0:
		raise OSError(get_errno())
	del result
	try:
		retval = {}
		for ifa in _ifap_iter(ifap):
			name = ifa.ifa_name
			i = retval.get(name)
			if not i:
				i = retval[name] = _NetworkInterface(name)
			family, addr = _getfamaddr(ifa.ifa_addr.contents)
			if addr:
				i.addresses[family] = addr
		
		return tuple([ni.name for ni in retval.values()])
	finally:
		libc.freeifaddrs(ifap)
	
if __name__ == '__main__':
	print get_local_host_devices()