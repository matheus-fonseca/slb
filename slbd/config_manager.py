#!/usr/bin/env python

import json
from utils import *

ROUND_ROBIN = 'ROUND_ROBIN'
LOWER_LATENCY = 'LOWER_LATENCY'
LEAST_CONNECTIONS = 'LEAST_CONNECTIONS'
ALGORITHMS = (ROUND_ROBIN, LOWER_LATENCY, LEAST_CONNECTIONS)

KEY_SLB = 'slb'
KEY_SLB_ALGORITHM = 'slb_algorithm'
KEY_SLB_SSH_PORT = 'slb_ssh_port'
KEY_SLB_PORT = 'slb_port'
KEY_SLB_ADDRESS = 'slb_address'
KEY_SLB_ADDRESS_DEVICE = 'slb_address_device'
KEY_SLB_CLUSTER_NETWORK = 'slb_cluster_network'
KEY_SLB_CLUSTER_GATEWAY = 'slb_cluster_gateway'
KEY_SLB_CLUSTER_GATEWAY_DEVICE = 'slb_cluster_gateway_device'
KEY_SLB_USER = 'slb_user'
KEY_SLB_PASS = 'slb_pass'

KEY_REAL_SERVERS = 'real_servers'
KEY_REAL_SERVER_ADDRESS = 'real_server_address'
KEY_REAL_SERVER_PORTS = 'real_server_ports'

KEY_SLB_BACKUP = 'slb_backup'
KEY_SLB_BACKUP_ADDRESS = 'slb_backup_address'
KEY_SLB_BACKUP_SSH_PORT = 'slb_backup_ssh_port'
KEY_SLB_BACKUP_USER = 'slb_backup_user'
KEY_SLB_BACKUP_PASS = 'slb_backup_pass'

logger = SlbLogger().get_logger(__name__)
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE_DEFAULT_PATH=os.path.join(BASE_DIR, os.pardir, 'conf', 'slb_conf.json')
	
class ConfigManager():
	__metaclass__ = Singleton
	
	def __init__(self):
		self._config = {}
		self.load_default_config()
	
	def load_config(self, config_file_path):
		try:
			with open(config_file_path, 'r') as f:
				content_str = f.read()

				try:
					#TODO: Validate all the configuration
					self._config = json.loads(content_str)
				except ValueError, e:
					raise ConfigurationFileParseError('Can\'t parse configuration file')
		except IOError, e:
			raise ConfigurationFileIOError(str(e))
	
	def load_default_config(self):
		self.load_config(CONFIG_FILE_DEFAULT_PATH)
	
	def clear_config(self):
		self._config = {}
	
	def clear_default_config(self):
		self.clear_config()
		
		try:
			with open(CONFIG_FILE_DEFAULT_PATH, 'w+') as f:
				f.write('{}')
				
		except IOError, e:
			raise ConfigurationFileIOError(str(e))
	
	def set_slb_address(self, address):
		if is_valid_hostname(address):
			if KEY_SLB not in self._config:
				self._config[KEY_SLB] = {}
				
			self._config[KEY_SLB][KEY_SLB_ADDRESS] = address
			
		else:
			raise ConfigurationInvalidParamError('Invalid host: ' + address)
	
	def set_slb_address_device(self, dev):
		if dev in get_local_host_devices():
			if KEY_SLB not in self._config:
				self._config[KEY_SLB] = {}
				
			self._config[KEY_SLB][KEY_SLB_ADDRESS_DEVICE] = dev
			
		else:
			raise ConfigurationInvalidParamError('Invalid device: ' + dev)
	
	def set_slb_cluster_gateway(self, address):
		if is_valid_hostname(address):
			if KEY_SLB not in self._config:
				self._config[KEY_SLB] = {}
				
			self._config[KEY_SLB][KEY_SLB_CLUSTER_GATEWAY] = address
			
		else:
			raise ConfigurationInvalidParamError('Invalid host: ' + address)
	
	def set_slb_cluster_gateway_device(self, dev):
		if dev in get_local_host_devices():
			if KEY_SLB not in self._config:
				self._config[KEY_SLB] = {}
				
			self._config[KEY_SLB][KEY_SLB_CLUSTER_GATEWAY_DEVICE] = dev
			
		else:
			raise ConfigurationInvalidParamError('Invalid device: ' + dev)
	
	def set_slb_cluster_network(self, address_cidr):
		split = address_cidr.split('/')
		if(len(split) != 2):
			raise ConfigurationInvalidParamError('Invalid CIDR network: ' + address_cidr)
		
		address, cidr_class = split
		
		if is_valid_hostname(address) and cidr_class.isdigit() and (1 <= int(cidr_class) <= 24):
			if KEY_SLB not in self._config:
				self._config[KEY_SLB] = {}
				
			self._config[KEY_SLB][KEY_SLB_CLUSTER_NETWORK] = address_cidr
			
		else:
			raise ConfigurationInvalidParamError('Invalid CIDR network: ' + address_cidr)
	
	def set_slb_ssh_port(self, port=22):
		if is_valid_port(port):
			if KEY_SLB not in self._config:
				self._config[KEY_SLB] = {}
				
			self._config[KEY_SLB][KEY_SLB_SSH_PORT] = port
			
		else:
			raise ConfigurationInvalidParamError('Invalid port: ' + str(port))
	
	def set_slb_port(self, port):
		if is_valid_port(port):
			if KEY_SLB not in self._config:
				self._config[KEY_SLB] = {}
				
			self._config[KEY_SLB][KEY_SLB_PORT] = port
			
		else:
			raise ConfigurationInvalidParamError('Invalid port: ' + str(port))
	
	def set_slb_credentials(self, user, password):
		if KEY_SLB not in self._config:
			self._config[KEY_SLB] = {}

		self._config[KEY_SLB][KEY_SLB_USER] = user
		self._config[KEY_SLB][KEY_SLB_PASS] = password
		
		
	def set_slb_backup(self, address, user, password, port=22):
		if is_valid_hostname(address) and is_valid_port(port):
			self._config[KEY_SLB_BACKUP] = {KEY_SLB_BACKUP_ADDRESS: address, KEY_SLB_BACKUP_SSH_PORT: port, KEY_SLB_BACKUP_USER: user, KEY_SLB_BACKUP_PASS: password}
			
		else:
			raise ConfigurationInvalidParamError('Invalid host or port: ' + address + ':' + str(port))
	
	def set_slb_algorithm(self, algorithm):
		if algorithm in ALGORITHMS:
			if KEY_SLB not in self._config:
				self._config[KEY_SLB] = {}
				
			self._config[KEY_SLB][KEY_SLB_ALGORITHM] = algorithm
		
		else:
			raise ConfigurationInvalidParamError('Invalid algorithm: ' + algorithm + ', use ' + ROUND_ROBIN + ' or ' + LOWER_LATENCY)
	
	def add_real_server(self, address, port):
		if is_valid_hostname(address) and is_valid_port(port):
			if KEY_REAL_SERVERS not in self._config:
				self._config[KEY_REAL_SERVERS] = []
			
			real_servers = self._config[KEY_REAL_SERVERS]
			
			try:
				server_exists = False
				for server in real_servers:
					if(server.has_key(KEY_REAL_SERVER_ADDRESS) is True) and (server[KEY_REAL_SERVER_ADDRESS] == address):
						server_exists = True
						if server.has_key(KEY_REAL_SERVER_PORTS) is True:													
							if port not in server[KEY_REAL_SERVER_PORTS]:
								server[KEY_REAL_SERVER_PORTS].append(port)
						else:
							server[KEY_REAL_SERVER_PORTS] = [port]
						
						break
				
				if server_exists is False:
					real_servers.append({KEY_REAL_SERVER_ADDRESS: address, KEY_REAL_SERVER_PORTS: [port]})
			except KeyError, e:
				raise ConfigurationInvalidParamError('Invalid real servers configuration')
			
		else:
			raise ConfigurationInvalidParamError('Invalid host or port: ' + address + ':' + str(port))

	
	def remove_real_server_port(self, address, port):
		if is_valid_hostname(address) and is_valid_port(port):
			try:
				if KEY_REAL_SERVERS in self._config:
					real_servers = self._config[KEY_REAL_SERVERS]
					
					for server in real_servers:
						if(server.has_key(KEY_REAL_SERVER_ADDRESS) is True) and (server[KEY_REAL_SERVER_ADDRESS] == address):
							if (server.has_key(KEY_REAL_SERVER_PORTS) is True) and (port in server[KEY_REAL_SERVER_PORTS]):
								server[KEY_REAL_SERVER_PORTS].remove(port)
								if len(server[KEY_REAL_SERVER_PORTS]) is 0:
									real_servers.remove(server)
							else:
								raise ConfigurationInvalidParamError('Inexistent address or port: ' + address + ':' + str(port))
								
							break
			except Exception, e:
				raise ConfigurationInvalidParamError('Invalid real servers configuration')
			
		else:
			raise ConfigurationInvalidParamError('Invalid host or port: ' + address + ':' + str(port))
	
	def remove_real_server(self, address):
		if is_valid_hostname(address):
			try:
				if KEY_REAL_SERVERS in self._config:
					real_servers = self._config[KEY_REAL_SERVERS]
					
					server_to_be_removed =  None
					for server in real_servers:
						if(server.has_key(KEY_REAL_SERVER_ADDRESS) is True) and (server[KEY_REAL_SERVER_ADDRESS] == address):
							server_to_be_removed = server
							break
					
					if server_to_be_removed is not None:
						real_servers.remove(server_to_be_removed)
					else:
						raise ConfigurationInvalidParamError('Inexistent real server: ' + address)		
			except Exception, e:
				raise ConfigurationInvalidParamError('Invalid real servers configuration')
			
		else:
			raise ConfigurationInvalidParamError('Invalid host: ' + address)
	
	def remove_slb_ssh_port(self):
		try:
			del self._config[KEY_SLB][KEY_SLB_SSH_PORT]
		except KeyError, e:
			raise ConfigurationInvalidParamError('Inexistent SSH port')
			
	def remove_slb_credentials(self):
		try:
			del self._config[KEY_SLB][KEY_SLB_USER]
			del self._config[KEY_SLB][KEY_SLB_PASS]
		except KeyError, e:
			raise ConfigurationInvalidParamError('Inexistent user or pass')
			
	def remove_slb_backup(self):
		try:
			del self._config[KEY_SLB_BACKUP]
		except KeyError, e:
			raise ConfigurationInvalidParamError('Inexistent slb backup')
			
	def get_slb_ssh_port(self):
		try:
			return self._config[KEY_SLB][KEY_SLB_SSH_PORT]
		except KeyError, e:
			return None
	
	def get_slb_cluster_gateway(self):
		try:
			return self._config[KEY_SLB][KEY_SLB_CLUSTER_GATEWAY]
		except KeyError, e:
			return None
	
	def get_slb_cluster_gateway_device(self):
		try:
			return self._config[KEY_SLB][KEY_SLB_CLUSTER_GATEWAY_DEVICE]
		except KeyError, e:
			return None
	
	def get_slb_address(self):
		try:
			return self._config[KEY_SLB][KEY_SLB_ADDRESS]	
		except KeyError, e:
			return None
	
	def get_slb_address_device(self):
		try:
			return self._config[KEY_SLB][KEY_SLB_ADDRESS_DEVICE]
		except KeyError, e:
			return None
	
	def get_slb_cluster_network(self):
		try:
			return self._config[KEY_SLB][KEY_SLB_CLUSTER_NETWORK]
		except KeyError, e:
			return None
	
	def get_slb_port(self):
		try:
			return self._config[KEY_SLB][KEY_SLB_PORT]
		except KeyError, e:
			return None
	
	def get_slb_credentials(self):
		try:
			return (self._config[KEY_SLB][KEY_SLB_USER], self._config[KEY_SLB][KEY_SLB_PASS])
		except KeyError, e:
			return None
	
	def get_slb_backup(self):
		try:
			address = self._config[KEY_SLB_BACKUP][KEY_SLB_BACKUP_ADDRESS]
			port = self._config[KEY_SLB_BACKUP][KEY_SLB_BACKUP_SSH_PORT]
			user = self._config[KEY_SLB_BACKUP][KEY_SLB_BACKUP_USER]
			password = self._config[KEY_SLB_BACKUP][KEY_SLB_BACKUP_PASS]
			
			return (address, port, user, password)
		except KeyError, e:
			return (None, None, None, None)
	
	
	def get_real_servers(self):
		try:
			servers = [server[KEY_REAL_SERVER_ADDRESS] for server in self._config[KEY_REAL_SERVERS] if server.has_key(KEY_REAL_SERVER_PORTS)]
			ports = [server[KEY_REAL_SERVER_PORTS] for server in self._config[KEY_REAL_SERVERS] if server.has_key(KEY_REAL_SERVER_ADDRESS)]
			
			return zip(servers, ports)
		except KeyError, e:
			return []
		
	def get_algorithm(self):
		try:
			return self._config[KEY_SLB][KEY_SLB_ALGORITHM]
		except KeyError, e:
			return None
	
	def get_config(self):
		return json.dumps(self._config, sort_keys=True, indent=4, separators=(',', ': '))
	
	def save_config(self):
		try:
			with open(CONFIG_FILE_DEFAULT_PATH, 'w+') as f:
				f.write(json.dumps(self._config, sort_keys=True, indent=4, separators=(',', ': ')))
		except IOError, e:
			raise ConfigurationFileIOError(str(e))

			
			
			
if __name__ == "__main__":
	config_mgr = ConfigManager()
	
	config_mgr.set_slb_address('192.168.0.11')
	config_mgr.set_slb_ssh_port(22)
	config_mgr.set_slb_credentials('matheus', '?????')
	config_mgr.set_algorithm(ROUND_ROBIN)
	
	config_mgr.set_slb_backup(address='192.168.0.12', user='matheus', password='????')
	
	config_mgr.add_real_server('192.168.0.8', 80)
	config_mgr.add_real_server('192.168.0.8', 22)
	
	config_mgr.add_real_server('192.168.0.2', 80)
	
	config_mgr.remove_real_server('192.168.0.8')
	
	config_mgr.save_config()
	
	print config_mgr.get_config()
	
