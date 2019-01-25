#!/usr/bin/env python

from cluster_monitor import *
from config_manager import *
from utils import *
from redundancy_manager import *
from pynl80211 import netlink

import sys
import threading
import time
import socket
import ssl
import os

CHUNK_SEPARATOR_TOKEN = '|'
COMMAND_SUCCESS_TOKEN = 'OK!'

ORDER_RUNNING_SERVICE_COMMAND='order_running_service'
RM_RUNNING_SERVICE_COMMAND='rm_running_service'
ADD_RUNNING_SERVICE_COMMAND='add_running_service'
CHECK_ALIVE_COMMAND='check_alive'
GET_PID_COMMAND='get_pid'

CLEAR_DEFAULT_CONFIG_COMMAND = 'clear_default_config'
CLEAR_CONFIG_COMMAND = 'clear_config'
SET_SLB_ADDRESS_COMMAND = 'set_slb_address'
SET_SLB_ALGORITHM_COMMAND = 'set_slb_algorithm'

logger = SlbLogger().get_logger(__name__)
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
SLBCORE_PATH = os.path.join(BASE_DIR, os.pardir, 'slbcore/slbcore.ko')
CRT_PATH = os.path.join(BASE_DIR, os.pardir, 'ssl/server.crt')
KEY_PATH = os.path.join(BASE_DIR, os.pardir, 'ssl/server.key')

SNAT_IPTABLES_FORMAT = 'iptables -t nat -%s POSTROUTING -s %s -j MASQUERADE'

#FUTURE: View services status in table format (UP or DOWN + Latency)

class CommandExecutor:
	def __init__(self):
		self._config_mgr = ConfigManager()
		self._COMMANDS_MAPPING = {
			CLEAR_CONFIG_COMMAND : self._clear_config,
			SET_SLB_ADDRESS_COMMAND : self._set_slb_address,
			'set_slb_address_device' : self._set_slb_address_device,
			'set_slb_cluster_gateway' : self._set_slb_cluster_gateway,
			'set_slb_cluster_gateway_device' : self._set_slb_cluster_gateway_device,
			'set_slb_cluster_network' : self._set_slb_cluster_network,
			'set_slb_ssh_port' : self._set_slb_ssh_port,
			'set_slb_credentials' : self._set_slb_credentials,
			'set_slb_backup' : self._set_slb_backup,
			SET_SLB_ALGORITHM_COMMAND : self._set_slb_algorithm,
			'add_real_server' : self._add_real_server,
			'remove_real_server_port' : self._remove_real_server_port,
			'remove_real_server' : self._remove_real_server,
			'remove_slb_ssh_port' : self._remove_slb_ssh_port,
			'remove_slb_credentials' : self._remove_slb_credentials,
			'get_config' : self._get_config,
			'save_config' : self._save_config,
			'stop' : self._stop,
			CHECK_ALIVE_COMMAND : self._check_alive,
			GET_PID_COMMAND : self._get_pid,
		}
		self._COMMANDS_SLBCORE = (
			CLEAR_CONFIG_COMMAND,
			SET_SLB_ADDRESS_COMMAND,
			SET_SLB_ALGORITHM_COMMAND,
			ADD_RUNNING_SERVICE_COMMAND,
			RM_RUNNING_SERVICE_COMMAND,
			ORDER_RUNNING_SERVICE_COMMAND
		)
		
	def _clear_config(self):
		self._config_mgr.clear_config()
		
	def _set_slb_address(self, address):
		self._config_mgr.set_slb_address(address)
	
	def _set_slb_address_device(self, dev):
		self._config_mgr.set_slb_address_device(dev)
	
	def _set_slb_cluster_gateway(self, address):
		self._config_mgr.set_slb_cluster_gateway(address)
	
	def _set_slb_cluster_gateway_device(self, dev):
		self._config_mgr.set_slb_cluster_gateway_device(dev)
	
	def _set_slb_cluster_network(self, address_cidr):
		self._config_mgr.set_slb_cluster_network(address_cidr)
		
	def _set_slb_ssh_port(self, port):
		self._config_mgr.set_slb_ssh_port(int(port))
		
	def _set_slb_credentials(self, user, password):
		self._config_mgr.set_slb_credentials(user, password)
		
	def _set_slb_backup(self, address, user, password, port):
		self._config_mgr.set_slb_backup(address, user, password, int(port))
		
	def _set_slb_algorithm(self, algorithm):
		self._config_mgr.set_slb_algorithm(algorithm)
		
	def _add_real_server(self, address, port):
		self._config_mgr.add_real_server(address, int(port))
		
	def _remove_real_server_port(self, address, port):
		self._config_mgr.remove_real_server_port(address, int(port))
		
	def _remove_real_server(self, address):
		self._config_mgr.remove_real_server(address)
		
	def _remove_slb_ssh_port(self):
		self._config_mgr.remove_slb_ssh_port()
		
	def _remove_slb_credentials(self):
		self._config_mgr.remove_slb_credentials()
		
	def _get_config(self):
		return self._config_mgr.get_config()
		
	def _save_config(self):
		self._config_mgr.save_config()
	
	def _check_alive(self):
		pass
	
	def _get_pid(self):
		if SlbDaemon()._redundancy_mgr is not None:
			return os.getpid()
	
	def _stop(self):
		SlbDaemon().stop_listening()
		return 'slb stopping...'
	
	def _diff_between_running_services(self, ref_services, cmp_services):
		diff_services = {}
		for ref_port, ref_servers in ref_services.items():
			if cmp_services.has_key(ref_port) is False:
				diff_services[ref_port] = ref_servers
			else:
				cmp_servers = cmp_services[ref_port]
				cmp_servers_set = set(cmp_servers)
				diff_servers = [ref_server for ref_server in ref_servers if ref_server not in cmp_servers_set]
				if len(diff_servers) > 0:
					diff_services[ref_port] = diff_servers

		return diff_services
	
	def _compose_service_msg(self, command, port, servers):
		return command + CHUNK_SEPARATOR_TOKEN + str(port) + CHUNK_SEPARATOR_TOKEN + CHUNK_SEPARATOR_TOKEN.join(servers) + CHUNK_SEPARATOR_TOKEN
	
	def _check_servers_latency_order_change(self, new_services, old_services, rm_services):
		old_with_rm = self._diff_between_running_services(old_services, rm_services)

		for ((port_old, servers_old) , (port_new, servers_new)) in zip(old_with_rm.items(), new_services.items()):
			for server_old, server_new in zip(servers_old, servers_new):
				if server_old != server_new:
					msg = self._compose_service_msg(ORDER_RUNNING_SERVICE_COMMAND, port_new, servers_new)
					self._send_slbcore_command(ORDER_RUNNING_SERVICE_COMMAND, msg)
					break
	
	def update_slbcore_running_services(self, new_services, old_services):
		add_services = self._diff_between_running_services(new_services, old_services)
		rm_services = self._diff_between_running_services(old_services, new_services)
		
		for port, servers in add_services.items():
			msg = self._compose_service_msg(ADD_RUNNING_SERVICE_COMMAND, port, servers)
			self._send_slbcore_command(ADD_RUNNING_SERVICE_COMMAND, msg)
		
		for port, servers in rm_services.items():
			msg = self._compose_service_msg(RM_RUNNING_SERVICE_COMMAND, port, servers)

			self._send_slbcore_command(RM_RUNNING_SERVICE_COMMAND, msg)
		
		if self._config_mgr.get_algorithm() == LOWER_LATENCY:
			self._check_servers_latency_order_change(new_services, old_services, rm_services)
	
	def _send_slbcore_command(self, command_name, msg):
		if (command_name in self._COMMANDS_SLBCORE) and SlbDaemon().check_if_running() is True:
			try:
				netlink_conn = netlink.Connection(netlink.NETLINK_USERSOCK)
				netlink_msg = netlink.Message(netlink.NLMSG_DONE, flags=netlink.NLM_F_REQUEST, payload=bytes(msg) + b'\x00')	
				netlink_msg.send(netlink_conn)
			except socket.error, e:
				logger.error('Problem connecting with slbcore: ' + str(e))
			
	def parse_and_execute(self, msg):
		if len(msg) > 0:
			# FUTURE: Accept more than one command
			tokens = msg.split(CHUNK_SEPARATOR_TOKEN)
			tokens.pop()

			command_name = tokens[0]
			params = []

			if len(tokens) > 1:
				params = tokens[1:]

			command_result = ''
			try:
				logger.info('Executing "' + command_name + '" with params ' + str(params))
				command_result = self._COMMANDS_MAPPING[command_name](*params)
				if command_result is None:
					command_result = COMMAND_SUCCESS_TOKEN
			except TypeError, e:
				return ConfigurationInvalidParamError('Invalid number of params')
			except KeyError, e:
				raise ConfigurationInvalidParamError('Inexistent command')
			
			self._send_slbcore_command(command_name, msg)
			
			return command_result 
		else:
			raise ConfigurationInvalidParamError('Invalid params')
			
class SlbDaemon:
	__metaclass__ = Singleton
	
	def __init__(self, with_redundancy=False):
		try:
			self.SEC_CONN_TIMEOUT = 2
			self._is_running_lock = threading.Lock()
			self._is_running = True
			self.ALLOWED_ADDRESSES = get_local_host_addresses()
			
			self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self._sock.settimeout(self.SEC_CONN_TIMEOUT)
			
			self._config_mgr = ConfigManager()
			
			self._redundancy_mgr = None
			if with_redundancy is True:
				try:
					self._redundancy_mgr = RedundancyManager()
				except ConfigurationRedundancyError, e:
					logger.error('Problem starting the redundancy manager: ' + str(e))
					self._redundancy_mgr = None
					
			self._cluster_moni = ClusterMonitor()			
			servers_and_ports = self._config_mgr.get_real_servers()
			if servers_and_ports is None:
				logger.error('No real server is configured, at leats one must be to run slb')
				sys.exit(-1)
			
			self._old_services = {}
			
			self._cmd_exec = CommandExecutor()
		except (ConfigurationFileParseError, ConfigurationFileIOError) as e:
			logger.error('Problem loading default configuration: ' + str(e))
			sys.exit(-1)
	
	def check_if_running(self):
		with self._is_running_lock:
			return self._is_running
	
	def _check_allowed_client(self, client_address):
		if client_address not in self.ALLOWED_ADDRESSES:
			logger.warning('Unallowed host "'+ str(client_address) +'" trying to connect')
			return False
		else:
			logger.info('Internal client "'+ str(client_address) +'" connected')
			return True
	
	def _recv_msg(self, ssl_conn):
			msg=''
			success_recv = True
			while True:  
				try:
					chunk = ssl_conn.read()
					
					if len(chunk) == 0:
						break
					else:
						msg += chunk
				except socket.error, e:
					if str(e).startswith('[Errno 35]') is True:
						time.sleep(0.1)
					else:
						success_recv = False
						logger.error('Problem receiving msg: ' + str(e))
						break
				except ssl.SSLError, e:
					success_recv = False
					logger.error('Error receiving msg with SSL: ' + str(e))
					break
			
			return msg, success_recv
		
	def _execute_msg_and_send_response(self, msg, ssl_conn):
		response_msg=''

		try:
			response_msg = self._cmd_exec.parse_and_execute(msg)
		except Exception, e:
			logger.error('Problem executing command: ' + str(e))
			response_msg = str(e)

		try:
			ssl_conn.write(str(response_msg) + CHUNK_SEPARATOR_TOKEN)
			ssl_conn.shutdown(socket.SHUT_WR)
		except socket.error, e:
			logger.error('Problem sending msg: ' + str(e))
		except ssl.SSLError, e:
			logger.error('Problem sending msg with SSL: ' + str(e))
		finally:
			ssl_conn.close()
	
	def _clean_up_to_exit(self):
		self._sock.close()
		self._apply_snat_operation('D')
		self._unload_slbcore()
		
	def _accept_connections(self):
		logger.info('Starting slbd listener thread...')
		
		while self.check_if_running():
			try:
				conn, client = self._sock.accept()
				ssl_conn = ssl.wrap_socket(conn,
											 server_side=True,
											 certfile=CRT_PATH,
											 keyfile=KEY_PATH)
			except socket.timeout, e:
				continue
			except socket.error, e:
				logger.error('Error accepting connection: ' + str(e))
				continue
			except ssl.SSLError, e:
				logger.error('Error wraping socket with SSL: ' + str(e))
				continue
			
			client_address = client[0]
			if self._check_allowed_client(client_address) is False:
				ssl_conn.close()
				continue
			
			msg, success_recv = self._recv_msg(ssl_conn)
			
			if success_recv is True:
				self._execute_msg_and_send_response(msg, ssl_conn)
		
		logger.info('Exiting slbd listener thread...')
		self._clean_up_to_exit()
	
	def _monitor_servers(self):
		logger.info('Starting slbd cluster monitor thread...')

		while self.check_if_running():
			servers_and_ports = self._config_mgr.get_real_servers()
			if servers_and_ports is not None:
				new_services = self._cluster_moni.check_services(servers_and_ports)
				self._cmd_exec.update_slbcore_running_services(new_services, 
															   self._old_services)
				self._old_services = new_services
				
				time.sleep(1)
		
		logger.info('Exiting slbd cluster monitor thread...')
	
	def _apply_snat_operation(self, operation):
		cluster_network = self._config_mgr.get_slb_cluster_network()
		success = True
		if operation in ('D', 'A') and cluster_network is not None:
			snat_command = SNAT_IPTABLES_FORMAT % (operation, cluster_network)
			
			rc = os.system(snat_command)
			if rc is not 0:
				logger.error('Problem applying SNAT. Exiting...')
				success = False
			else:
				logger.info('SNAT '+ ('add' if operation == 'A' else 'remove') +' for '+ cluster_network +' applied.')
		else:
			logger.error('Invalid SNAT operation \'-'+ str(operation) +'\' or cluster network configuration is missing. Exiting...')
			success = False
		
		return success
	
	def _configure_slbcore(self):
		# TODO: Send ssh port too
		address = self._config_mgr.get_slb_address()
		if address is None:
			logger.error('slb address configuration is missing.')
			return False
		msg = SET_SLB_ADDRESS_COMMAND + CHUNK_SEPARATOR_TOKEN + address + CHUNK_SEPARATOR_TOKEN
		self._cmd_exec._send_slbcore_command(SET_SLB_ADDRESS_COMMAND, msg)
		
		algorithm = self._config_mgr.get_algorithm()
		if algorithm is None:
			logger.error('slb algorithm configuration is missing.')
			return False
		msg = SET_SLB_ALGORITHM_COMMAND + CHUNK_SEPARATOR_TOKEN + algorithm + CHUNK_SEPARATOR_TOKEN
		self._cmd_exec._send_slbcore_command(SET_SLB_ALGORITHM_COMMAND, msg)
		
		return True
	
	def _load_slbcore(self):
		success = True
		rc = os.system('insmod ' + SLBCORE_PATH)
		if rc is not 0:
			logger.error('Problem loading slbcore module. Exiting...')
			success = False
		else:
			logger.info('Loading slbcore module')
			success = self._configure_slbcore()
			
		return success
	
	def _unload_slbcore(self):
		success = True
		
		rc = os.system('rmmod ' + SLBCORE_PATH)
		if rc is not 0:
			logger.error('Problem unloading slbcore module. Exiting...')
			success = False
		else:
			logger.info('Unloading slbcore module')
			
		return success
	
	def _start_sync_config(self):
		logger.info('Sarting slbd configuration synchronizer thread...')
		
		while self.check_if_running():
			self._redundancy_mgr.sync_config()
		
		logger.info('Exiting slbd configuration synchronizer thread...')
		
	def _start_app_mgr_check(self):
		logger.info('Sarting slbd AppMgr checker thread...')
		
		while self.check_if_running():
			self._redundancy_mgr.app_mgr_check()
			
		logger.info('Exiting slbd AppMgr checker thread...')
		
	def listen(self):
		if self.check_if_running() is True:
			port = self._config_mgr.get_slb_port()
			
			if port is None:
				logger.error('The slb port is missing, review the configuration file')
				return
			try:
				self._sock.bind(('127.0.0.1', port))
				self._sock.listen(5)
			except socket.error, e:
				logger.error('Can\'t bind socket to port "' + str(port) + '": ' + str(e))
				return 
			
			if self._load_slbcore() == False: 
				return
			if self._apply_snat_operation('A') == False:
				return
			
			threads = []
			
			thread_monitor = threading.Thread(target=self._monitor_servers)
			thread_accept = threading.Thread(target=self._accept_connections)
			
			threads.append(thread_monitor)
			threads.append(thread_accept)
			
			if self._redundancy_mgr is not None:
				thread_sync = threading.Thread(target=self._start_sync_config)
				thread_check = threading.Thread(target=self._start_app_mgr_check)
				
				threads.append(thread_sync)
				threads.append(thread_check)
			
			for thread in threads:
				thread.start()
			
			for thread in threads:
				thread.join()
	
	def stop_listening(self):
		with self._is_running_lock:
			self._is_running = False
	
if __name__ == '__main__':
	if os.geteuid() is 0:
		with_redundancy = False
		
		if len(sys.argv) > 1 and sys.argv[1] == 'with_redundancy':
			with_redundancy = True
			
		slbd = SlbDaemon(with_redundancy=with_redundancy)
		slbd.listen()
	else:
		logger.error('You need to be \'root\' user to use slb')