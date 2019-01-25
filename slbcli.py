#!/usr/bin/env python

import argparse
import socket
import sys
import time
import os
import re
from slbd.slbd import *
from slbd.utils import *
from slbd.config_manager import *

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
CRT_PATH = os.path.join(BASE_DIR, 'ssl', 'server.crt')

class SlbCli():
	def __init__(self):
		self._DAEMON_COMMANDS = {
			'clear_config' : 'clear_config',
			'address' : 'set_slb_address',
			'address_dev' : 'set_slb_address_device',
			'gateway' : 'set_slb_cluster_gateway',
			'gateway_dev' : 'set_slb_cluster_gateway_device',
			'cluster_network' : 'set_slb_cluster_network',
			'ssh_port' : 'set_slb_ssh_port',
			'credentials' : 'set_slb_credentials',
			'backup_slb' : 'set_slb_backup',
			'algorithm' : 'set_slb_algorithm',
			'add_server' : 'add_real_server',
			'rm_server_port' : 'remove_real_server_port',
			'rm_server' : 'remove_real_server',
			'rm_ssh_port' : 'remove_slb_ssh_port',
			'rm_credentials' : 'remove_slb_credentials',
			'show_config' : 'get_config',
			'save_config' : 'save_config',
			'unload' : 'stop',
		}
		
		self._parser = argparse.ArgumentParser(description="slbcli - A command-line interface for the slb system (Server Load Balancing)")
		
		try:
			self._config_mgr = ConfigManager()
			self._slb_port = self._config_mgr.get_slb_port()

			if self._slb_port is None:
				print 'The slb port is missing, review the configuration file.'
				sys.exit(-1)
		except (ConfigurationFileParseError, ConfigurationFileIOError) as e:
			print 'Error loading the slb default configuration: ' + str(e) + '. Review the configuration file.'
			sys.exit(-1)
		
		self._add_slb_arguments()
		
		if len(sys.argv) == 1:
			self._print_error_wtih_usage('pass at least one argument')
		
		self._args = vars(self._parser.parse_args())
		self._execute_commands()	
	
	def _send_to_daemon(self, command_name, *args):
		original_command_name = command_name.replace('_','-')
		command_line_arg = self._DAEMON_COMMANDS[command_name]
		
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(4)
			ssl_sock = ssl.wrap_socket(sock,
									   ca_certs=CRT_PATH,
									   cert_reqs=ssl.CERT_REQUIRED)
			
			ssl_sock.connect(('127.0.0.1', self._slb_port))
		except socket.error:
			print 'Error executing \''+ command_line_arg +'\'. Start the slb before with \'--load\' option.'
			sys.exit(-1)
		except ssl.SSLError, e:
			print 'Error executing \''+ command_line_arg +'\'. SSL Error: ' + str(e)
			sys.exit(-1)
			
		ssl_sock.write(command_line_arg + CHUNK_SEPARATOR_TOKEN)
		if len(args) > 0:
			ssl_sock.write(CHUNK_SEPARATOR_TOKEN.join([str(i) for i in args]) + CHUNK_SEPARATOR_TOKEN)
			
		sock.shutdown(socket.SHUT_WR)
		
		response = ''
		while True:  
			try:
				chunk = ssl_sock.read()
				chunk = chunk.split(CHUNK_SEPARATOR_TOKEN)[0]
				if len(chunk) == 0:
					break
				else:
					response += chunk
			except socket.error, e:
				if str(e).startswith('[Errno 35]') is True:
					time.sleep(0.1)
				else:
					print 'Error executing \''+ original_command_name +'\': ' + str(e) + '. Check the slb logs.'
					break
			except socket.timeout, e:
				print 'Error executing \''+ original_command_name +'\': Timeout communicating the slb daemon. Try again.'
				break
			except ssl.SSLError, e:		
				print 'SSL Error executing \''+ original_command_name +'\': ' + str(e) + '. Check the slb logs.'
				break
		
		if self._args['with_redundancy'] == False:
			print original_command_name + ': ' + response
		else:
			print response
			
		ssl_sock.close()
	
	def _print_error_wtih_usage(self, message):
		self._parser.print_usage()
		print sys.argv[0] + ': error: '+ message
		sys.exit(-1)
	
	def _start_daemon(self, with_redundancy=False):
		if self._check_alive_daemon() is True:
			print 'slb already started.'
			sys.exit(-1)
		
		slbd_path = os.path.join(BASE_DIR, 'slbd/slbd.py')
		
		cmd = ''
		if with_redundancy is False:
			cmd = 'python '+ slbd_path +' &'
		else:
			cmd = 'python '+ slbd_path +' with_redundancy &'
			
		os.system(cmd)
		time.sleep(1)
		
		success = True
		if self._check_alive_daemon() is True:
			if with_redundancy is False:
				print 'load: slb started.'
			else:
				pid = self._get_dameon_pid()
				if pid > 0:
					print pid
				else:
					success = False
		else:
			success = False
		
		if success is False:
			print 'Error starting slb, check logs.'
			sys.exit(-1)
	
	def _get_dameon_pid(self):
		pid = -1
		
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			ssl_sock = ssl.wrap_socket(sock,
									   ca_certs=CRT_PATH,
									   cert_reqs=ssl.CERT_REQUIRED)
			ssl_sock.connect(('127.0.0.1', self._slb_port))
			ssl_sock.write(GET_PID_COMMAND + CHUNK_SEPARATOR_TOKEN)
			sock.shutdown(socket.SHUT_WR)
			response = ssl_sock.read()
			
			# max_pid = 32768 = 5 digits
			if re.search('^\d{1,5}' + CHUNK_SEPARATOR_TOKEN, response) is not None: 
				pid = response.split(CHUNK_SEPARATOR_TOKEN)[0]	# pid	
		
		except (socket.error, ssl.SSLError) as e:
			pass
		
		ssl_sock.close()
		
		return pid

	#FUTURE: Refactor _check_alive_daemon and _get_dameon_pid
	def _check_alive_daemon(self):
		is_alive = False
		
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			ssl_sock = ssl.wrap_socket(sock,
									   ca_certs=CRT_PATH,
									   cert_reqs=ssl.CERT_REQUIRED)
			ssl_sock.connect(('127.0.0.1', self._slb_port))
			ssl_sock.write(CHECK_ALIVE_COMMAND + CHUNK_SEPARATOR_TOKEN)
			sock.shutdown(socket.SHUT_WR)
			response = ssl_sock.read()
			
			if response == (COMMAND_SUCCESS_TOKEN + CHUNK_SEPARATOR_TOKEN):
				is_alive = True
		
		except (socket.error, ssl.SSLError) as e:
			pass
		
		ssl_sock.close()
		
		return is_alive
	
	def _check_status(self):
		if self._check_alive_daemon() is True:
			print '[ ' + TerminalColor.OKGREEN + 'OK' + TerminalColor.ENDC + ' ] slb is running.'
		else:
			print '[ ' + TerminalColor.FAIL + 'FAIL' + TerminalColor.ENDC + ' ] slb is not running...'
	
	def _execute_commands(self):
		
		if os.geteuid() is not 0:
			print 'You need to be \'root\' user to use slb.'
			sys.exit(-1)
				
		if self._args['status'] is True:
			self._check_status()
		
		with_redundancy = False
		if self._args['with_redundancy'] == True:
			if self._args['load'] == True or self._args['reload'] == True:
				with_redundancy = True
			else:
				self._print_error_wtih_usage('--with-redundancy option must be used along with --load or --reload')
		
		if self._args['load'] == True:
			self._start_daemon(with_redundancy=with_redundancy)
				
		if self._args['reload'] == True:
			self._send_to_daemon('unload')
			time.sleep(3)
			self._start_daemon(with_redundancy=with_redundancy)
		
		if self._args['unload'] == True:
			self._send_to_daemon('unload')
		
		if self._args['clear_config'] is True:
			self._send_to_daemon('clear_config')
			
		if self._args['save_config'] is True:
			self._send_to_daemon('save_config')
			
		if self._args['show_config'] is True:
			self._send_to_daemon('show_config')
		
		if self._args['address'] is not None:
			self._send_to_daemon('address', self._args['address'])
			
		if self._args['address_dev'] is not None:
			self._send_to_daemon('address_dev', self._args['address_dev'])
			
		if self._args['gateway'] is not None:
			self._send_to_daemon('gateway', self._args['gateway'])
		
		if self._args['gateway_dev'] is not None:
			self._send_to_daemon('gateway_dev', self._args['gateway_dev'])
		
		if self._args['cluster_network'] is not None:
			self._send_to_daemon('cluster_network', self._args['cluster_network'])
		
		if self._args['ssh_port'] is not None:
			self._send_to_daemon('ssh_port', self._args['ssh_port'])
			
		if self._args['credentials'] is not None:
			try:
				user, password = tuple([i.strip() for i in self._args['credentials'].split(',')])
				
				self._send_to_daemon('credentials', user, password)
			except Exception, e:
				self._print_error_wtih_usage('argument of --credentials must have the format USER,PASS') 
		
		if self._args['backup_slb'] is not None:
			try:
				address, user, password, port = tuple([i.strip() for i in self._args['backup_slb'].split(',')])
				
				self._send_to_daemon('backup_slb', address, user, password, port)
			except Exception, e:
				self._print_error_wtih_usage('argument of --backup-slb must have the format ADDRESS,USER,PASS,PORT')
		
		if self._args['algorithm'] is not None:
			self._send_to_daemon('algorithm', self._args['algorithm'])
		
		for server in self._args['add_server']:
			try:
				address, port = tuple([i.strip() for i in server.split(':')])
				self._send_to_daemon('add_server', address, port)
			except Exception, e:
				self._print_error_wtih_usage('argument of --add-server must have the format ADDRESS:PORT')
		
		for server in self._args['rm_server_port']:
			try:
				address, port = tuple([i.strip() for i in server.split(':')])
				self._send_to_daemon('rm_server_port', address, port)
			except Exception, e:
				self._print_error_wtih_usage('argument of --rm-server-port must have the format ADDRESS:PORT')
		
		for address in self._args['rm_server']:
			self._send_to_daemon('rm_server', address)
		
		if self._args['rm_ssh_port'] is True:
			self._send_to_daemon('rm_ssh_port')
		
		if self._args['rm_credentials'] is True:
			self._send_to_daemon('rm_credentials')
					
	def _add_slb_arguments(self):
		manage_group = self._parser.add_argument_group('management')
		show_group = self._parser.add_argument_group('show')
		execute_group = self._parser.add_argument_group('execute')
		
		execute_group.add_argument('--status', help='Check the status of slb', action='store_true', default=False)
		execute_group.add_argument('--clear-config', help='Clear the actual in-use configuration of lsb', action='store_true', default=False)
		execute_group.add_argument('--address', help='Set the slb address for incoming clients requests')
		execute_group.add_argument('--address-dev', help='Set the slb device for incoming clients requests')
		execute_group.add_argument('--gateway', help='Set the slb gateway address for delivery client requests to real servers')
		execute_group.add_argument('--gateway-dev', help='Set the slb device for delivery client requests to real servers')
		execute_group.add_argument('--cluster-network', help='Set the slb cluster network address in CIDR notation to perform NAT in real servers', metavar='ADDRESS/CIDR_CLASS')
		execute_group.add_argument('--ssh-port', help='Set the slb SSH port')
		execute_group.add_argument('--credentials', help='Set the slb OS host credentials for the redundant system (Actually this system is only integrated with Application Manager software). The arguments are user and password, separated by a comma \',\'', metavar='USER,PASS')
		execute_group.add_argument('--backup-slb', help='Set the slb backup information for the redundant system (Actually this system is only integrated with Application Manager software). The arguments are address, user, password and SSH port, separated by a comma \',\'', metavar='ADDRESS,USER,PASS,PORT')
		execute_group.add_argument('--algorithm', help='Set a scheduling algorithm', choices=['ROUND_ROBIN', 'LOWER_LATENCY', 'LEAST_CONNECTIONS'])
		execute_group.add_argument('--add-server', help='Add a real server for slb', action='append', default=[], metavar='ADDRESS:PORT')
		execute_group.add_argument('--save-config', help='Save in the default configuration file the actual slb configuration', action='store_true', default=False)
		execute_group.add_argument('--rm-credentials', help='Remove the slb OS host credentials for the redundant system (Actually this system is only integrated with Application Manager software)', action='store_true', default=False)
		execute_group.add_argument('--rm-ssh-port', help='Remove the slb SSH port', action='store_true', default=False)
		execute_group.add_argument('--rm-server', help='Remove a real server from slb', action='append', default=[])
		execute_group.add_argument('--rm-server-port', help='Remove a real server port from slb', action='append', default=[], metavar='ADDRESS:PORT')
		
		show_group.add_argument('--show-config', help='Show the actual slb configuration in JSON format', action='store_true', default=False)
		show_group.add_argument('--version', action='version', version='%(prog)s 0.1')	
		
		manage_mutex_group = manage_group.add_mutually_exclusive_group()
		manage_mutex_group.add_argument('--load', help='Load the slb module and initializes the slb functions', action='store_true', default=False)
		manage_mutex_group.add_argument('--unload', help='Unload the slb module and stop the slb functions', action='store_true', default=False)
		manage_mutex_group.add_argument('--reload', help='Reload the slb module and restart the slb functions', action='store_true', default=False)
		manage_group.add_argument('--with-redundancy', help='Set the slb to work in a redundant system with primary and backup nodes, initially at active and standby modes, respectively (Actually this system is only integrated with Application Manager software)', action='store_true', default=False)
		

if __name__ == '__main__':
	slbcli = SlbCli()