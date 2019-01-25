#!/usr/bin/env python

import scp
import paramiko
from utils import *
from config_manager import *
from slbd import *
import os
import sys
import socket 
import threading

logger = SlbLogger().get_logger(__name__)

ACTIVE_STATE = 'ACTIVE'
STANDBY_STATE = 'STANDBY'
OFFLINE_STATE = 'OFFLINE'
OTHER_STATE = 'OTHER'
VALID_APP_STATES = (ACTIVE_STATE, STANDBY_STATE, OFFLINE_STATE)

IP_COMMAND_ADD_RM = 'ip addr %s %s/24 dev %s'
IP_COMMAND_FLUSH = 'ip addr flush dev %s'

APP_NAME = 'slb'
APP_MGR_PORT = 2200
APP_MGR_RULEOFTHUMB = '4c6c14a5de1cacbdab5dcf71e0078c7f'

class _ConfigSynchronizer:
	def __init__(self, server, port, user, password):
		self.TIMEOUT=4
		
		try:
			self._ssh_client = self._create_ssh_client(server, port, user, password)
			self._scp_client = scp.SCPClient(self._ssh_client.get_transport())
		except (paramiko.BadHostKeyException, paramiko.AuthenticationException, paramiko.SSHException, scp.SCPException, socket.error, socket.timeout) as e:
			raise ConfigurationRedundancyError(str(e))
	
	def _create_ssh_client(self, server, port, user, password):
		ssh_client = paramiko.SSHClient()
		ssh_client.load_system_host_keys() 
		ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) 
		ssh_client.connect(server, port=port, username=user, password=password, timeout=self.TIMEOUT)
		
		return ssh_client

	def synchronize(self, local_files_paths, remote_file_path):
		self._scp_client.put(files=local_files_paths, remote_path=remote_file_path, recursive=False , preserve_times=False)
		

class RedundancyManager:
	def __init__(self):
		self.SEC_BETWEEN_CONFIG_SYNC = 10
		self.SEC_BETWEEN_STATE_CHECK = 5
		self.SEC_APP_MGR_CHECK = 3
		self.SEC_CONN_TIMEOUT = 3
		
		self._app_state = OTHER_STATE
		self._check_state_lock = threading.Lock()
		
		self._initial_app_mgr_conf_done = False
		self._config_mgr = ConfigManager()
		
		slb_backup_data = self._config_mgr.get_slb_backup()
		if None in slb_backup_data:
			raise ConfigurationRedundancyError('slb backup node information is not configured')	
		else:
			self._config_sync = _ConfigSynchronizer(*slb_backup_data)
		
	def _send_and_recv_app_mgr(self, msg):
		response = ''
		
		msg_with_endline = msg + '\n'
		if self._sock is not None:
			try:
				self._sock.send(msg_with_endline)
				
				response = self._sock.recv(4096)
				response = response.rstrip('\r\n')
			except socket.error, e:
				logger.error('Problem at send/recv with AppMgr: (' + str(e.__class__.__name) + ') ' + str(e))

		return response
	
	def _send_app_mgr(self, msg):
		msg_with_endline = msg + '\n'
		
		if self._sock is not None:
			try:
				self._sock.send(msg_with_endline)
			except socket.error, e:
				logger.error('Problem at send/recv with AppMgr: (' + str(e.__class__.__name) + ') ' + str(e))
	
	def _register_app_mgr(self):
		register_msg = 'APP ' + APP_NAME + ' ' + APP_NAME + ' REGISTRATION'
		register_resp = self._send_and_recv_app_mgr(register_msg)
		
		logger.info('AppMgr register response = ' + register_resp)
			
	def _authenticate_app_mgr(self):
		auth_msg = APP_NAME + ' ' + APP_MGR_RULEOFTHUMB
		
		response = self._send_and_recv_app_mgr(auth_msg)
		
		if response != 'ACK':
			return False
		else:
			return True
	
	def _state_machine_event(self, from_state, to_state):
		
		if from_state == STANDBY_STATE and to_state == ACTIVE_STATE:
			self._config_sync = None
			
			self._config_mgr.load_default_config()
			
			address_dev =  self._config_mgr.get_slb_address_device()
			address =  self._config_mgr.get_slb_address()
			
			rc = os.system(IP_COMMAND_FLUSH % address_dev)
			if rc is not 0:
				logger.error('Problem on state change event from STANDBY_STATE to ACTIVE_STATE: Flush interface')
				
			rc = os.system(IP_COMMAND_ADD_RM % ('add', address, address_dev))
			if rc is not 0:
				logger.error('Problem on state change event from STANDBY_STATE to ACTIVE_STATE: Add new address ' + address)
			
			bkp_address, bkp_ssh_port, bkp_user, bkp_pass  =  self._config_mgr.get_slb_backup()
			
			gateway =  self._config_mgr.get_slb_cluster_gateway()
			user, password =  self._config_mgr.get_slb_credentials()
			ssh_port =  self._config_mgr.get_slb_ssh_port()
			
			self._config_mgr.set_slb_cluster_gateway(bkp_address)
			self._config_mgr.set_slb_credentials(bkp_user, bkp_pass)
			self._config_mgr.set_slb_ssh_port(bkp_ssh_port)
			
			self._config_mgr.set_slb_backup(gateway, user, password, ssh_port)
			
			self._config_mgr.save_config()
			
			self._config_sync = _ConfigSynchronizer(gateway, ssh_port, user, password)
			
		elif from_state == ACTIVE_STATE and to_state == STANDBY_STATE:
			address =  self._config_mgr.get_slb_address()
			address_dev =  self._config_mgr.get_slb_address_device()
			rc = os.system(IP_COMMAND_ADD_RM % ('del', address, address_dev))
			
			if rc is not 0:
				logger.error('Problem on state change event from ACTIVE_STATE to STANDBY_STATE')
		elif to_state == OFFLINE_STATE:
			SlbDaemon().stop_listening()
			self._sock.close()
			sys.exit()
	
	def _change_state(self, state_msg):
		if state_msg.startswith('CMD') is True:
			new_state = state_msg.split(' ')[1]
			
			with self._check_state_lock:
				if new_state in VALID_APP_STATES:
					logger.info('State change from "'+ self._app_state +'" to "' + new_state + '"')
					self._state_machine_event(self._app_state, new_state)
					self._app_state = new_state
				else:
					logger.warning('Invalid state "' + state_msg + '". Defining "OTHER" state.')
					self._app_state = OTHER_STATE
		else:
			logger.warning('Invalid chage state message: ' + state_msg)
			
	def _check_state(self):
		with self._check_state_lock:
			return self._app_state
	
	def app_mgr_check(self):
		
		if self._initial_app_mgr_conf_done is False:
			time.sleep(self.SEC_APP_MGR_CHECK)
			
			try:
				logger.info('Creating AppMgr socket')
				self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				self._sock.settimeout(self.SEC_CONN_TIMEOUT)
				self._sock.connect(('127.0.0.1', APP_MGR_PORT))
			except socket.error, e:
				logger.error('Problem creating socket with AppMgr: ' + str(e))
				return

			if self._authenticate_app_mgr() is False:
				logger.warning('Can\'t authenticate with AppMgr (port = '+ str(APP_MGR_PORT) +')')
				self._sock.close()
				return
			else:
				logger.info('Authenticated with AppMgr (port = '+ str(APP_MGR_PORT) +')')

			self._register_app_mgr()

			req_ini_state_msg = 'REQ_INIT_STATE'
			self._send_app_mgr(req_ini_state_msg)
			self._initial_app_mgr_conf_done = True
			
		try:
			msg = self._sock.recv(4096)
			msg = msg.rstrip('\r\n')

			if len(msg) == 0:
				return

			if msg.startswith('CMD') is True:
				self._change_state(msg)
				self._sock.send('ACK\n')
			elif msg.startswith('TEST PING') is True:
				self._sock.send('TESTACK\n')

		except socket.timeout, e:
			pass
		except Exception, e:
			logger.error('Problem receiving AppMgr msg: <'+ e.__class__.__name__ +'> ' + str(e))
		
		
	def sync_config(self):
		while self._app_state == ACTIVE_STATE and self._config_sync is not None:
			try:
				#TODO: change this
#				self._config_sync.synchronize([CONFIG_FILE_DEFAULT_PATH, LOG_CONFIG_FILE], os.path.dirname(CONFIG_FILE_DEFAULT_PATH))
				self._config_sync.synchronize([CONFIG_FILE_DEFAULT_PATH, LOG_CONFIG_FILE], '/vagrant/slb_backup/conf/')
			except SCPError, e:
				logger.error('Problem syncing files: ' + str(e))
			time.sleep(self.SEC_BETWEEN_CONFIG_SYNC)
		time.sleep(self.SEC_BETWEEN_STATE_CHECK)
