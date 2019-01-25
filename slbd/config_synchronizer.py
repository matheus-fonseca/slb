#!/usr/bin/env python

import scp
import paramiko
from utils import *

logger = SlbLogger().get_logger(__name__)

class ConfigSynchronizer:
	def __init__(self, server, port, user, password):
		self.TIMEOUT=4
		
		try:
			self._ssh_client = self._create_ssh_client(server, port, user, password)
			self._scp_client = scp.SCPClient(self._ssh_client.get_transport())
		except (paramiko.BadHostKeyException, paramiko.AuthenticationException, paramiko.SSHException, scp.SCPException, socket.error, socket.timeout) as e:
			raise ConfigurationSSHError(str(e))
	
	def _create_ssh_client(self, server, port, user, password):
		ssh_client = paramiko.SSHClient()
		ssh_client.load_system_host_keys() 
		ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) 
		ssh_client.connect(server, port=port, username=user, password=password, timeout=self.TIMEOUT)
		
		return ssh_client

	def synchronize(self, local_files_paths, remote_file_path):
		try:
			self._scp_client.put(files=local_files_paths, remote_path=remote_file_path, recursive=False , preserve_times=False)
			logger.info('Configuration files synchronized')
		except SCPException, e:
			raise SCPError(str(e))

if __name__ == "__main__":
	confi_sync = ConfigSynchronizer('127.0.0.1', 22, 'matheus', 'm@t123.SF')
	confi_sync.syncronize(['slb_conf.json', 'slb_logging_conf.json'], '/Users/matheus/GoogleDrive/Documentos/UnB/TCC/slb/')