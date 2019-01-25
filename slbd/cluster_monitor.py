#!/usr/bin/env python

# THREADING TUTORIAL: 
#
# http://pymotw.com/2/threading/

from threading import Thread
import socket
import os
import sys
import time
from datetime import datetime
from utils import *

TIMEOUT=3000 # miliseconds

logger = SlbLogger().get_logger(__name__)

# FUTURE: Make a thread pool
class ThreadWithReturn(Thread):
	def __init__(self, group=None, target=None, name=None,
				 args=(), kwargs={}, Verbose=None):
		Thread.__init__(self, group, target, name, args, kwargs, Verbose)
		self._return = None
	def run(self):
		if self._Thread__target is not None:
			self._return = self._Thread__target(*self._Thread__args,
												**self._Thread__kwargs)
	def join(self):
		Thread.join(self)
		return self._return
	
class ClusterMonitor:
	
	def __init__(self):
		self.timeout = TIMEOUT
	
	def is_server_up(self, address):
		result = os.system('ping -c 2 -W '+ str(self.timeout) +' '+ address +' > /dev/null 2>&1')
		
		if result == 0:
			return True
		else:
			return False
	
	def is_service_up(self, address, port):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(self.timeout/1000)
		try:
			result = sock.connect_ex((address, port))
		except Exception, e:
			result = -1
			logger.error('Problem checking service ('+ address + ':' + str(port) +'): ' + str(e))
		finally:
			sock.close()
		
		if result == 0:
			return True
		else:
			return False
	
	def service_latency(self, address, port):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(self.timeout/1000)
		elapsed_time = 0
		try:
			start_time = time.time()
			result = sock.connect_ex((address, port))
			elapsed_time = time.time() - start_time
		except Exception, e:
			result = -1
			logger.error('Problem checking service ('+ address + ':' + str(port) +'): ' + str(e))
		finally:
			sock.close()
		
		if result == 0:
			return (True, elapsed_time)
		else:
			return (False, 0)
	
	def check_servers(self, servers):
		servers_ips = []
		for server in servers:
			try:
				servers_ips[i] += socket.gethostbyname_ex(server)[2][0]
			except socket.gaierror:
				pass
			
		threads = []
		for server in servers:
			t = ThreadWithReturn(target=self.is_server_up, args=(server,))
			t.start()
			
			threads.append(t)
		
		results=[]
		for (server, t) in zip(servers_ips, threads):
			is_up = t.join()
			
			results.append((server, is_up))
		
		logger.debug('Servers checking done')
		
		return results
	
	def check_services(self, servers_with_ports):
		servers_ips_with_ports = []
		offline_services = []
		for server_n_ports in servers_with_ports:
			try:
				server_ip = socket.gethostbyname_ex(server_n_ports[0])[2][0]
				servers_ips_with_ports.append((server_ip, server_n_ports[1]))
			except socket.gaierror:
				pass
		
		threads = []
		for server, ports in servers_ips_with_ports:
			for port in ports:
				t = ThreadWithReturn(target=self.service_latency, args=(server,port,))
				t.start()

				threads.append(t)
		
		services={}
		threads_list_start_index=0
		threads_list_end_index=0
		for server, ports in servers_ips_with_ports:
			threads_list_end_index+=len(ports)
			for (port, t) in zip(ports, threads[threads_list_start_index:threads_list_end_index]):
				is_up, latency = t.join()
				if is_up == True:
					if services.has_key(port):
						services[port].append((server, latency))
					else:
						services[port] = [(server, latency)]
				else:
					offline_services.append(server + ':' + str(port))
					
			threads_list_start_index=threads_list_end_index
			
		for port, servers_and_latencies in services.items():
			sorted_servers_and_latencies = sorted(servers_and_latencies, key=lambda tup: tup[1])
			services[port] = [i[0] for i in sorted_servers_and_latencies]
		
		if len(offline_services) > 1:
			is_only_one_offline = len(offline_services) is 1
			offline_services_msg = 'Service%s %s %s offline' % ('' if is_only_one_offline else 's', str(offline_services), 'is' if is_only_one_offline else 'are')
			logger.warning(offline_services_msg)
		
		return services
	
if __name__ == '__main__':
	cluster_monior = ClusterMonitor()