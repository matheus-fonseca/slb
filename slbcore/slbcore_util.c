#include "slbcore_util.h"


slb_service* slb_service_new(__be16 port) {
	slb_service *new_service = NULL;
	
	new_service = (slb_service*) kmalloc(sizeof(slb_service), GFP_ATOMIC);
	new_service->servers = NULL;
	new_service->port = port;
	
	return new_service;
}

slb_client* slb_check_client_persistence(UT_array *clients, __be32 addr) {
	slb_client *client_found = NULL;
	slb_client **client_found_ref = NULL;
	slb_client *client_search = NULL;
	
	if(clients) {
		client_search = kmalloc(sizeof(slb_client), GFP_ATOMIC);
		client_search->addr = addr;
		
		client_found_ref = (slb_client **) utarray_find(clients, &client_search, slb_client_cmp);
		
		if(client_found_ref)
			client_found = *client_found_ref;
		
		kfree(client_search);	
	}
	
	return client_found;
}

void _slb_client_insert_sorted(UT_array *clients, slb_client *new_client) {
	slb_client *client_itr = NULL;
	__s16 new_index;
	
	if (clients && new_client) {
		for(new_index = 0; new_index < utarray_len(clients); new_index++) {
			client_itr = *((slb_client**) utarray_eltptr(clients, new_index));
			if (new_client->addr < client_itr->addr)
				break;
		}
		
		utarray_insert(clients, &new_client, new_index);
	}
}

slb_client* slb_add_client(UT_array *clients, __be32 addr, slb_server *server) {
	slb_client *new_client = NULL;
	struct timeval tv_current;
	
	if(clients && server) {
		new_client = kmalloc(sizeof(slb_client), GFP_ATOMIC);
		new_client->addr = addr;
		new_client->server = server;
		do_gettimeofday(&tv_current);
		new_client->sec_last_conn = tv_current.tv_sec;
		
		_slb_client_insert_sorted(server->clients, new_client);
		_slb_client_insert_sorted(clients, new_client);
	}
	
	return new_client;
}

__u16 slb_server_active_conn_count(slb_server *server) {
	__u16 i, count = 0;
	slb_client *client_itr = NULL;
	struct timeval tv_current;
	
	do_gettimeofday(&tv_current);
	
	if(server) {
		for (i = 0; i < utarray_len(server->clients); i++) {
			client_itr = *((slb_client **) utarray_eltptr(server->clients, i));	
		
			if((tv_current.tv_sec - client_itr->sec_last_conn) < 60)
				count++;
		}
	}
	
	return count;
}

slb_server* slb_service_add_server(slb_service *service, __be32 addr) {
	slb_server *new_server = NULL;
	slb_server *server_itr = NULL;
	__u16 count = 0;
	
	if (service) {
		new_server = (slb_server*) kmalloc(sizeof(slb_server), GFP_ATOMIC);
		new_server->addr = addr;
		new_server->clients = NULL;
		utarray_new(new_server->clients, &slb_server_clients_icd);
		
		CDL_COUNT(service->servers, server_itr, count);
		if(count == 0) {
			service->actual_server = new_server;	
		}
		
		CDL_APPEND(service->servers, new_server);
	} 
	
	return new_server;
}

void _slb_rm_related_clients(UT_array *clients, slb_server *server) {
	slb_client **client_found_ref = NULL;
	slb_client *client_itr = NULL;
	__u16 index;
	__u16 i;
	
	for (i = 0; i < utarray_len(server->clients); i++) {
		client_itr = *((slb_client **) utarray_eltptr(server->clients, i));

		client_found_ref = (slb_client **) utarray_find(clients, &client_itr, slb_client_cmp);	
		if(client_found_ref) {
			logger_info("Removing client %pI4 connected to %pI4", &((*client_found_ref)->addr), &server->addr);
			index = utarray_eltidx(clients, client_found_ref);
			utarray_erase(clients, index, 1);
		}
	}
}

void slb_service_rm_server(slb_service *service, __be32 addr, UT_array *clients) {
	slb_server *server_found = NULL;
	slb_server *server_itr = NULL;
	__u16 count = 0;
	
	if(service) {
		CDL_SEARCH_SCALAR(service->servers, server_found, addr, addr);
		
		if(server_found) {
			if(slb_server_cmp(&service->actual_server, &server_found) == 0) {
				CDL_COUNT(service->servers, server_itr, count);
				if(count > 1) {
					service->actual_server = service->actual_server->next;
				}
			}
			
			CDL_DELETE(service->servers, server_found);
			
			_slb_rm_related_clients(clients, server_found);
			
			utarray_free(server_found->clients);
			
			kfree(server_found);
		}
	}
}

void slb_free_services(slb_service *services, UT_array *clients) {
	slb_service *service_itr = NULL;
	slb_service *service_tmp = NULL;
	slb_server *server_itr = NULL;
	slb_server *server_tmp1 = NULL;
	slb_server *server_tmp2 = NULL;
	
	if(services) {
		HASH_ITER(hh, services, service_itr, service_tmp) {				
			CDL_FOREACH_SAFE(service_itr->servers, server_itr, server_tmp1, server_tmp2) {
				CDL_DELETE(service_itr->servers, server_itr);
				
				if(clients)
					_slb_rm_related_clients(clients, server_itr);
				
				utarray_free(server_itr->clients);
				
				kfree(server_itr);
			}
			
			HASH_DEL(services, service_itr); 
			kfree(service_itr);
		}
	}
	
	services = NULL;
}

__u16 _slb_str_char_occur(char *str, const char occur) {	
	__u16 count;
	for (count=0; str[count]; str[count]==occur ? count++ : *str++);
	
	return count;
}

__s16 slb_str_split(char *str, const char occur, UT_array* split_msg) {
	__u16 i, j, token_len, num_tokens;
	__s16 rc = 0;
	
	char *str_itr;
	char *token;
	
	if(split_msg == NULL) {
		rc = -1;
	} else {
		str_itr = str;
		num_tokens = _slb_str_char_occur(str, occur);

		if(num_tokens == 0) {
			rc = -1;
		} else {
			for(i = 0; i < num_tokens; i++) {
				for(j = 0; str_itr[j] != occur && str_itr[j]; j++);

				token = NULL;
				token_len = j + 1;
				token = kcalloc(token_len, sizeof(char), GFP_ATOMIC); 
				memcpy(token, str_itr, token_len-1);
				token[token_len] = '\0';

				utarray_push_back(split_msg, &token);

				str_itr+=token_len;
			}
		}
	}
	
	return rc;
}

__be32 slb_ip_from_device(const struct net_device *device) {
	struct in_device *in_dev; 
	struct in_ifaddr *if_info; 
	__be32 addr = 0; 

	if (device) {
		in_dev = (struct in_device *)device->ip_ptr; 
		if_info = in_dev->ifa_list; 
		addr = (__u32) if_info->ifa_local;	
	}
	
	return addr;
}