// HEADERS
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/netlink.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>

// MY HEADERS
#include <slbcore_util.h>
#include <checksum/checksum.h>
#include "uthash/utarray.h"
#include "uthash/uthash.h"

// DEFINITIONS
#define CHUNK_SEPARATOR_TOKEN '|'
#define CLEAR_CONFIG_COMMAND "clear_config"
#define ORDER_SERVICE_COMMAND "order_running_service"
#define ADD_SERVICE_COMMAND "add_running_service"
#define RM_SERVICE_COMMAND "rm_running_service"
#define SET_SLB_ADDRESS_COMMAND "set_slb_address"
#define SET_SLB_ALGORITHM_COMMAND "set_slb_algorithm"
#define ROUND_ROBIN_STR "ROUND_ROBIN"
#define LOWER_LATENCY_STR "LOWER_LATENCY"
#define LEAST_CONNECTIONS_STR "LEAST_CONNECTIONS"


 // == 127.0.0.1
#define LOCALHOST_IP 0x100007f

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matheus Fonseca <1matheusfonseca@gmail.com>");
MODULE_DESCRIPTION("slbcore - A kernel module for the slb (server load balancing) solution");
MODULE_VERSION("0.1.0"); 

static struct nf_hook_ops slb_pre_routing_hook_ops;
static struct nf_hook_ops slb_post_routing_hook_ops;
static struct sock *netlink_sock = NULL;
static slb_service *services = NULL;
static UT_array *clients;
static struct slb_conf slb_conf; 
//static DEFINE_SPINLOCK(slb_lock);
//unsigned long flags;
//spin_lock_irqsave(&slb_lock, flags);
//spin_unlock_irqrestore(&slb_lock, flags);
	
static void slb_order_service(__be16 hport, UT_array *servers) {
	slb_service *service_found = NULL;
	slb_server *server_found = NULL;
	slb_server *server_itr = NULL;
	slb_server *server_tmp1 = NULL;
	slb_server *server_tmp2 = NULL;
	UT_array *ordered_servers = NULL;
	
	__u16 i;
	__be32 addr;
	__be16 nport;
	char ** str_ref;
	
	utarray_new(ordered_servers, &slb_server_icd);
	nport = htons(hport);

	HASH_FIND_INT16(services, &nport, service_found);

	if(service_found) {
		for (i = 0; i < utarray_len(servers); i++) {
			str_ref = (char **)utarray_eltptr(servers, i);

			if(str_ref) {
				addr = in_aton(*str_ref);
				if (addr == 0) {
					logger_error("Invalid address: %s. Not adding server.", *str_ref); 
				} else {
					CDL_SEARCH_SCALAR(service_found->servers, server_found, addr, addr);
					if (server_found) {
						utarray_push_back(ordered_servers, &server_found);
					}
				}
			}
		}
		
		// TODO: Spinlock it ?
		CDL_FOREACH_SAFE(service_found->servers, server_itr, server_tmp1, server_tmp2) {
			CDL_DELETE(service_found->servers, server_itr);
		}
		
		service_found->actual_server = *((slb_server **)utarray_eltptr(ordered_servers, 0));
		
		for (i = 0; i < utarray_len(ordered_servers); i++) {
			server_itr = *((slb_server **)utarray_eltptr(ordered_servers, i));
			CDL_APPEND(service_found->servers, server_itr);
		}
	}
	
	utarray_free(ordered_servers);
}
	
static void slb_add_service(__be16 hport, UT_array *servers) {
	slb_service *service_found = NULL;
	slb_service *add_service = NULL;
	__u16 i;
	__be32 addr;
	__be16 nport;
	char ** str_ref;
	
	nport = htons(hport);
	
	HASH_FIND_INT16(services, &nport, service_found);
	
	if(service_found) {
		add_service = service_found;
	} else {
		add_service = slb_service_new(nport); 
		HASH_ADD_INT16(services, port, add_service);
	}
	
	for (i = 0; i < utarray_len(servers); i++) {
		str_ref = (char **)utarray_eltptr(servers, i);
		
		if(str_ref) {
			addr = in_aton(*str_ref);
			if (addr == 0) {
				logger_error("Invalid address: %s. Not adding server.", *str_ref); 
			} else {
				slb_service_add_server(add_service, addr);

				logger_info("Adding service %pI4:%u", &addr, ntohs(nport));
			}
		}
	}
}

static void slb_rm_service(__be16 hport, UT_array *servers) {
	slb_service *service_found = NULL;
	__u16 i;
	__be32 addr;
	__be16 nport;
	char ** str_ref;
	
	nport = htons(hport);
	
	HASH_FIND_INT16(services, &nport, service_found);
	
	if(service_found) {
		for (i = 0; i < utarray_len(servers); i++) {
			str_ref = (char **)utarray_eltptr(servers, i);
		
			if(str_ref) {
				addr = in_aton(*str_ref);
				if (addr == 0) {
					logger_error("Invalid address: %s. Not removing server.", *str_ref); 
				} else {
					slb_service_rm_server(service_found, addr, clients);

					logger_info("Removing service %pI4:%u", &addr, ntohs(nport));
				}	
			}
		}
		
		if(HASH_COUNT(services) == 0) {
			HASH_DEL(services, service_found);
			kfree(service_found);	
		}
	} 
}

void slb_clear_config(void) {
	slb_free_services(services, clients);
	
	slb_conf.slb_algorithm = ROUND_ROBIN;
	slb_conf.slb_address = 0;
}

void set_slb_address(char *address) {
	__be32 addr = in_aton(address);
	
	
	if(addr) {
		slb_conf.slb_address = addr;
		
		logger_info("Setting address = %pI4", &slb_conf.slb_address);	
	} else {
		logger_error("Invalid address: %s. Not setting slb address.", address); 
	}
	
	slb_service *service_itr = NULL, *service_tmp = NULL;
	slb_server *server_itr = NULL;
	slb_client *client_itr = NULL;
	__u16 server_active_conn_count;
	__u16 i;

	HASH_ITER(hh, services, service_itr, service_tmp) {
		logger_info("PORT: %u", ntohs(service_itr->port));
		CDL_FOREACH(service_itr->servers, server_itr) {
			server_active_conn_count = slb_server_active_conn_count(server_itr);
			logger_info("-Server: %pI4 (%u active conn)", &server_itr->addr, server_active_conn_count);
			
			for (i = 0; i < utarray_len(server_itr->clients); i++) {
				client_itr = *((slb_client **) utarray_eltptr(server_itr->clients, i));
				logger_info("---client: %pI4 (last conn = %lld)", &client_itr->addr, client_itr->sec_last_conn);
			}
		}
	}
}

void set_slb_algorithm(char *algorithm) {
	if(strcmp(algorithm, ROUND_ROBIN_STR) == 0) {
		slb_conf.slb_algorithm = ROUND_ROBIN;
	} else if(strcmp(algorithm, LOWER_LATENCY_STR) == 0) {
		slb_conf.slb_algorithm = LOWER_LATENCY;
	} else if(strcmp(algorithm, LEAST_CONNECTIONS_STR) == 0) {
		slb_conf.slb_algorithm = LEAST_CONNECTIONS;
	} else {
		logger_error("Invalid algorithm: %s. Maintaining last defined.", algorithm);	
		return;
	}
	
	logger_info("Setting algorithm = %s", algorithm);
}

void slb_execute_command(char *command_name, UT_array *params) {
	__be16 port = 0;
	__s16 rc;
	char ** str_ref;
	
	if(strcmp(command_name, CLEAR_CONFIG_COMMAND) == 0) {
		 slb_clear_config();
		
	} else if(strcmp(command_name, SET_SLB_ADDRESS_COMMAND) == 0) {
		str_ref = (char **)utarray_eltptr(params, 0);
		
		if(str_ref) {
			set_slb_address(*str_ref);
		}
		
	} else if(strcmp(command_name, SET_SLB_ALGORITHM_COMMAND) == 0) {
		str_ref = (char **)utarray_eltptr(params, 0);
		
		if(str_ref) {
			set_slb_algorithm(*str_ref);
		}
		
	} else if(strcmp(command_name, ADD_SERVICE_COMMAND) == 0) {
		str_ref = (char **)utarray_eltptr(params, 0);
		
		if(str_ref) {
			rc = kstrtol(*str_ref, 10, (long *)&port);
			if(rc == 0) {
				utarray_erase(params, 0, 1);
				slb_add_service(port , params);	
			} else {
				logger_error("Error parsing port '%s'. Not adding service", *str_ref);
			}
		}
		
	} else if(strcmp(command_name, RM_SERVICE_COMMAND) == 0) {
		str_ref = (char **)utarray_eltptr(params, 0);
		
		if(str_ref) {
			rc = kstrtol(*str_ref, 10, (long *)&port);
			if(rc == 0) {
				utarray_erase(params, 0, 1);
				slb_rm_service(port , params);	
			} else {
				logger_error("Error parsing port '%s'. Not adding service", *str_ref);
			}
		}
	} else if(strcmp(command_name, ORDER_SERVICE_COMMAND) == 0) {
		str_ref = (char **)utarray_eltptr(params, 0);

		if(str_ref) {
			rc = kstrtol(*str_ref, 10, (long *)&port);
			if(rc == 0) {
				utarray_erase(params, 0, 1);
				slb_order_service(port , params);	
			} else {
				logger_error("Error parsing port '%s'. Not adding service", *str_ref);
			}
		}
	} else {
		logger_error("Invalid command came from slbd: %s", command_name);	
	}
	
	utarray_free(params);	
}

static slb_server* slb_load_balance(__be32 src_addr, __be16 dest_port) {
	slb_client *client_found = NULL;
	slb_service *service_found = NULL;
	slb_client *new_client = NULL;
	slb_server *server = NULL;
	slb_server *server_itr = NULL;
	__u16 count = 0;
	__u16 server_active_conn_count, itr_active_conn_count;
	struct timeval tv_current;
	
	HASH_FIND_INT16(services, &dest_port, service_found);
	if(service_found) {
		client_found = slb_check_client_persistence(clients, src_addr);
		if(client_found) {
			server = client_found->server;
			
			do_gettimeofday(&tv_current);
			client_found->sec_last_conn = tv_current.tv_sec;
		} else {		
			CDL_COUNT(service_found->servers, server_itr, count);
			if(count > 0) {
				if(slb_conf.slb_algorithm == ROUND_ROBIN) {
					server = service_found->actual_server;
					service_found->actual_server = service_found->actual_server->next;	
				} else if (slb_conf.slb_algorithm == LOWER_LATENCY) {
					server = service_found->actual_server;
				} else if (slb_conf.slb_algorithm == LEAST_CONNECTIONS) {
					server = service_found->actual_server;
					server_active_conn_count = slb_server_active_conn_count(server);

					CDL_FOREACH(service_found->servers, server_itr) {
						itr_active_conn_count = slb_server_active_conn_count(server_itr);

						if(server_active_conn_count > itr_active_conn_count) {
							server = server_itr;
							server_active_conn_count = itr_active_conn_count;
						} 
					}
					
					service_found->actual_server = server;
				} 
				
				new_client = slb_add_client(clients, src_addr, server);
				logger_info("New client %pI4 -> %pI4 (at time %lld sec)", &new_client->addr, &new_client->server->addr, (long long int) new_client->sec_last_conn);

			}
		}
	} 
	
	return server;
}

static __s16 slb_recalculate_checksums(struct iphdr *ip_head, struct tcphdr *tcp_head, struct udphdr *udp_head) {
	__s16 rc = 0;
	
	compute_ip_checksum(ip_head);
	
	if(ip_head->protocol == IPPROTO_TCP)
		compute_tcp_checksum(ip_head, (unsigned short *) tcp_head);
	else 
		compute_udp_checksum(ip_head, (unsigned short *) udp_head);

//	if(validate_ip_checksum(ip_head) != 0) {
//		logger_error("Error calculating checksum = %x (src = %pI4, dest = %pI4). Will drop packet...", ip_head->check, &ip_head->saddr, &ip_head->daddr);
//
//		rc = -1;
//	}
	
	return rc;
}

static unsigned int slb_post_routing_hook(
					   unsigned int hooknum,
					   struct sk_buff *skb,
					   const struct net_device *in_device,
					   const struct net_device *out_device,
					   int (*okfn)(struct sk_buff *)) {
	
	struct iphdr *ip_head = (struct iphdr *)skb_network_header(skb);
	struct tcphdr *tcp_head = NULL;
	struct udphdr *udp_head = NULL;
	
	__be32 *src_addr = &ip_head->saddr;
	__be32 dest_addr = ip_head->daddr;
	__be32 out_dev_addr = slb_ip_from_device(out_device);
	__be16 src_port;	
	
	if(*src_addr == LOCALHOST_IP)
		return NF_ACCEPT;
	
	if(ip_head->protocol == IPPROTO_TCP) {
		tcp_head = (struct tcphdr *)((__u32 *)ip_head + ip_head->ihl);
		src_port = tcp_head->source;
	} else if (ip_head->protocol == IPPROTO_UDP) {
		udp_head = (struct udphdr *)((__u32 *)ip_head + ip_head->ihl);
		src_port = udp_head->dest;
	} else {
		return NF_ACCEPT;
	}
	
	if(out_dev_addr != slb_conf.slb_address)
		return NF_ACCEPT;
	
//	logger_info("POST/BEFORE %pI4:%u -> %pI4", src_addr, ntohs(src_port), &dest_addr);
	*src_addr = slb_conf.slb_address;
	slb_recalculate_checksums(ip_head, tcp_head, udp_head);
//	logger_info("POST/AFTER %pI4:%u -> %pI4\n", src_addr, ntohs(src_port), &dest_addr);
	
	return NF_ACCEPT;

//enum ip_conntrack_info ctinfo;
//struct nf_conn *ct;
//	logger_info("POST HOOK = %pI4 -> %pI4", &src_addr, &dest_addr);
//	ct = nf_ct_get(skb, &ctinfo);
//	if (ct == NULL) {
//		logger_info("Packet == NULL");
//	} else if (ctinfo % IP_CT_IS_REPLY == IP_CT_NEW) {
//		logger_info("Packet == IP_CT_NEW");
//	} else if (ctinfo % IP_CT_IS_REPLY == IP_CT_RELATED) {
//		logger_info("Packet == IP_CT_RELATED");
//	} else if (ctinfo % IP_CT_IS_REPLY == IP_CT_ESTABLISHED) {
//		logger_info("Packet == IP_CT_ESTABLISHED");
//	} 
//
//	if(CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL) {
//		logger_info("ORIGINAL -> ");
//	} else if (CTINFO2DIR(ctinfo) == IP_CT_DIR_REPLY) {
//		logger_info("IS REPLY <- ");
//	}
}

// TODO: ifdef DEBUG; set missing packets attributes and print (before and after hooks)
static unsigned int slb_pre_routing_hook(
					   unsigned int hooknum,
					   struct sk_buff *skb,
					   const struct net_device *in_device,
					   const struct net_device *out_device,
					   int (*okfn)(struct sk_buff *)) {
	
	struct iphdr *ip_head = (struct iphdr *)skb_network_header(skb);
	struct tcphdr *tcp_head = NULL;
	struct udphdr *udp_head = NULL;
	
	__be32 *dest_addr = &ip_head->daddr;
	__be32 src_addr = ip_head->saddr;
	__be32 in_dev_addr = slb_ip_from_device(in_device);
	__be16 dest_port;
	
	slb_server *server;
	
	if(src_addr == LOCALHOST_IP)
		return NF_ACCEPT;
	
	if(ip_head->protocol == IPPROTO_TCP) {
		tcp_head = (struct tcphdr *)((__u32 *)ip_head + ip_head->ihl);
		dest_port = tcp_head->dest;
	} else if (ip_head->protocol == IPPROTO_UDP) {
		udp_head = (struct udphdr *)((__u32 *)ip_head + ip_head->ihl);
		dest_port = udp_head->dest;
	} else {
		return NF_ACCEPT;
	}
	
	if(in_dev_addr != slb_conf.slb_address) 
		return NF_ACCEPT;
	
	server = slb_load_balance(src_addr, dest_port);
	if(!server)
		return NF_ACCEPT;
	
//	logger_info("PRE/BEFORE %pI4 -> %pI4:%u", &src_addr, dest_addr, ntohs(dest_port));
	*dest_addr = server->addr;
	slb_recalculate_checksums(ip_head, tcp_head, udp_head);
//	logger_info("PRE/AFTER %pI4 -> %pI4:%u\n", &src_addr, dest_addr, ntohs(dest_port));
	
	return NF_ACCEPT;
}

static void slb_netlink_recv(struct sk_buff *skb) {
	struct nlmsghdr *nlh = NULL;
	char *slbd_msg = NULL;
	__u16 i = 0;
	char *command_name = NULL;
	char *param = NULL;
	char ** str_ref;
	UT_array *params = NULL;
	UT_array *split_msg = NULL;
	
	nlh = (struct nlmsghdr *)skb->data;
	slbd_msg = (char *) nlmsg_data(nlh);
	
	utarray_new(split_msg, &ut_str_icd);
	if (slb_str_split(slbd_msg, CHUNK_SEPARATOR_TOKEN, split_msg) != 0) {
		logger_error("Invalid message: %s", slbd_msg);
		goto clean_up;
	}
	
	str_ref = (char **) utarray_eltptr(split_msg, 0);
	if(str_ref) {
		command_name = *str_ref;	
	}
	
	utarray_new(params, &ut_str_icd);
	for (i = 1; i < utarray_len(split_msg); i++) {
		str_ref = (char **) utarray_eltptr(split_msg, i);
		if(str_ref) {
			param = strdup(*str_ref);	
		}
		
		utarray_push_back(params, &param);
	}
	
	slb_execute_command(command_name, params);	
	
	clean_up:
		utarray_free(split_msg);	
	
//	memset(slbd_msg, '\0', strlen(slbd_msg));
//	struct sk_buff *skb_out;
//	int pid;
//	char *msg = "Hello from kernel";
//	int msg_size = strlen(msg);;
//	int res;
//	pid = nlh->nlmsg_pid; // PID of the sending process
//	skb_out = nlmsg_new(msg_size, 0);
//	if (!skb_out) {
//		printk(KERN_ERR "Failed to allocate new skbn");
//		return;
//		
//	}
//	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
//	NETLINK_CB(skb_out).dst_group = 0;
//	strncpy(nlmsg_data(nlh), msg, msg_size);
//	res = nlmsg_unicast(nl_sk, skb_out, pid);
//	
//	if (res < 0)
//		printk(KERN_INFO "Error while sending bak to usern");
//	
}

// Module init
static int __init slbcore_init(void) {
	__s16 rc = 0;

	logger_info("Starting slbcore module");
	
	// slbcore conf init
	slb_conf = (struct slb_conf) {
		.slb_algorithm = ROUND_ROBIN,
		.slb_address = 0
	};
	utarray_new(clients, &slb_clients_icd);
	
	// Netlink init
	netlink_sock = netlink_kernel_create(&init_net, NETLINK_USERSOCK, 0, slb_netlink_recv, NULL, THIS_MODULE);
	if (!netlink_sock) {
		logger_error("Error creating netlink socket");
		goto clean_up_netlink;
	}
	
	// Netfilter init
	slb_pre_routing_hook_ops = (struct nf_hook_ops) {
		.hooknum = NF_INET_PRE_ROUTING,
		.pf = PF_INET,
		.hook = slb_pre_routing_hook,
		.priority = NF_IP_PRI_FIRST
	};
	if((rc = nf_register_hook(&slb_pre_routing_hook_ops)) < 0) {
		logger_error("Registering netfilter PRE failed: %d", rc);
		
		goto clean_up_pre_netlfilter;
	}
	slb_post_routing_hook_ops = (struct nf_hook_ops) {
		.hooknum = NF_INET_POST_ROUTING,
		.pf = PF_INET,
		.hook = slb_post_routing_hook,
		.priority = NF_IP_PRI_LAST
	};
	if((rc = nf_register_hook(&slb_post_routing_hook_ops)) < 0) {
		logger_error("Registering netfilter POST failed: %d", rc);
		
		goto clean_up_post_netlfilter;
	}
	
	return 0;
	
	clean_up_post_netlfilter:
		nf_unregister_hook(&slb_post_routing_hook_ops);
	clean_up_pre_netlfilter:
		nf_unregister_hook(&slb_pre_routing_hook_ops);
	clean_up_netlink:
		netlink_kernel_release(netlink_sock);
	
	utarray_free(clients);
	
	return -1000;
}

// Module exit
static void __exit slbcore_exit(void) {
	logger_info("Exiting slbcore module");
	
	slb_free_services(services, NULL);
	utarray_free(clients);
	nf_unregister_hook(&slb_pre_routing_hook_ops);
	nf_unregister_hook(&slb_post_routing_hook_ops);
	netlink_kernel_release(netlink_sock);
}

module_init(slbcore_init);
module_exit(slbcore_exit);