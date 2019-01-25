#ifndef _slbcore_UTIL_H
#define _slbcore_UTIL_H

#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/inetdevice.h> 
#include <linux/netdevice.h> 
#include <asm/types.h>
#include <linux/time.h>

#include "uthash/utarray.h"
#include "uthash/uthash.h"
#include "uthash/utlist.h"

#define logger_info(format, args...) \
	printk(KERN_INFO "%s.%s() = " format "\n", module_name(THIS_MODULE), __FUNCTION__, ##args);

#define logger_error(format, args...) \
	printk(KERN_ERR "%s.%s() = " format "\n", module_name(THIS_MODULE), __FUNCTION__, ##args);

#define logger_warn(format, args...) \
	printk(KERN_WARNING "%s.%s() = " format "\n", module_name(THIS_MODULE), __FUNCTION__, ##args);
	

#define HASH_ADD_INT16(head, int16field, add) \
	HASH_ADD(hh, head, int16field, sizeof(__be16), add);

#define HASH_FIND_INT16(head, findint16, out) \
	HASH_FIND(hh, head, findint16, sizeof(__be16), out)

// STRUCTURES DEFINITIONS

typedef enum algorithm {
	NONE, ROUND_ROBIN, LOWER_LATENCY, LEAST_CONNECTIONS
} algorithm;

struct slb_conf {
	__be32 slb_address;
	algorithm slb_algorithm;
};

struct slb_client;

typedef struct slb_server {
	__be32 addr;
	UT_array *clients;
	struct slb_server *prev, *next;
} slb_server;

typedef struct slb_client {
	__be32 addr;
	slb_server *server;
	unsigned long long sec_last_conn;
} slb_client;

typedef struct slb_service {
	__be16 port; // key
	slb_server *servers;
	slb_server *actual_server;
	UT_hash_handle hh;
} slb_service;


// HELPER DEFINITIONS

static inline int slb_client_cmp(const void *a, const void *b) {
	slb_client *_a = *((slb_client **) a);
	slb_client *_b = *((slb_client **) b);
	
	return _a->addr - _b->addr;
}

static inline int slb_server_cmp(const void *a, const void *b) {
	slb_server *_a = *((slb_server **) a);
	slb_server *_b = *((slb_server **) b);

	return _a->addr - _b->addr;
}


static inline void slb_client_dtor(void *elt) {
	slb_client **_elt = (slb_client **)elt;
	if (*_elt)
		kfree(*_elt);
}

static const UT_icd slb_clients_icd = {
	sizeof(slb_client*), 
	NULL, 
	NULL, 
	slb_client_dtor
};

static const UT_icd slb_server_clients_icd = {
	sizeof(slb_client*), 
	NULL, 
	NULL, 
	NULL
};

static const UT_icd slb_server_icd = {
	sizeof(slb_server*), 
	NULL, 
	NULL, 
	NULL
};

// FUNCTION DEFINITIONS

__s16 slb_str_split(char *str, const char occur, UT_array* split_msg);

slb_server* slb_service_add_server(slb_service *service, __be32 addr);

slb_client* slb_add_client(UT_array *clients, __be32 addr, slb_server *server);

void slb_service_rm_server(slb_service *service, __be32 addr, UT_array *clients);

__u16 slb_server_active_conn_count(slb_server *server);

slb_client* slb_check_client_persistence(UT_array *clients, __be32 addr);

slb_service* slb_service_new(__be16 port);

void slb_free_services(slb_service *services, UT_array *clients);

__be32 slb_ip_from_device(const struct net_device *device);

#endif