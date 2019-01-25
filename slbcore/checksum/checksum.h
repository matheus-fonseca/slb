/* 
 * CREDITS FOR Liu Feipeng <liuf0005@gmail.com>
 *
 * Source: http://www.roman10.net/how-to-calculate-iptcpudp-checksumpart-3-usage-example-and-validation/
 *
 */

#ifndef _SLBCORE_CHECKSUM_H
#define _SLBCORE_CHECKSUM_H

#include <linux/ip.h>

/* set ip checksum of a given ip header*/
void compute_ip_checksum(struct iphdr* iphdrp);
/*validate ip checksum, result should be 0 if IP header is correct*/
__u16 validate_ip_checksum(struct iphdr* iphdrp);
/* set tcp checksum: given IP header and TCP header, and TCP data */
void compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload);
/* set tcp checksum: given IP header and TCP header, and TCP data */
void compute_udp_checksum(struct iphdr *pIph, unsigned short *ipPayload);

#endif