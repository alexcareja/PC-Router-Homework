#include "skel.h"
#include <netinet/if_ether.h>

#define R_TABLE_SIZE 64285

typedef struct rt_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} rt_entry;

typedef struct arp_entry {
	uint32_t ip;
	uint8_t mac[6];
} arp_entry;

typedef struct list {
	packet pckt;
	struct list *next;
} list;

int parse_routing_table(rt_entry *);
void merge(rt_entry *, int , int , int );
void merge_sort(rt_entry *, int , int );
rt_entry *get_best_route(uint32_t ,rt_entry *);
uint32_t convert_to_uint32(u_char *);
u_char *convert_to_uchar(uint32_t);
void insert_in_arp_table(arp_entry *, int *, uint32_t, u_char *);
uint16_t ip_checksum(void *,size_t );
arp_entry *get_arp_entry(arp_entry *, int, uint32_t );
void insert_in_list(list **, packet);

int main(int argc, char *argv[])
{	
	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	int rc;
	rt_entry *r_table = (rt_entry *) malloc(2 * R_TABLE_SIZE * sizeof(r_table));
	parse_routing_table(r_table);
	arp_entry *arp_table = (arp_entry *) malloc(4 * sizeof(arp_entry));
	int arp_table_size = 0;
	list *q = NULL;
	init();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct in_addr my_addr;
		inet_aton(get_interface_ip(m.interface), &my_addr);
		u_char *my_ip = convert_to_uchar(my_addr.s_addr);
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) { // Addr resolution protocol
			struct ether_arp *eth_arp = (struct ether_arp *) (m.payload + sizeof(struct ether_header));
			struct arphdr *arp_hdr = (struct arphdr *) &(eth_arp->ea_hdr);
			struct in_addr my_addr;
			struct in_addr target_addr;
			// printf("AJUGN IN PRIMUL IF\n");
			if (ntohs(arp_hdr->ar_op) == ARPOP_REQUEST) { // ARP Request
				inet_aton(get_interface_ip(m.interface), &my_addr);
				target_addr.s_addr = convert_to_uint32(eth_arp->arp_tpa);
				if (my_addr.s_addr == target_addr.s_addr) { // ARP Request is targeted to me
					// TODO Send ARP Reply with the coresponding MAC address
					// Change ether_arp
					memcpy(eth_arp->arp_tha, eth_arp->arp_sha, 6 * sizeof(u_char)); // mac source address -> mac destination address
					memcpy(eth_arp->arp_tpa, eth_arp->arp_spa, 4 * sizeof(u_char));	// ip source address -> ip destination address
					memcpy(eth_arp->arp_spa, my_ip, 4 * sizeof(u_char)); // my ip address
					get_interface_mac(m.interface, eth_arp->arp_sha); // my mac address
					// Change ARP Operation value to the ARP Reply value
					arp_hdr->ar_op = htons(ARPOP_REPLY);
					// Change ether_header
					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6 * sizeof(u_char));
					get_interface_mac(m.interface, eth_hdr->ether_shost);
					// Send the packet
					send_packet(m.interface, &m);
				}
				else { // ARP Request is not targeted to me
					continue; // Drop the packet
				}
			}
			if (arp_hdr->ar_op == ARPOP_REPLY) { // ARP Reply
				// Update ARP Table
				insert_in_arp_table(arp_table, &arp_table_size, convert_to_uint32(eth_arp->arp_spa), eth_arp->arp_sha);
				// TODO Send packets from queue which were waiting for this mac address
			}
		}
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) { // IP protocol
			struct iphdr *ip_hdr = (struct iphdr *) (m.payload + sizeof(struct ether_header));
			// Check the checksum
			if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) {
				perror("Checksum error\n");
			}
			// Check TTL >= 1
			if (ip_hdr->ttl < 1) {
				perror("TTL error\n");
			}
			rt_entry *next = get_best_route(ip_hdr->daddr, r_table); 
			if (next == NULL) {
				perror("Best route not found\n");
			}
			// Update TTL and recalculate the checksum */
			ip_hdr->ttl = ip_hdr->ttl - 1;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
			// Find the arp entry of the best route
			struct arp_entry *dest_arp = get_arp_entry(arp_table, arp_table_size, ip_hdr->daddr);
			if (dest_arp == NULL) {
				// TO DO enqueue and send arp request
				insert_in_list(&q, m);
				struct arphdr *req_arp_hdr = (struct arphdr *) malloc( sizeof(struct arphdr));
				req_arp_hdr->ar_op = htons(ARPOP_REQUEST);
				req_arp_hdr->ar_hrd = htons(ARPHRD_ETHER);
				req_arp_hdr->ar_pro = htons(0x0800);
				req_arp_hdr->ar_hln = (uint8_t) 6;
				req_arp_hdr->ar_pln = (uint8_t) 4;
				struct ether_arp *req_eth_arp = (struct ether_arp *) malloc( sizeof(struct ether_arp));
				req_eth_arp->ea_hdr = *req_arp_hdr;
				get_interface_mac(m.interface, req_eth_arp->arp_sha); // my mac address
				memcpy(req_eth_arp->arp_spa, my_ip, 4 * sizeof(u_char)); // my ip address
				if (hwaddr_aton("ff:ff:ff:ff:ff:ff", req_eth_arp->arp_tha) == -1) { // set target mac to ff:ff:ff:ff:ff:ff
					perror("Hwaddr error\n");
				}
				memcpy(req_eth_arp->arp_tpa, convert_to_uchar(ip_hdr->daddr), 4 * sizeof(u_char)); // target ip addr
				struct ether_header *req_eth_hdr = (struct ether_header *) malloc(sizeof(struct ether_header));
				if (hwaddr_aton("ff:ff:ff:ff:ff:ff", req_eth_hdr->ether_dhost) == -1) { // set destination mac to ff:ff:ff:ff:ff:ff
					perror("Hwaddr error\n");
				}
				get_interface_mac(m.interface, req_eth_hdr->ether_shost); // my mac address
				req_eth_hdr->ether_type = htons(ETHERTYPE_ARP); // specify type of ether communication (ARP)
				packet arp_request;
				memcpy(&(arp_request.payload), req_eth_hdr, sizeof(struct ether_header));
				memcpy(arp_request.payload + sizeof(struct ether_header), req_eth_arp, sizeof(struct ether_arp));
				arp_request.len = sizeof(struct ether_header) + sizeof(struct ether_arp);
				arp_request.interface = next->interface;
				send_packet(next->interface, &arp_request);
			}
			else {
				memcpy(eth_hdr->ether_dhost, dest_arp->mac, 6 * sizeof(u_char));
				// Forward the packet to best_route->interface
				send_packet(next->interface, &m);
			}
		}
	}
	return 0;
}

int parse_routing_table(rt_entry *r_table) {
	FILE *f;
	char *buffer;
	size_t len = 0;
	ssize_t read;
	char *token;
	int i = 0;
	struct in_addr aux;

	f = fopen("rtable.txt", "r");
	if (f == NULL) {
		return -1;
	}

	while ((read  = getline(&buffer, &len, f)) != -1) { //read the input file line by line
		token = strtok(buffer, " ");	// prefix
		inet_aton(token, &aux);
		r_table[i].prefix = aux.s_addr;
		token = strtok(NULL, " ");	// next hop
		inet_aton(token, &aux);
		r_table[i].next_hop = aux.s_addr;
		token = strtok(NULL, " ");	// mask
		inet_aton(token, &aux);
		r_table[i].mask = aux.s_addr;
		token = strtok(NULL, " ");	// interface
		r_table[i].interface = atoi(token);
		i++;
		token = NULL;
	}
	merge_sort(r_table, 0, i - 1);

	fclose(f);
	return 0;
}

void merge(rt_entry *v, int i, int m, int j) {
	int iinit = i;
	rt_entry *u = (rt_entry *) calloc(j - i + 1, sizeof(rt_entry));
	int l = 0;
	int k = m + 1;
	while (i <= m && k <= j) {
		if (v[i].prefix == v[k].prefix) {
			if (v[i].mask < v[k].mask) {
				u[l++] = v[i++];
			}
			else {
				u[l++] = v[k++];
			}
		}
		else {
			if (v[i].prefix < v[k].prefix) {
				u[l++] = v[i++];
			}
			else {
				u[l++] = v[k++];
			}
		}
	}
	while (i <= m) {
		u[l++] = v[i++];
	}
	while (k <= j) {
		u[l++] = v[k++];
	}
	l = 0;
	while (iinit <= j) {
		v[iinit++] = u[l++];
	}
	free(u);
}

void merge_sort(rt_entry *v, int i, int j) {
	if (i < j) {
		int m = (i + j) / 2;
		merge_sort(v, i, m);
		merge_sort(v, m + 1, j);
		merge(v, i, m, j);
	}
}

rt_entry *get_best_route(uint32_t dest_ip, rt_entry *r_table) {
	int l, m, r;
	rt_entry *x = NULL;
	l = 0;
	r = R_TABLE_SIZE - 1;
	while (l <= r) {
		m = l + (r - l) / 2;
		if ((r_table[m].mask & dest_ip) == r_table[m].prefix) {
			x = & r_table[m];
			l = m;	// search in the right side of this entry (bigger prefixes)
			continue;
		}
		if ((r_table[m].mask & dest_ip) < r_table[m].prefix) {
			r = m;	// search in the left side of this entry (bigger prefixes)
		}
		else {
			l = m;	// search in the right side of this entry (smaller prefixes)
		}
	}
	return x;
}

uint32_t convert_to_uint32(u_char *initial) {
	uint32_t final = 0;
	int i = 0;
	for (; i < 4; i++){
		final = final << 8;
		final += initial[3 - i];
	}
	return final;
}

u_char *convert_to_uchar(uint32_t initial) {
	u_char *final = (u_char *) malloc(4 * sizeof(u_char));
	final[3] = (initial >> 24) & 0xFF;
	final[2] = (initial >> 16) & 0xFF;
	final[1] = (initial >> 8) & 0xFF;
	final[0] = initial & 0xFF;
	return final;
}

void insert_in_arp_table(arp_entry *table, int *size, uint32_t ip, u_char *mac) {
	int i;
	for (i = 0; i < *size; i++) {
		if (table[i].ip == ip) { // ip is already in my arp table
			return;
		}
	}
	table[*size].ip = ip;
	memcpy(&(table[*size].mac), mac, 6 * sizeof(u_char));
	*size = *size + 1;
}

uint16_t ip_checksum(void* vdata,size_t length) {
	// Cast the data pointer to one that can be indexed.
	char* data=(char*)vdata;

	// Initialise the accumulator.
	uint64_t acc=0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	// Handle any complete 32-bit blocks.
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	// Handle any partial block at the end of the data.
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	// Handle deferred carries.
	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}

arp_entry *get_arp_entry(arp_entry *arp_table, int size, uint32_t daddr) {
	int i;
	for (i = 0; i < size; i++) {
		if (arp_table[i].ip == daddr) {
			return &arp_table[i];
		}
	}
	return NULL;
}


void insert_in_list(list **q, packet p) {
	list *new_node = (list *) malloc(sizeof(list));
	memcpy(&(new_node->pckt), &p, sizeof(packet));
	new_node->next = NULL;
	if (*q == NULL) {
		*q = new_node;
		return;
	}
	list *aux = *q;
	while(aux->next != NULL) {
		aux = aux->next;
	}
	aux->next = new_node;
}