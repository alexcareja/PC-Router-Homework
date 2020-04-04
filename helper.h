#ifndef HELPER_H
#define HELPER_H

#include <stdint.h>

#define R_TABLE_SIZE 64285

typedef struct rt_entry{
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} rt_entry;

#endif