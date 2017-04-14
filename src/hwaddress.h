#ifndef __hwaddress_h__

#define __hwaddress_h__

#include <string.h>
#include <stdlib.h>

NDPPD_NS_BEGIN

class hwaddress {
public:
	hwaddress() { memset(addr, 0, sizeof(addr)); }

	uint8_t addr[6];
};

NDPPD_NS_END

#endif
