
This project used for the Chinese National Algorithm SMx SM2, SM3, ...) implementation
For any question and bug report, please contact with Yanbo Li dreamfly281@gmail.com

--------------
The SM2 depend on opnessl library currently

--------------
Wlecome submit patch, for coding style, we follow Linux Kernel C coding style which can
be found from here:
http://lxr.linux.no/linux+v4.7.1/Documentation/CodingStyle


REFERENCE
--------------
The networh header file define the u8, u16 and u32 size type, also supply endian function
as below:
#include <arpa/inet.h>
uint32_t htonl(uint32_t hostlong); // Host to network
uint16_t htons(uint16_t hostshort); // Host to network
uint32_t ntohl(uint32_t netlong); // Network to host
uint16_t ntohs(uint16_t netshort); // Network to host

Network byte order is big-endian. So, these functions mean:
hton*: Host endian to big endian
ntoh*: Big endian to host endian
