#include<stdint.h>
#include<sys/socket.h>
#include<sys/un.h>
#include<stdarg.h>

#define DVBAPI_PROTOCOL_VERSION         2

#define DVBAPI_FILTER_DATA     0xFFFF0000
#define DVBAPI_CLIENT_INFO     0xFFFF0001
#define DVBAPI_SERVER_INFO     0xFFFF0002
#define DVBAPI_ECM_INFO        0xFFFF0003

#define LIST_MORE            0x00
#define LIST_FIRST           0x01
#define LIST_LAST            0x02
#define LIST_ONLY            0x03
#define LIST_ADD             0x04
#define LIST_UPDATE          0x05

#define CA_SET_DESCR    0x40106f86
#define DMX_SET_FILTER  0x403c6f2b
#define CA_SET_PID      0x40086f87
#define DMX_STOP        0x00006f2a

#define DMX_FILTER_SIZE 16

#define INFO_VERSION LIB_NAME "_" LIB_VERSION
#define __u8 unsigned char

typedef struct dmx_filter
{
	__u8  filter[DMX_FILTER_SIZE];
	__u8  mask[DMX_FILTER_SIZE];
	__u8  mode[DMX_FILTER_SIZE];
} dmx_filter_t;

typedef struct dmx_sct_filter_params
{
	uint16_t          	pid;
	dmx_filter_t   		filter;
	uint32_t          	timeout;
	uint32_t          	flags;
#define DMX_CHECK_CRC       1
#define DMX_ONESHOT         2
#define DMX_IMMEDIATE_START 4
#define DMX_KERNEL_CLIENT   0x8000
} dmx_sct_filter_params_t;

typedef struct ca_descr {
	unsigned int index;
	unsigned int parity;
	unsigned char cw[8];
} ca_descr_t;

typedef struct ca_pid {
    unsigned int pid;
    int index;              /* -1 == disable*/
 } ca_pid_t;
 
int g_socket = -1;

int capmt_connection_handler(int);
void *start_capmt_server();
void send_client_info();
void send_filter_data(unsigned char *data, int len);
int recv_server_info();
void send_pmt(unsigned char* buf);
