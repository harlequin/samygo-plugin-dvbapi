#ifndef NULL
#define NULL (void *)0
#endif



typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed int s32;


static inline u8 be8(u8 *p) {
	return *p;
}

static inline u16 be16(unsigned char *p) {
	u16 a;
	a  = p[0] << 8;
	a |= p[1];
	return a;
}

static inline u32 be32(u8 *p) {
	u32 a;
	a  = p[0] << 24;
	a |= p[1] << 16;
	a |= p[2] <<  8;
	a |= p[3] <<  0;
	return a;
}


typedef struct PMT {
	u16 sid;
	u8 *ptr;
	u32 len;
	u8 lm;
	struct PMT *next;
} pmt_t;

#if !defined(DMX_FILTER_SIZE)
#define DMX_FILTER_SIZE 16
#endif

 typedef struct dmx_filter
{
	u8  filter[DMX_FILTER_SIZE];
	u8  mask[DMX_FILTER_SIZE];
	u8  mode[DMX_FILTER_SIZE];
} dmx_filter_t;

struct dmx_sct_filter_params
{
	u16          pid;
	dmx_filter_t filter;
	u32          timeout;
	u32          flags;
#define DMX_CHECK_CRC       1
#define DMX_ONESHOT         2
#define DMX_IMMEDIATE_START 4
#define DMX_KERNEL_CLIENT   0x8000
};


#define myfunc __func__+2



#define PMT_LIST_MORE            0x00
#define PMT_LIST_FIRST           0x01
#define PMT_LIST_LAST            0x02
#define PMT_LIST_ONLY            0x03
#define PMT_LIST_ADD             0x04
#define PMT_LIST_UPDATE          0x05

#define DVBAPI_PROTOCOL_VERSION         2
#define DVBAPI_FILTER_DATA     0xFFFF0000
#define DVBAPI_CLIENT_INFO     0xFFFF0001
#define DVBAPI_SERVER_INFO     0xFFFF0002
#define DVBAPI_ECM_INFO        0xFFFF0003
#define CA_SET_DESCR_MODE      0x400c6f88
#define DMX_SET_FILTER         0x403c6f2b


#define DVBAPI_CA_SET_PID      0x40086f87
#define DVBAPI_CA_SET_DESCR    0x40106f86
#define DVBAPI_DMX_STOP        0x00006f2a
#define CA_SET_DESCR_X         0x00866f10
#define CA_SET_DESCR_AES       0x40106f87
#define CA_SET_DESCR_AES_X     0x00876f10
#define CA_SET_PID_X           0x00876f08
#define DMX_STOP_X             0x002a6f00
#define DMX_SET_FILTER_X       0x002b6f3c
#define CA_SET_DESCR_MODE      0x400c6f88


/// Descrambler key type
typedef enum
{
    /// Descrambler key type : clear
    E_DSCMB_KEY_CLEAR = 0,
    /// Descrambler key type : even
    E_DSCMB_KEY_EVEN,
    /// Descrambler key type : odd
    E_DSCMB_KEY_ODD,
} DSCMB_Key_Type;



typedef struct ca_pid {
	u32 pid;
    s32 index;              /* -1 == disable*/
} ca_pid_t;

typedef struct ca_descr {
    u32 index;
    u32 parity;    /* 0 == even, 1 == odd */
    u8 cw[8];
} ca_descr_t;

enum ca_descr_algo {
        CA_ALGO_DVBCSA,
        CA_ALGO_DES,
        CA_ALGO_AES128,
};

enum ca_descr_cipher_mode {
        CA_MODE_ECB,
        CA_MODE_CBC,
};

typedef struct ca_descr_mode {
        u32 index;
        enum ca_descr_algo algo;
        enum ca_descr_cipher_mode cipher_mode;
} ca_descr_mode_t;

//////////////////////////////////////////////////////////////////////////////
#define LIB_NAME "dvbapi"
#define LIB_VERSION "v0.0.1"
#define LIB_TV_MODELS "D (MIPS/MSTAR)"
#define INFO_VERSION "samygo-plugin-dvbapi " LIB_VERSION " / MODEL " LIB_TV_MODELS
