/*
 *  bugficks
 *	(c) 2013
 *
 *  sectroyer
 *	(c) 2014
 *
 *  MrB
 *	(c) 2015
 *
 *  License: GPLv3
 *
 */
//////////////////////////////////////////////////////////////////////////////

#define DMX_PVR_PLAYBACK 0x19800622

//#define LIB_NAME "libOscamD_T-MST"
#define LIB_VERSION "build " SVN_REV
#define LIB_TV_MODELS "D T-MST NEW"
#define LIB_HOOKS libOscamD_hooks
#define hCTX libOscamD_hook_ctx

//////////////////////////////////////////////////////////////////////////////

#include <netinet/in.h>
#include "utlist.h"
#include "../common_D/common.h"
#include "../common_D/hook.h"
#include "../common_D/util.h"
#include "../common_D/capmt.h"

//////////////////////////////////////////////////////////////////////////////
#define MAX_FILTER_SIZE		16

typedef struct
{
	unsigned char filter[MAX_FILTER_SIZE];
	unsigned char mask[MAX_FILTER_SIZE];
	unsigned char mode[MAX_FILTER_SIZE];
} t_monParamsData;

/**
* Old struct from D MST series
*/
typedef struct
{
    /* 0*/ unsigned int pid;
    /* 4*/ unsigned int eDataType; /*0*/		// 0, 1, 2
    /* 8*/ unsigned int unknown1; /*filter type 1?*/		// 0 play around
    /*12*/ unsigned int tableId;
	/*16*/ unsigned int _bVersion;		// 0; looks more like len 16
	/*20*/ unsigned char mask[MAX_FILTER_SIZE];		// 0 -- filter
} t_dmxParams;
t_dmxParams g_dmxParams;

typedef struct
{
    /* 0 */ int pid;
    /* 4 */ unsigned int data_type;		// 0, 1, 2
    /* 8 */ unsigned int bCRC_check;	// 0
    /* 12 */ unsigned int filter_type; 	// 0: table, 1: mask
    /* 16 */ unsigned char* filter_data;
	/* 20 */ unsigned int filter_data_len;	// max 16
	/* 84 */ unsigned char* filter_mask;
	/*148 */unsigned char* filter_mode;	// 0: normal, 1:invert
} t_monParams;

typedef struct
{
	int hmon;
	t_monParams monParams;
	t_monParamsData monParamsData;
} t_filter;

#define MAX_DEMUX_FILTERS	32
typedef struct
{
	unsigned int dmxHandle;
	int serviceId;
	t_filter filter[MAX_DEMUX_FILTERS];
} t_demux;

#define MAX_PMT		64
#define PMT_SIZE	1024
unsigned char* g_PMT[MAX_PMT];
int g_PMT_indices[MAX_PMT] = {0};
int g_PMT_head = 0;

#define MAX_DEMUX	2
t_demux	g_demux[MAX_DEMUX];
char g_send_PMT = 0;

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

typedef union
{
	const void *procs[32];
	struct
	{
		// libSDAL.so
		int (*SdTSData_StartMonitor)(unsigned int dmxHandle, void* dmxParams, unsigned int eDataType);
		int (*SdTSData_StopMonitor)(unsigned int dmxHandle, unsigned int monHandle);

		// libUTOPIA.so
		int (*MDrv_DSCMB_Init)();
		int (*MDrv_DSCMB_FltAlloc)();	// u32DscmbID = 0
		int (*MDrv_DSCMB_FltFree)(unsigned int filterId);
		int (*MDrv_DSCMB_FltConnectFltId)(unsigned int filterId, unsigned int fltId);
		int (*MDrv_DSCMB_FltConnectPid)(unsigned int filterId, unsigned int pid);
		int (*MDrv_DSCMB_FltDisconnectPid)(unsigned int filterId, unsigned int pid);
		int (*MDrv_DSCMB_FltTypeSet)(unsigned int filterId, unsigned int type); // type = 0
		int (*MDrv_DSCMB_FltKeySet)(unsigned int filterId, unsigned int parity, unsigned char* cw);  // parity: even = 1, odd = 2
		int (*msAPI_DMX_Init)();

		// exeDSP
		void** g_pAppWindow;
		const int (*TCWindow_GetSource)(void *window, int *source, int a2);
		const int (*TCWindow_GetTVChannel)(void *window, void *channel, int arg3);
		const int (*TCWindow_SetChannelQuiet)(void *window, void *channel, int arg3);
		const int (*TCChannel_Create)(void *channel);
		const int (*TCChannel_Destroy)(void *channel);
		const int (*TCChannel_ProgramNumber)(void* channel);
		const int (*TCChannel_SizeOfDescriptor)(void *channel);
		const int (*TCChannel_Descriptor)(void *channel, int nine, int desc);
		const int (*TCChannel_FlagScrambled)(void *channel);
		
		const int (*StartSIMaskFiltering)(int *this, int * a1, int a2, unsigned char * a3, unsigned char * a4, unsigned char * a5, unsigned int a6, int a7, int ba8, unsigned int a9);
	};
} samyGO_whacky_t;

samyGO_whacky_t hCTX =
{{
	(const void*)"_Z21SdTSData_StartMonitorjP19SdTSData_Settings_tj",
	(const void*)"_Z20SdTSData_StopMonitorjj",

	(const void*)"MDrv_DSCMB_Init",
	(const void*)"MDrv_DSCMB_FltAlloc",
	(const void*)"MDrv_DSCMB_FltFree",
	(const void*)"MDrv_DSCMB_FltConnectFltId",
	(const void*)"MDrv_DSCMB_FltConnectPid",
	(const void*)"MDrv_DSCMB_FltDisconnectPid",
	(const void*)"MDrv_DSCMB_FltTypeSet",
	(const void*)"MDrv_DSCMB_FltKeySet",
	(const void*)"msAPI_DMX_Init",

	(const void*)"g_pAppWindow",
	(const void*)"_ZN8TCWindow9GetSourceEPii",
	(const void*)"_ZN8TCWindow12GetTVChannelEP9TCChanneli",
	(const void*)"_ZN8TCWindow15SetChannelQuietEPK9TCChannelb",
	(const void*)"_ZN9TCChannelC2Ev",
	(const void*)"_ZN9TCChannelD2Ev",
	(const void*)"_ZNK9TCChannel13ProgramNumberEv",
	(const void*)"_ZNK9TCChannel16SizeOfDescriptorEv",
	(const void*)"_ZNK9TCChannel10DescriptorEii",
	(const void*)"_ZNK9TCChannel13FlagScrambledEv",
	
	(const void*)"_ZN13TDsPrimeDemux20StartSIMaskFilteringEPiiPhS1_S1_jibj",
}};

//////////////////////////////////////////////////////////////////////////////

STATIC int samyGO_whacky_t_init(
        void *h, samyGO_whacky_t *ctx, uint32_t cnt)
{
    for(int i = 0; i < cnt ; i++)
    {
        if(!ctx->procs[i])
            continue;

        void *fn = dlsym(h, ctx->procs[i]);
        if(!fn)
            log("dlsym '%s' failed.\n", ctx->procs[i]);
		else
        	log("%s [%p].\n",  ctx->procs[i], fn);
        ctx->procs[i] = fn;
    }
    return 0;
}

void init_demux(t_demux* dmx)
{
	dmx->dmxHandle = 0;
	dmx->serviceId = -1;

	for( int i = 0; i < MAX_DEMUX_FILTERS; i++ )
	{
		memset(dmx->filter[i].monParamsData.filter, 0, MAX_FILTER_SIZE);
		memset(dmx->filter[i].monParamsData.mask, 0xff, MAX_FILTER_SIZE);
		memset(dmx->filter[i].monParamsData.mode, 0, MAX_FILTER_SIZE);

		dmx->filter[i].hmon = -1;
		dmx->filter[i].monParams.pid = -1;
		dmx->filter[i].monParams.data_type = 0;
		dmx->filter[i].monParams.bCRC_check = 0;
		dmx->filter[i].monParams.filter_type = 1;
		dmx->filter[i].monParams.filter_data_len = MAX_FILTER_SIZE;
		dmx->filter[i].monParams.filter_data = dmx->filter[i].monParamsData.filter;
		dmx->filter[i].monParams.filter_mask = dmx->filter[i].monParamsData.mask;
		dmx->filter[i].monParams.filter_mode = dmx->filter[i].monParamsData.mode;
	}
}

int get_demux_index( unsigned int dmxHandle )
{
	return dmxHandle == 0x19800620 ? 0 : dmxHandle == 0x19800621 ? 1 : 2;
}

//////////////////////////////////////////////////////////////////////////////

int g_PMT_indices_get_index_of( int sid )
{
	for( int i = 0; i < MAX_PMT; i++ )
		if(g_PMT_indices[i] == sid)
			return i;

	return -1;
}

int g_PMT_set( int index, unsigned char* buf, int len )
{
	if(index == -1)		// insert
	{
		index = g_PMT_head;
		g_PMT_head = (g_PMT_head + 1) % MAX_PMT;
	}

	memset(g_PMT[index], 0, sizeof(unsigned char) * PMT_SIZE);
	memcpy(g_PMT[index], buf, len);

	return index;
}

void resetCurrentChannel()
{
	int source = 0;

	hCTX.TCWindow_GetSource(*hCTX.g_pAppWindow, &source, 1);
	if(source == 0)
	{
		unsigned char channel[32] = {0};

		hCTX.TCChannel_Create(channel);
		hCTX.TCWindow_GetTVChannel(*hCTX.g_pAppWindow, channel, 1);

		for(int i = 0; i < hCTX.TCChannel_SizeOfDescriptor(channel); i++)
			if(hCTX.TCChannel_Descriptor(channel, 9, i))
			{
				hCTX.TCWindow_SetChannelQuiet(*hCTX.g_pAppWindow, channel, 1);
				break;
			}
		//if(hCTX.TCChannel_FlagScrambled(channel))
			//hCTX.TCWindow_SetChannelQuiet(*hCTX.g_pAppWindow, channel, 1);
		hCTX.TCChannel_Destroy(channel);
	}
}

int match( t_filter* filter, uint8_t* data, uint32_t len ) {
	int i, k, match;
	uint8_t flt, mask;
	match = 1;
	
	for( i = 0, k = 0; i < 16 && match; i++, k++) {
		mask = filter->monParamsData.mask[i];
		if ( k == 1) {
			k+=2;
		}
		if (!mask) {
			continue;
		}
		flt = filter->monParamsData.filter[i] & mask;
		if ( k <= len ) {
			match = ( flt == (data[k] & mask));
		}else{
			match = 0;
		}
	}
	return (match && i == 16); // 0 = delivered data does not match with filter, 1 = delivered data matches with filter	
}

int match_filter( t_filter* filter, uint16_t pid, uint8_t* data, uint32_t len )
{
	if( pid != filter->monParams.pid )
		return 0;

	for( int i = 0; i < len; i++ )
		if( (filter->monParamsData.filter[i] & filter->monParamsData.mask[i]) != (data[i] & filter->monParamsData.mask[i]) )
			return 0;

	return 1;
}


//////////////////////////////////////////////////////////////////////////////
_HOOK_IMPL(int, TCCIMManagerBase_HostChannelChangeCompleted, void* this, void* TCChannel, int a2, int ESource)
{
	log("TCCIMManagerBase_HostChannelChangeCompleted, this=0x%08X, TCChannel=0x%08X, a2=0x%08X, ESource=0x%08X\n", this, TCChannel, a2, ESource);

	_HOOK_DISPATCH(TCCIMManagerBase_HostChannelChangeCompleted, this, TCChannel, a2, ESource);

	if(TCChannel == 0) return (int)h_ret;
	int sourceid = ESource;

	log("Source id=%d\n", sourceid);

	if(sourceid == 53 || sourceid == 78)
	{
		int sId = hCTX.TCChannel_ProgramNumber(TCChannel);
		log("Service changed, new sId=0x%04X\n", sId);

		int dmxIndex = sourceid == 53 ? 0 : sourceid == 78 ? 1 : 2;

		for(int i = 0; i < MAX_DEMUX; i++)
			init_demux(&g_demux[i]);
		
		g_demux[dmxIndex].serviceId = sId;
		g_send_PMT = 1;
	}
	/*
	int dmxIndex = 0;

	if(ESource != 0x55) {
		int sId = hCTX.TCChannel_ProgramNumber(TCChannel);
		g_send_PMT = 1;
		log("Service changed, new sId=0x%04X\n", sId);
		g_demux[dmxIndex].serviceId = sId;
	}
	*/
	return (int)h_ret;
}

_HOOK_IMPL(int,DemuxBase_m_Demux_SICallback, unsigned int* SICallBackSettings_t)
{
	_HOOK_DISPATCH(DemuxBase_m_Demux_SICallback, SICallBackSettings_t);

	if(g_socket < 0) return (int)h_ret;

	unsigned int hmon = SICallBackSettings_t[0];
	unsigned int pid = SICallBackSettings_t[1];
	unsigned char* buf = (unsigned char*)SICallBackSettings_t[2];
	unsigned int len = SICallBackSettings_t[3];

	if(len > 0 && len <= 1024)
	{
		if(buf[0] == 0x02)	// got PMT
		{
			int sId = (buf[3] << 8) + buf[4];
			int pmt_index = g_PMT_indices_get_index_of(sId);

			if(pmt_index == -1 || memcmp(g_PMT[pmt_index], buf, len) != 0)	// got PMT
			{
				pmt_index = g_PMT_set(pmt_index, buf, len);		// pmt_index is updated with new index of buf
				g_PMT_indices[pmt_index] = sId;
				//log("Got PMT for sId=0x%04X, pmt_index=%d\n", sId, pmt_index);
			}
		}
		
		for(int i = 0; i < MAX_DEMUX; i++)
			for(int j = 0; j < MAX_DEMUX_FILTERS; j++)
				if( hmon == g_demux[i].filter[j].hmon )
				{				
					if ( match( &g_demux[i].filter[j], buf, len < MAX_FILTER_SIZE ? len : MAX_FILTER_SIZE ) ) {
						log("Got filter data, hmon=0x%08X, idx=0x%02X, flt=0x%02X, pid=0x%04X\n", hmon, i, j, pid);
						send_filter_data(i, j, buf, len);
					}
					break;
				}
	}
	
	if(g_send_PMT)
	{
		char lm;
		for(int i = 0; i < MAX_DEMUX; i++)
		{
			int pmt_index = g_PMT_indices_get_index_of(g_demux[i].serviceId);
			if( pmt_index > -1 )
			{
				lm = i == MAX_DEMUX - 1 ? LIST_LAST : i > 0 ? LIST_MORE : LIST_ONLY;
				send_pmt(lm, g_PMT[pmt_index], i);
				log("PMT sent, dmx=%d, sId=0x%04X, lm=0x%02X\n", i, g_demux[i].serviceId, lm);
			}
		}
		g_send_PMT = 0;
	}
	return (int)h_ret;
}

_HOOK_IMPL(int,SdDemux_Start, unsigned int dmxHandle, int eDemuxOut)
{
	log("SdDemux_Start, dmxHandle=0x%08X\n", dmxHandle);

	_HOOK_DISPATCH(SdDemux_Start, dmxHandle, eDemuxOut);

	int dmxIndex = get_demux_index(dmxHandle);
	g_demux[dmxIndex].dmxHandle = dmxHandle;

	return (int)h_ret;
}

_HOOK_IMPL(int,SdDemux_Stop, unsigned int dmxHandle, int eDemuxOut)
{
	log("SdDemux_Stop, dmxHandle=0x%08X\n", dmxHandle);

	int dmxIndex = get_demux_index(dmxHandle);

	g_demux[dmxIndex].dmxHandle = 0;
	g_demux[dmxIndex].serviceId = -1;

	send_stop_dmx(dmxIndex);

	_HOOK_DISPATCH(SdDemux_Stop, dmxHandle, eDemuxOut);

	return (int)h_ret;
}

_HOOK_IMPL(int, TCCIMManagerBase_SetAVPID, void* this, int pidVideo, int pidAudio, int EWindow)
{
	void *ra;
    asm("move %0, $ra\n" : "=r" (ra));

	log("TCCIMManagerBase_SetAVPID, ra=0x%08X, pidVideo=0x%04X, pidAudio=0x%04X, EWindow=0x%04X\n", ra, pidVideo, pidAudio, EWindow);

	_HOOK_DISPATCH(TCCIMManagerBase_SetAVPID, this, pidVideo, pidAudio, EWindow);

	log("TCCIMManagerBase_SetAVPID, dispatched\n");

	log("MDrv_DSCMB_FltDisconnectPid=%d\n", hCTX.MDrv_DSCMB_FltDisconnectPid(0, pidAudio));
	log("MDrv_DSCMB_FltDisconnectPid=%d\n", hCTX.MDrv_DSCMB_FltDisconnectPid(0, pidVideo));
	log("MDrv_DSCMB_FltFree=0x%08X\n", hCTX.MDrv_DSCMB_FltFree(0));


	hCTX.MDrv_DSCMB_FltAlloc();
	log("MDrv_DSCMB_FltAlloc=0x%08X\n", 0);

	log("MDrv_DSCMB_FltConnectPid=%d\n", hCTX.MDrv_DSCMB_FltConnectPid(0, pidAudio));
	log("MDrv_DSCMB_FltConnectPid=%d\n", hCTX.MDrv_DSCMB_FltConnectPid(0, pidVideo));
	log("MDrv_DSCMB_FltTypeSet=%d\n", hCTX.MDrv_DSCMB_FltTypeSet(0, 0));

	return (int)h_ret;
}

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

STATIC dyn_fn_t dyn_hook_fn_tab[] =
{
    { 0, "_ZN13TDsPrimeDemux15t_DemuxCallbackEPN8CDiDemux20SICallBackSettings_tE" },
    { 0, "_ZN16TCCIMManagerBase26HostChannelChangeCompletedEP9TCChanneliN8TCWindow7ESourceE" },
	{ 0, "_Z18SdAVDec_DemuxStartj18SdAVDec_DemuxOut_k" },
	{ 0, "_Z17SdAVDec_DemuxStopj18SdAVDec_DemuxOut_k" },
	{ 0, "_ZN16TCCIMManagerBase8SetAVPIDEiii" },	
};

STATIC hook_entry_t LIB_HOOKS[] =
{
#define _HOOK_ENTRY(F, I) \
    &hook_##F, &dyn_hook_fn_tab[I], &x_##F

    { _HOOK_ENTRY(DemuxBase_m_Demux_SICallback, __COUNTER__) },
    { _HOOK_ENTRY(TCCIMManagerBase_HostChannelChangeCompleted, __COUNTER__) },
	{ _HOOK_ENTRY(SdDemux_Start, __COUNTER__) },
	{ _HOOK_ENTRY(SdDemux_Stop, __COUNTER__) },
	{ _HOOK_ENTRY(TCCIMManagerBase_SetAVPID, __COUNTER__) },
#undef _HOOK_ENTRY
};

//////////////////////////////////////////////////////////////////////////////
static int _hooked = 0;

EXTERN_C void lib_init(
        void *_h, const char *libpath)
{
	//unsigned long *cur_addr;
    if(_hooked)
    {
        log("Injecting once is enough!\n");
        return;
    }

	unlink(LOG_FILE);

	log("SamyGO "LIB_TV_MODELS" "LIB_NAME" "LIB_VERSION" - (c) MrB 2016\n");

	for(int i = 0; i < MAX_DEMUX; i++)
		init_demux(&g_demux[i]);

	for(int i = 0; i < MAX_PMT; i++)
	{
		g_PMT[i] = malloc(sizeof(unsigned char) * PMT_SIZE);
		memset(g_PMT[i], 0, sizeof(unsigned char) * PMT_SIZE);
	}

    void *h = dlopen(0, RTLD_LAZY);
    if(!h)
    {
        char *serr = dlerror();
        log("dlopen error %s\n", serr);
        return;
    }

    patch_adbg_CheckSystem(h);

	samyGO_whacky_t_init(h, &hCTX, ARRAYSIZE(hCTX.procs));

    if(dyn_sym_tab_init(h, dyn_hook_fn_tab, ARRAYSIZE(dyn_hook_fn_tab)) >= 0)
    {
        set_hooks(LIB_HOOKS, ARRAYSIZE(LIB_HOOKS));
        _hooked = 1;
    }

	log("init done...\n");

    dlclose(h);

	pthread_t tid;
	int err = pthread_create(&tid, NULL, &start_capmt_server, NULL);
	if (err != 0)
		log("can't create thread :[%s]\n", strerror(err));
}

EXTERN_C void lib_deinit(
        void *_h)
{
    log(">>> %s\n", __func__);

    log("If you see this message you forget to specify -r when invoking hijack :)\n");

    if(_hooked)
        remove_hooks(LIB_HOOKS, ARRAYSIZE(LIB_HOOKS));

    log("<<< %s\n", __func__);
}

//////////////////////////////////////////////////////////////////////////////

void *start_capmt_server()
{
	const char* socket_name = "/tmp/.listen.camd.socket";
	int socket_desc, client_sock , c;
	struct sockaddr_un server, client;
	int *retval = malloc(sizeof(int));
    *retval = 0;

	unlink(socket_name);

    //Create socket
    socket_desc = socket(AF_UNIX , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
		log("Could not create socket: %s\n", socket_name);
		return retval;
    }

    //Prepare the sockaddr_un structure
	server.sun_family = AF_UNIX;
    strcpy(server.sun_path, socket_name);

    //Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(struct sockaddr_un)) < 0)
    {
        //print the error message
		log("Socket bind failed: %s\n", socket_name);
        return retval;
    }

    //Listen
    listen(socket_desc , 3);

    //Accept and incoming connection
	log("Waiting for incoming connections...\n");
    c = sizeof(struct sockaddr_un);

    while( (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
    {
        log("Client connected\n");
		capmt_connection_handler(client_sock);
    }

    if (client_sock < 0)
    {
		log("Accept failed\n");
        return retval;
    }
	
	return 0;
}

void send_client_info()
{
  int len = sizeof(INFO_VERSION) - 1;                     //ignoring null termination
  unsigned char buff[7 + len];

  uint32_t req = htonl(DVBAPI_CLIENT_INFO);               //type of request
  memcpy(&buff[0], &req, 4);
  int16_t proto_version = htons(DVBAPI_PROTOCOL_VERSION); //supported protocol version
  memcpy(&buff[4], &proto_version, 2);
  buff[6] = len;
  memcpy(&buff[7], &INFO_VERSION, len);                   //copy info string
  write(g_socket, buff, sizeof(buff));
}

void send_filter_data(char idx, char flt, unsigned char *data, int len)
{
  unsigned char buff[6 + len];

  uint32_t req = htonl(DVBAPI_FILTER_DATA);             //type of request
  memcpy(&buff[0], &req, 4);
  buff[4] = idx;                                   		//demux
  buff[5] = flt;                                   		//filter
  memcpy(buff + 6, data, len);                          //copy filter data
  write(g_socket, buff, sizeof(buff));
}

int recv_server_info()
{
	//uint32_t *request;
	unsigned char buff[262];
  	int cRead = recv(g_socket, &buff[0], 6, 0);
	if (cRead == 6)
	{
		//request = (uint32_t *) &buff;
		if (ntohl(*(uint32_t *) &buff) == DVBAPI_SERVER_INFO)
		{
		  unsigned char len;

		  uint16_t *proto_ver_ptr = (uint16_t *) &buff[4];
		  uint16_t protocol_version = ntohs(*proto_ver_ptr);

		  recv(g_socket, &len, 1, 0);               	//string length
		  recv(g_socket, buff+6, len, 0);
		  buff[6+len] = 0;                              //terminate the string
		  log("Got SERVER_INFO: %s, protocol_version = %d\n", &buff[6], protocol_version);
		  return 1;
		}
	}

	return 0;
}

void send_stop_dmx(char dmx)
{
	unsigned char cmd[8] = {0x9F, 0x80, 0x3f, 0x04, 0x83, 0x02, 0x00};
	cmd[7] = dmx;

	write(g_socket, cmd, 8);
	log("Stop descrambling sent for dmx %d\n", dmx);
}

void send_pmt(char lm, unsigned char* buf, int idx)
{
	int len = 3 + ((buf[1] & 0x0F) << 8) + buf[2];
	if( len > 1024 )
	{
		log("Unable to send pmt, wrong length: %d\n", len);
		return;
	}

	unsigned char caPMT[1040];
	int program_info_length = ((buf[10] & 0x0F) << 8) + buf[11] + 4 + 1;	//program_info_length (+1 for ca_pmt_cmd_id, +4 for CAPMT_DESC_DEMUX)
	int length_field = len - 5;	// 17 - 6 + len - 4 - 12

	//ca_pmt_tag
	caPMT[0] = 0x9F;
	caPMT[1] = 0x80;
	caPMT[2] = 0x32;
	caPMT[3] = 0x82;              //2 following bytes for size

	caPMT[4] = length_field >> 8;
	caPMT[5] = length_field & 0xff;

	caPMT[6] = lm; 				//list management
	caPMT[7] = buf[3];          //program_number
	caPMT[8] = buf[4];        	//program_number
	caPMT[9] = 0;               //version_number, current_next_indicator

	caPMT[10] = program_info_length >> 8;            //reserved+program_info_length
	caPMT[11] = program_info_length & 0xFF;          //reserved+program_info_length (+1 for ca_pmt_cmd_id, +4 for above CAPMT_DESC_DEMUX)

	caPMT[12] = 0x01;             //ca_pmt_cmd_id = CAPMT_CMD_OK_DESCRAMBLING
	//adding own descriptor with demux and adapter_id
	caPMT[13] = 0x82;           //CAPMT_DESC_DEMUX
	caPMT[14] = 0x02;           //length
	caPMT[15] = 0x00;           //demux id
	caPMT[16] = (char)idx;   	//adapter id

	memcpy(caPMT + 17, buf + 12, len - 16);  //copy pmt data starting at program_info block

	write(g_socket, caPMT, length_field + 6);	// dont send the last 4 bytes (CRC)
}

/*
 * This will handle connection for each client
 * */
int capmt_connection_handler(int socket_desc)
{
    //Get the socket descriptor
    g_socket = socket_desc;

	send_client_info();
	if(!recv_server_info())
		return 0;

	resetCurrentChannel();

	for(int i = 0; i < MAX_PMT; i++)
		memset(g_PMT[i], 0, sizeof(unsigned char) * PMT_SIZE);

	memset(g_PMT_indices, 0, sizeof(int) * MAX_PMT);

	unsigned char buff[1024];
	int cRead;
	uint32_t *request;
	uint8_t adapter_index;

	// request
	while (1)
	{
		cRead = recv(g_socket, buff, sizeof(int), MSG_DONTWAIT);
		if (cRead <= 0)
		{
			if (cRead == 0)
				break;
			usleep(20);
			continue;
		}

		request = (uint32_t *) &buff;

	    if (ntohl(*request) != DVBAPI_SERVER_INFO)
		{
			// first byte -> adapter_index
			cRead = recv(g_socket, &adapter_index, 1, MSG_DONTWAIT);
			if (cRead <= 0)
			{
				if (cRead == 0)
					break;
				usleep(20);
				continue;
			}
		}

		*request = ntohl(*request);

		if (*request == CA_SET_PID)
		  cRead = recv(g_socket, buff+4, sizeof(ca_pid_t), MSG_DONTWAIT);
		else if (*request == DVBAPI_ECM_INFO)
		  cRead = recv(g_socket, buff+4, 14, MSG_DONTWAIT);
		else if (*request == CA_SET_DESCR)
		  cRead = recv(g_socket, buff+4, sizeof(ca_descr_t), MSG_DONTWAIT);
		else if (*request == DMX_SET_FILTER)
		  cRead = recv(g_socket, buff+4, sizeof(dmx_sct_filter_params_t), MSG_DONTWAIT);
		else if (*request == DMX_STOP)
		  cRead = recv(g_socket, buff+4, 2 + 2, MSG_DONTWAIT);
		else
		{
			hexDump("unknown request received", buff, 32);
			usleep(20);
			continue;
		}

		if (cRead <= 0)
		{
			if (cRead == 0)
				break;
			usleep(20);
			continue;
		}

		if (*request == CA_SET_PID)
		{
			ca_pid_t ca_pid;
			memcpy(&ca_pid, &buff[sizeof(int)], sizeof(ca_pid_t));
			ca_pid.pid = ntohl(ca_pid.pid);
			ca_pid.index = ntohl(ca_pid.index);

			//log("Got CA_SET_PID request, pid=0x%04X, idx=%d\n", ca_pid.pid, ca_pid.index);
		}
		if (*request == DVBAPI_ECM_INFO)
		{
			log("Got DVBAPI_ECM_INFO\n");

			// read 4 strings + 1 byte (hops)
			int p = 14;
			for(int i = 0; i < 4; i++)
			{
				cRead = recv(g_socket, buff + p, 1, MSG_DONTWAIT);					// strlen
				cRead = recv(g_socket, buff + p + 1, buff[p], MSG_DONTWAIT);		// str
				p += buff[p] + 1;
			}

			cRead = recv(g_socket, buff + p, 1, MSG_DONTWAIT);		// hops
			//hexDump("buff", buff, p + 1);
		}
		else if (*request == CA_SET_DESCR)
		{
			ca_descr_t ca_descr;
			memcpy(&ca_descr, &buff[sizeof(int)], sizeof(ca_descr_t));
			ca_descr.index = ntohl(ca_descr.index);
			ca_descr.parity = ntohl(ca_descr.parity);	// 0:odd, 1:even


			//log("MDrv_DSCMB_FltKeySet=%d g_fltDscmb=%d\n", hCTX.MDrv_DSCMB_FltKeySet(g_fltDscmb, ca_descr.parity + 1, ca_descr.cw), g_fltDscmb); // parity:: 1:odd, 2:even
			log("Got CA_SET_DESCR request, adapter=%d, idx=%d, cw parity=%d\n", adapter_index, ca_descr.index, ca_descr.parity);

			//if((adapter_index == 0 && g_demux[1].serviceId == -1) || adapter_index == 1)
			log("hCTX.MDrv_DSCMB_FltKeySet=%d\n", hCTX.MDrv_DSCMB_FltKeySet(0, ca_descr.parity + 1, ca_descr.cw));
					//log("MDrv_DSCMB2_FltKeySet=%d\n", hCTX.MDrv_DSCMB2_FltKeySet(g_u32DscmbID, i, ca_descr.parity + 1, ca_descr.cw));
		}
		else if (*request == DMX_SET_FILTER)
		{
			uint8_t dmx = buff[4];
			uint8_t flt = buff[5];
			uint16_t pid = ntohs(*((uint16_t *) &buff[6]));
			uint32_t flags = ntohl(*((uint32_t *) &buff[60]));

			log("Got DMX_SET_FILTER request, idx=0x%02X, flt=0x%02X, pid=0x%04X, tableid=0x%02X, mask=0x%02X, flags=0x%04X\n", dmx, flt, pid, buff[8], buff[24], flags);

			if(dmx >= MAX_DEMUX || flt >= MAX_DEMUX_FILTERS)
			{
				log("wrong idx(%d)/flt(%d) received\n", dmx, flt);
				continue;
			}

			if ( pid == 0 )
				continue;

			memset(&g_dmxParams, 0, sizeof(t_dmxParams));
			g_dmxParams.pid = pid;
			g_dmxParams.tableId = buff[8];
			
			g_demux[dmx].filter[flt].monParams.pid = pid;
			g_demux[dmx].filter[flt].monParamsData.filter[0] = buff[8];
			g_demux[dmx].filter[flt].monParamsData.mask[0] = buff[24];

			//memcpy(&g_demux[dmx].filter[flt].monParamsData.filter[3], &buff[9], MAX_FILTER_SIZE - 3);
			//memcpy(&g_demux[dmx].filter[flt].monParamsData.mask[3], &buff[25], MAX_FILTER_SIZE - 3);
			
			memcpy(&g_demux[dmx].filter[flt].monParamsData.filter[0], &buff[8], MAX_FILTER_SIZE);
			memcpy(&g_demux[dmx].filter[flt].monParamsData.mask[0], &buff[24], MAX_FILTER_SIZE);
			
			//hexDump("filter", g_demux[dmx].filter[flt].monParamsData.filter, MAX_FILTER_SIZE );
			//hexDump("mask", g_demux[dmx].filter[flt].monParamsData.mask, MAX_FILTER_SIZE );

			if(g_demux[dmx].filter[flt].hmon != -1) {
				log("Monitor stopped, idx=0x%02X, flt=0x%02X, dmxHandle=0x%08X, monHandle=0x%08X, ret=0x%08X\n", dmx, flt, g_demux[dmx].dmxHandle, g_demux[dmx].filter[flt].hmon /*& 0x7FFFFFFF*/, hCTX.SdTSData_StopMonitor( g_demux[dmx].dmxHandle, g_demux[dmx].filter[flt].hmon /*& 0x7FFFFFFF*/ ));
			}
			//if ( g_demux[dmx].filter[flt].hmon == -1) {
				g_demux[dmx].filter[flt].hmon = hCTX.SdTSData_StartMonitor( g_demux[dmx].dmxHandle, &g_dmxParams /*&g_demux[dmx].filter[flt].monParams*/, 0 );
				log("Monitor started, idx=0x%02X, flt=0x%02X, dmxHandle=0x%08X, monHandle=0x%08X\n", dmx, flt, g_demux[dmx].dmxHandle, g_demux[dmx].filter[flt].hmon);
			//}			
		}
		else if (*request == DMX_STOP)
		{
			uint8_t dmx = buff[4];
			uint8_t flt = buff[5];
			uint16_t pid = ntohs(*((uint16_t *) &buff[6]));

			log("Got DMX_STOP request, idx=0x%02X, flt=0x%02X, pid=0x%04X\n", dmx, flt, pid);

			if(dmx >= MAX_DEMUX || flt >= MAX_DEMUX_FILTERS)
			{
				log("wrong idx(%d)/flt(%d) received\n", dmx, flt);
				continue;
			}
			
			if(g_demux[dmx].filter[flt].hmon != -1)
				log("Monitor stopped, idx=0x%02X, flt=0x%02X, dmxHandle=0x%08X, monHandle=0x%08X, ret=0x%08X\n", dmx, flt, g_demux[dmx].dmxHandle, g_demux[dmx].filter[flt].hmon /*& 0x7FFFFFFF*/, hCTX.SdTSData_StopMonitor( g_demux[dmx].dmxHandle, g_demux[dmx].filter[flt].hmon /*& 0x7FFFFFFF*/ ));

			g_demux[dmx].filter[flt].hmon = -1;
			g_demux[dmx].filter[flt].monParams.pid = -1;
		}
	}

	close(g_socket);
	g_socket = -1;
	log("Client disconnected\n");

    return 0;
}
