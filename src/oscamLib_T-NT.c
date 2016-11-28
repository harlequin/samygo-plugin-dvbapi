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


#define LIB_VERSION "build " SVN_REV
#define LIB_TV_MODELS "H T-NT"
#define LIB_HOOKS libOscamH_hooks
#define hCTX libOscamH_hook_ctx

//////////////////////////////////////////////////////////////////////////////

#include <netinet/in.h>
#include "../common_T-NT/common.h"
#include "../common_T-NT/hook.h"
#include "../common_T-NT/util.h"
#include "../common_T-NT/capmt.h"

//////////////////////////////////////////////////////////////////////////////

#define CWB 	6

typedef struct 
{
    unsigned int pid;
    unsigned int data_type;		// 0, 1, 2
    unsigned int param_type;	// 0
    unsigned int filter_type; 	// 0: table, 1: mask
    unsigned char* filter_data;
	unsigned int filter_data_len;
	unsigned char* filter_mask;		
	unsigned char* filter_mode;	// 0: normal, 1:invert	
} t_dmxParams;

typedef struct
{
    unsigned char                              au8EvenCW[8];                 /*!< Odd control word                           */
    unsigned char                              au8OddCW[8];                  /*!< Even control word                          */
}ST_DRV_TSPU_DESC_CWB_DVB_CSA_PARAMS, *PST_DRV_TSPU_DESC_CWB_DVB_CSA_PARAMS;

typedef struct
{
    unsigned char                              b8DefaultCWEnable;                                          /*!< Enable Default control word            */
    unsigned char                              au8DefaultCW[8];              /*!< Default control word                   */
}ST_DRV_TSPU_DESC_MODE_DVB_CSA_PARAMS, *PST_DRV_TSPU_DESC_MODE_DVB_CSA_PARAMS;

typedef struct
{
    int           enDescMode;                                                 /*!< DESC operation mode            */
    union
    {
        ST_DRV_TSPU_DESC_MODE_DVB_CSA_PARAMS        stDvbCsaParams;                             /*!< DVB CSA Parameters             */        
    } unCfg;
}ST_DRV_TSPU_DESC_CFG_PARAMS, *PST_DRV_TSPU_DESC_CFG_PARAMS;

typedef struct
{
    unsigned int                             u32DpHandle;												/*!< reserve for futher use                                         */
}ST_DRV_TSPU_DESC_PID_OPEN_PARAMS, *PST_DRV_TSPU_DESC_PID_OPEN_PARAMS;

typedef struct
{
    unsigned short                          u16PidPattern;                                              /*!< PID Pattern value                  */  
    int            							enCWB;                                                      /*!< Control Word Bank Value            */
    int										enLayer;                                                    /*!< encrypted layer TS/PES             */
}ST_DRV_TSPU_DESC_PID_CFG_PARAMS, *PST_DRV_TSPU_DESC_PID_CFG_PARAMS;

//////////////////////////////////////////////////////////////////////////////

unsigned int g_u32DscmbID = 0;
unsigned int g_dmxHandle = 0;
int g_monHandle = -1;
int g_sId = -1;
t_dmxParams g_dmxParams;
#define MAX_PMT		64
#define PMT_SIZE	1024
#define ECM_SIZE	1024
unsigned char* g_PMT[MAX_PMT];
int g_PMT_indices[MAX_PMT] = {0};
int g_PMT_head = 0;
unsigned char* g_ECM80;
unsigned char* g_ECM81;
int g_send_PMT_required = 0;
unsigned int g_DescPid[2] = {0};
ST_DRV_TSPU_DESC_CWB_DVB_CSA_PARAMS csaParams;
int g_PVR_PLAYBACK_enabled = 0;

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

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

typedef union
{
	const void *procs[32];
	struct
	{
		// libSDAL.so		
		int (*SdTSData_StartMonitor)(unsigned int dmxHandle, void* dmxParams, unsigned int eDataType, unsigned int SdMainChip_k);
		int (*SdTSData_StopMonitor)(unsigned int dmxHandle, unsigned int monHandle, unsigned int SdMainChip_k);
		
		int (*PLAT_TSPU_GetDpHandleByDemuxHdl)(unsigned int dmxHandle, int *dpNumber);		
		int (*DRV_TSPU_DESC_CWB_Enable)(unsigned int u32DPHandle, int enCWB);
		int (*DRV_TSPU_DESC_CWB_Disable)(unsigned int u32DPHandle, int enCWB);
		int (*DRV_TSPU_DESC_CWB_Config)(unsigned int u32DPHandle, int enCWB, PST_DRV_TSPU_DESC_CWB_DVB_CSA_PARAMS pstParams);
		int (*DRV_TSPU_DESC_Config)(unsigned int u32DPHandle, PST_DRV_TSPU_DESC_CFG_PARAMS pstParams);
		
		int (*DRV_TSPU_DESC_PID_Open)(char *DeviceName, PST_DRV_TSPU_DESC_PID_OPEN_PARAMS pstParams, unsigned int *pu32DescHandle);
		int (*DRV_TSPU_DESC_PID_Close)(unsigned int *pu32DescHandle);
		int (*DRV_TSPU_DESC_PID_Enable)(unsigned int u32DescHandle);
		int (*DRV_TSPU_DESC_PID_Disable)(unsigned int u32DescHandle);
		int (*DRV_TSPU_DESC_PID_Config)(unsigned int u32DescHandle, PST_DRV_TSPU_DESC_PID_CFG_PARAMS pstParams);
		
		int (*SdCP_Open)(unsigned int dmxHandle, unsigned int SdMainChip_k);
			
		// exeTV
		void* (*TCAPI_GetWindow)(int arg1);
		const int (*TCWindowImpl_GetSource)(void *window, int *source, int a2);
		const int (*TCWindowImpl_GetTVChannel)(void *window, void *channel, int arg3);
		const int (*TCWindowImpl_SetChannelQuiet)(void *window, void *channel, int arg3);
		const int (*TCChannel_Create)(void *channel);
		const int (*TCChannel_Destroy)(void *channel);
		const int (*TCChannel_ProgramNumber)(void *channel);
		const int (*TCChannel_SizeOfDescriptor)(void *channel);
		const int (*TCChannel_Descriptor)(void *channel, int nine, int desc);
		const int (*TCMwUtilsBridge_GetSourceId)(void *this, void *TCSourceConf);
	};
} samyGO_whacky_t;

samyGO_whacky_t hCTX = 
{	
	(const void*)"_Z21SdTSData_StartMonitorjP19SdTSData_Settings_tj12SdMainChip_k",
	(const void*)"_Z20SdTSData_StopMonitorjj12SdMainChip_k",

	(const void*)"PLAT_TSPU_GetDpHandleByDemuxHdl",
	(const void*)"DRV_TSPU_DESC_CWB_Enable",
	(const void*)"DRV_TSPU_DESC_CWB_Disable",
	(const void*)"DRV_TSPU_DESC_CWB_Config",
	(const void*)"DRV_TSPU_DESC_Config",
	
	(const void*)"DRV_TSPU_DESC_PID_Open",
	(const void*)"DRV_TSPU_DESC_PID_Close",
	(const void*)"DRV_TSPU_DESC_PID_Enable",
	(const void*)"DRV_TSPU_DESC_PID_Disable",
	(const void*)"DRV_TSPU_DESC_PID_Config",
	
	(const void*)"_Z9SdCP_Openj12SdMainChip_k",
	
	(const void*)"_ZN5TCAPI9GetWindowEN8TCWindow7EWindowE",
	(const void*)"_ZN12TCWindowImpl9GetSourceEPii",				  
	(const void*)"_ZN12TCWindowImpl12GetTVChannelEP9TCChanneli",				  
	(const void*)"_ZN12TCWindowImpl15SetChannelQuietEPK9TCChannelb",
	(const void*)"_ZN9TCChannelC2Ev",
	(const void*)"_ZN9TCChannelD2Ev",
	(const void*)"_ZNK9TCChannel13ProgramNumberEv",
	(const void*)"_ZNK9TCChannel16SizeOfDescriptorEv",
	(const void*)"_ZNK9TCChannel10DescriptorEii",
	(const void*)"_ZNK3CIM15TCMwUtilsBridge11GetSourceIdEP12TCSourceConf",
};

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

//////////////////////////////////////////////////////////////////////////////

_HOOK_IMPL(int, TCCIMManagerPlus_ChannelChange, void* this, void* TCChannel, void *TCSourceConf)
{	  
	_HOOK_DISPATCH(TCCIMManagerPlus_ChannelChange, this, TCChannel, TCSourceConf);
	
	log("TCCIMManagerPlus_ChannelChange, TCChannel=0x%08X, TCSourceConf=0x%04X\n", TCChannel, TCSourceConf);
	
	if(TCChannel == 0) return (int)h_ret;	
	
	int prev_sId = g_sId;
	int sourceid = hCTX.TCMwUtilsBridge_GetSourceId(0, TCSourceConf);
	
	log("Source id=%d\n", sourceid);
	
	if(sourceid < 88 )	//(!(g_dmxActive & DMX_PLAY))
		g_sId = hCTX.TCChannel_ProgramNumber(TCChannel);
	
	if(prev_sId != g_sId)
	{		
		g_send_PMT_required = 1;
		log("Service changed, new sId=0x%04X\n", g_sId);
		
		ST_DRV_TSPU_DESC_CFG_PARAMS pstCfgParams;
		memset(&pstCfgParams, 0, sizeof(ST_DRV_TSPU_DESC_CFG_PARAMS));
								
		pstCfgParams.enDescMode = 1;
							
		int dpHandle = -1;
		log("PLAT_TSPU_GetDpHandleByDemuxHdl=0x%08X, g_dmxHandle=0x%08X, dpHandle=0x%08X\n", hCTX.PLAT_TSPU_GetDpHandleByDemuxHdl(g_dmxHandle, &dpHandle), g_dmxHandle, dpHandle);
		
		log("DRV_TSPU_DESC_CWB_Disable=0x%08X\n", hCTX.DRV_TSPU_DESC_CWB_Disable(dpHandle, CWB));			
		log("DRV_TSPU_DESC_Config=0x%08X\n", hCTX.DRV_TSPU_DESC_Config( dpHandle, &pstCfgParams ));
		log("DRV_TSPU_DESC_CWB_Enable=0x%08X\n", hCTX.DRV_TSPU_DESC_CWB_Enable(dpHandle, CWB));	
	}
}

_HOOK_IMPL(int,DemuxBase_m_Demux_SICallback, unsigned int* SICallBackSettings_t)
{
	_HOOK_DISPATCH(DemuxBase_m_Demux_SICallback, SICallBackSettings_t);
	
	if(g_socket < 0) return (int)h_ret;
	
	unsigned int hmon = SICallBackSettings_t[0];
	unsigned int pid = SICallBackSettings_t[1];
	unsigned char* buf = (unsigned char*)SICallBackSettings_t[2];
	unsigned int len = SICallBackSettings_t[3];	

	if(buf[0] == 0x02 && len > 0 && len < 1024)
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
	else if(buf[0] == 0x80 && len > 0 && len < 1024 &&  memcmp(g_ECM80, buf, len)!=0)	// got ECM
	{
		log("Got ECM80\n");
		memcpy(g_ECM80, buf, len);		
		send_filter_data(buf, len);		
	}
	else if(buf[0] == 0x81 && len > 0 && len < 1024 && memcmp(g_ECM81, buf, len)!=0)	// got ECM
	{
		log("Got ECM81\n");
		memcpy(g_ECM81, buf, len);		
		send_filter_data(buf, len);		
	}		
	
	if(g_send_PMT_required == 1)
	{
		int pmt_index = g_PMT_indices_get_index_of(g_sId);
		if( pmt_index > -1 )
		{
			send_pmt(g_PMT[pmt_index]);
			g_send_PMT_required = 0;
			log("PMT sent, sId=0x%04X\n", g_sId);
		}
	}
	
	if( (buf[0] == 0x02 || buf[0] == 0x80 || buf[0] == 0x81) && (len == 0 && len >= 1024) )
		log("Wrong PES received, type=0x%02X, len=%d\n", buf[0], len);
}

void changeMonitor(unsigned int dmxHandle)
{
	if(g_monHandle > -1)
		log("ECM monitor stopped, dmxHandle=0x%08X, monHandle=0x%08X, ret=0x%08X\n", g_dmxHandle, g_monHandle, hCTX.SdTSData_StopMonitor( g_dmxHandle, g_monHandle, 0 ));
	
	g_dmxHandle = dmxHandle;
	log("using dmxHandle=0x%08X\n", g_dmxHandle);
	
	if(g_dmxParams.pid > 0)
	{
		unsigned char buff[3] = {0x80, 0xF0, 0x00};
		g_dmxParams.filter_data = &buff[0];
		g_dmxParams.filter_mask = &buff[1];
		g_dmxParams.filter_mode = &buff[2];	
		
		g_monHandle = hCTX.SdTSData_StartMonitor( g_dmxHandle, &g_dmxParams, 0, 0 );	
		log("ECM monitor restarted, dmxHandle=0x%08X, monHandle=0x%08X\n", g_dmxHandle, g_monHandle);
	}
}

_HOOK_IMPL(int,SdDemux_Start, unsigned int dmxHandle, int eDemuxOut, int eMainChip)
{
	_HOOK_DISPATCH(SdDemux_Start, dmxHandle, eDemuxOut, eMainChip);
	
	log("SdDemux_Start, dmxHandle=0x%08X, eDemuxOut=0x%08X, eMainChip=0x%08X\n", dmxHandle, eDemuxOut, eMainChip);
			
	if(g_dmxHandle != 0x12345601)
		changeMonitor(dmxHandle);
	
	unsigned int dpHandle = 0;
	log("PLAT_TSPU_GetDpHandleByDemuxHdl=0x%08X, g_dmxHandle=0x%08X, dpHandle=0x%08X\n", hCTX.PLAT_TSPU_GetDpHandleByDemuxHdl(g_dmxHandle, &dpHandle), g_dmxHandle, dpHandle);	
	
	if( (dpHandle & 0x0000FF00) == 0x0200)
		g_PVR_PLAYBACK_enabled = 1;
	
	if( !g_PVR_PLAYBACK_enabled )
	{	
		for(int i = 0; i < 2; i++)
			if(g_DescPid[i] > 0)
			{
				log("DRV_TSPU_DESC_PID_Disable=0x%08X, descPid=0x%08X\n", hCTX.DRV_TSPU_DESC_PID_Disable( g_DescPid[i] ), g_DescPid[i]);
				log("DRV_TSPU_DESC_PID_Close=0x%08X, descPid=0x%08X\n", hCTX.DRV_TSPU_DESC_PID_Close( &g_DescPid[i] ), g_DescPid[i]);		
			}
				
		ST_DRV_TSPU_DESC_PID_OPEN_PARAMS pidOpenParams;
		pidOpenParams.u32DpHandle = dpHandle;
		
		for(int i = 0; i < 2; i++)
			log("DRV_TSPU_DESC_PID_Open=0x%08X, descPid=0x%08X\n", hCTX.DRV_TSPU_DESC_PID_Open( "TSPU001", &pidOpenParams, &g_DescPid[i] ), g_DescPid[i]);
	}
	else
		log("ignoring dpHandle=0x%08X\n", dpHandle);
					
	return (int)h_ret;
}

_HOOK_IMPL(int,SdDemux_Stop, unsigned int dmxHandle, int eDemuxOut, int eMainChip)
{		
	log("SdDemux_Stop, dmxHandle=0x%08X, eDemuxOut=0x%08X, eMainChip=0x%08X\n", dmxHandle, eDemuxOut, eMainChip);
	
	unsigned int dpHandle = 0;
	log("PLAT_TSPU_GetDpHandleByDemuxHdl=0x%08X, dmxHandle=0x%08X, dpHandle=0x%08X\n", hCTX.PLAT_TSPU_GetDpHandleByDemuxHdl(dmxHandle, &dpHandle), dmxHandle, dpHandle);
	
	if( (dpHandle & 0x0000FF00) == 0x0200)
		g_PVR_PLAYBACK_enabled = 0;
	
	if(g_dmxHandle == 0x12345600 && dmxHandle == 0x12345600 && g_monHandle > -1)
	{
		hCTX.SdTSData_StopMonitor( g_dmxHandle, g_monHandle, 0 );
		log("ECM monitor stopped, dmxHandle=0x%08X, monHandle=0x%08X\n", g_dmxHandle, g_monHandle);
		g_monHandle = -1;	
	}
	
	if(g_dmxHandle == 0x12345601 && dmxHandle == 0x12345601)
		changeMonitor(0x12345600);
					
	_HOOK_DISPATCH(SdDemux_Stop, dmxHandle, eDemuxOut, eMainChip);
		
	return (int)h_ret;
}

_HOOK_IMPL(int, CIM_TCServiceSelectionManager_SetAvPid, void* this, int EWindow, int pidVideo, int pidAudio)
{	  
	_HOOK_DISPATCH(CIM_TCServiceSelectionManager_SetAvPid, this, EWindow, pidVideo, pidAudio);
	
	if( !g_PVR_PLAYBACK_enabled && pidVideo > -1 && pidAudio > -1)
	{		
		log("New video and audio pids, pidVideo=0x%04X, pidAudio=0x%04X\n", pidVideo, pidAudio);
				
		ST_DRV_TSPU_DESC_PID_CFG_PARAMS pidCfgParams;
		
		for(int i = 0; i < 2; i++)
		{
			if(g_DescPid[i] < 0)
				continue;
			
			pidCfgParams.u16PidPattern = i == 0 ? pidVideo : pidAudio;
			pidCfgParams.enCWB = CWB;
			pidCfgParams.enLayer = 0;			
			
			log("DRV_TSPU_DESC_PID_Disable=0x%08X, descPid=0x%08X\n", hCTX.DRV_TSPU_DESC_PID_Disable( g_DescPid[i] ), g_DescPid[i]);
			log("DRV_TSPU_DESC_PID_Config=0x%08X\n", hCTX.DRV_TSPU_DESC_PID_Config( g_DescPid[i], &pidCfgParams ));
			log("DRV_TSPU_DESC_PID_Enable=0x%08X, descPid=0x%08X\n", hCTX.DRV_TSPU_DESC_PID_Enable( g_DescPid[i] ), g_DescPid[i]);
		}
	}	
}

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

STATIC dyn_fn_t dyn_hook_fn_tab[] =
{    
    { 0, "_ZN9DemuxBase18m_Demux_SICallbackEPN8CDiDemux20SICallBackSettings_tE" },
    { 0, "_ZN16TCCIMManagerPlus13ChannelChangeEPK9TCChannelP12TCSourceConf" },
	{ 0, "_Z13SdDemux_Startj13SdDemux_Out_k12SdMainChip_k" }, 
	{ 0, "_Z12SdDemux_Stopj13SdDemux_Out_k12SdMainChip_k" }, 
	{ 0, "_ZN3CIM25TCServiceSelectionManager8SetAvPidEN8TCWindow7EWindowEii" },
};

STATIC hook_entry_t LIB_HOOKS[] =
{
#define _HOOK_ENTRY(F, I) \
    &hook_##F, &dyn_hook_fn_tab[I], &x_##F

    { _HOOK_ENTRY(DemuxBase_m_Demux_SICallback, __COUNTER__) },
    { _HOOK_ENTRY(TCCIMManagerPlus_ChannelChange, __COUNTER__) },
	{ _HOOK_ENTRY(SdDemux_Start, __COUNTER__) },
	{ _HOOK_ENTRY(SdDemux_Stop, __COUNTER__) },
	{ _HOOK_ENTRY(CIM_TCServiceSelectionManager_SetAvPid, __COUNTER__) },

#undef _HOOK_ENTRY
};

//////////////////////////////////////////////////////////////////////////////
static int _hooked = 0;

EXTERN_C void lib_init(
        void *_h, const char *libpath)
{
	unsigned long *cur_addr;
    if(_hooked)
    {
        log("Injecting once is enough!\n");
        return;
    }
	
	unlink(LOG_FILE);
/*	
	char *argv[100];
    int argc = getArgCArgV(libpath, argv);
*/
	log("SamyGO "LIB_TV_MODELS" "LIB_NAME" "LIB_VERSION" - (c) MrB 2015\n");

    void *h = dlopen(0, RTLD_LAZY);
    if(!h)
    {
        char *serr = dlerror();
        log("dlopen error %s\n", serr);
        return;
    }
    
    patch_adbg_CheckSystem(h);
	
	for(int i = 0; i < MAX_PMT; i++) 
	{
		g_PMT[i] = malloc(sizeof(unsigned char) * PMT_SIZE);
		memset(g_PMT[i], 0, sizeof(unsigned char) * PMT_SIZE);
	}
	
	g_ECM80 = malloc(sizeof(unsigned char) * ECM_SIZE);
	g_ECM81 = malloc(sizeof(unsigned char) * ECM_SIZE);
	memset(g_ECM80, 0, sizeof(unsigned char) * ECM_SIZE);
	memset(g_ECM81, 0, sizeof(unsigned char) * ECM_SIZE);
	
	memset(&csaParams, 0, sizeof(ST_DRV_TSPU_DESC_CWB_DVB_CSA_PARAMS));
		
	samyGO_whacky_t_init(h, &hCTX, ARRAYSIZE(hCTX.procs));
	
    if(dyn_sym_tab_init(h, dyn_hook_fn_tab, ARRAYSIZE(dyn_hook_fn_tab)) >= 0)
    {
        set_hooks(LIB_HOOKS, ARRAYSIZE(LIB_HOOKS));
        _hooked = 1;
    }
	
	log("SdCP_Open=0x%08X\n", hCTX.SdCP_Open(0x12345600, 0));
		
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

void send_filter_data(unsigned char *data, int len)
{
  unsigned char buff[6 + len];

  uint32_t req = htonl(DVBAPI_FILTER_DATA);             //type of request
  memcpy(&buff[0], &req, 4);
  buff[4] = 0;                                     		//demux
  buff[5] = 0;                                   		//filter
  memcpy(buff + 6, data, len);                          //copy filter data
  write(g_socket, buff, sizeof(buff));
}

int recv_server_info()
{
	uint32_t *request;
	unsigned char buff[262];	
  	int cRead = recv(g_socket, &buff[0], 6, 0);
	if (cRead == 6)
	{
		request = (uint32_t *) &buff;
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

void send_pmt(unsigned char* buf)
{	
	int len = 3 + ((buf[1] & 0x0F) << 8) + buf[2];
	unsigned char caPMT[2048]; 
	int program_info_length = ((buf[10] & 0x0F) << 8) + buf[11];
	int length_field = len - 10;

	//ca_pmt_tag
	caPMT[0] = 0x9F;
	caPMT[1] = 0x80;
	caPMT[2] = 0x32;
	caPMT[3] = 0x82;              //2 following bytes for size

	caPMT[4] = length_field >> 8;
	caPMT[5] = length_field & 0xff;
	
	caPMT[6] = LIST_ONLY; 		//list management	
	caPMT[7] = buf[3];          //program_number
	caPMT[8] = buf[4];        	//program_number
	caPMT[9] = 0;               //version_number, current_next_indicator

	memcpy(caPMT + 10, buf + 10, len - 14);    		//copy pmt data starting at progtam_info block

	write(g_socket, caPMT, len - 4);	// dont send the last 4 bytes (CRC)	
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
	
	g_sId = -1;
	int source = 0;
	
	hCTX.TCWindowImpl_GetSource(hCTX.TCAPI_GetWindow(0), &source, 1);
	if(source == 0)
	{	
		unsigned char channel[32] = {0};
		
		hCTX.TCChannel_Create(channel);
		hCTX.TCWindowImpl_GetTVChannel(hCTX.TCAPI_GetWindow(0), channel, 1);
		
		for(int i = 0; i < hCTX.TCChannel_SizeOfDescriptor(channel); i++)			
			if(hCTX.TCChannel_Descriptor(channel, 9, i))
			{
				hCTX.TCWindowImpl_SetChannelQuiet(hCTX.TCAPI_GetWindow(0), channel, 1);
				break;
			}
		
		hCTX.TCChannel_Destroy(channel);	
	}
	
	log("channel set...\n");

	for(int i = 0; i < MAX_PMT; i++)	
		memset(g_PMT[i], 0, sizeof(unsigned char) * PMT_SIZE);
		
	memset(g_PMT_indices, 0, sizeof(g_PMT_indices));
				
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
			log("Got CA_SET_PID request\n");
		}
		else if (*request == CA_SET_DESCR)
		{
			ca_descr_t ca_descr;						
			memcpy(&ca_descr, &buff[sizeof(int)], sizeof(ca_descr_t));
			ca_descr.index = ntohl(ca_descr.index);
			ca_descr.parity = ntohl(ca_descr.parity);	// 0:odd, 1:even
			
/*			ST_DRV_TSPU_DESC_CFG_PARAMS pstCfgParams;
			memset(&pstCfgParams, 0, sizeof(ST_DRV_TSPU_DESC_CFG_PARAMS));
									
			pstCfgParams.enDescMode = 1;
*/															
			if(!ca_descr.parity)
				memcpy(csaParams.au8EvenCW, ca_descr.cw, 8);
			else
				memcpy(csaParams.au8OddCW, ca_descr.cw, 8);
						
			int dpHandle = -1;
			log("PLAT_TSPU_GetDpHandleByDemuxHdl=0x%08X, g_dmxHandle=0x%08X, dpHandle=0x%08X\n", hCTX.PLAT_TSPU_GetDpHandleByDemuxHdl(g_dmxHandle, &dpHandle), g_dmxHandle, dpHandle);
			
			log("DRV_TSPU_DESC_CWB_Disable=0x%08X\n", hCTX.DRV_TSPU_DESC_CWB_Disable(dpHandle, CWB));			
//			log("DRV_TSPU_DESC_Config=0x%08X\n", hCTX.DRV_TSPU_DESC_Config( dpHandle, &pstCfgParams ));				
			log("DRV_TSPU_DESC_CWB_Config=0x%08X\n", hCTX.DRV_TSPU_DESC_CWB_Config(dpHandle, CWB, &csaParams));
			log("DRV_TSPU_DESC_CWB_Enable=0x%08X\n", hCTX.DRV_TSPU_DESC_CWB_Enable(dpHandle, CWB));	
			
			log("Got CA_SET_DESCR request, cw parity=%d\n", ca_descr.parity);
		}		
		else if (*request == DMX_SET_FILTER)
		{	
			uint16_t *pid_ptr = (uint16_t *) &buff[6];
			
			memset(&g_dmxParams, 0, sizeof(t_dmxParams));					  
			
			g_dmxParams.pid = ntohs(*pid_ptr);
			g_dmxParams.data_type = 0;
			g_dmxParams.param_type = 0;
			g_dmxParams.filter_type = 1;
			g_dmxParams.filter_data_len = 1;
			g_dmxParams.filter_data = &buff[8];
			g_dmxParams.filter_mask = &buff[24];
			g_dmxParams.filter_mode = &buff[40];
			
			log("Got DMX_SET_FILTER request, pid=0x%04X, byte1=0x%02X, mask1=0x%02X\n", g_dmxParams.pid, buff[8], buff[24]);
			
			if(g_monHandle > -1) 
				log("ECM monitor stopped, dmxHandle=0x%08X, monHandle=0x%08X, ret=0x%08X\n", g_dmxHandle, g_monHandle, hCTX.SdTSData_StopMonitor( g_dmxHandle, g_monHandle, 0 ));
		
			g_monHandle = hCTX.SdTSData_StartMonitor( g_dmxHandle, &g_dmxParams, 0, 0 );						
			log("ECM monitor started, dmxHandle=0x%08X, monHandle=0x%08X\n", g_dmxHandle, g_monHandle);
		}
		else if (*request == DMX_STOP)
		{			
			uint16_t pid;
			uint16_t *pid_ptr = (uint16_t *) &buff[6];
			pid = ntohs(*pid_ptr);
			
			if(g_monHandle > -1) 
			{
				log("ECM monitor stopped, dmxHandle=0x%08X, monHandle=0x%08X, ret=0x%08X\n", g_dmxHandle, g_monHandle, hCTX.SdTSData_StopMonitor( g_dmxHandle, g_monHandle, 0 ));
				g_monHandle = -1;
			}
		
			log("Got DMX_STOP request, pid=0x%04X\n", pid);
		}
	}
       
	close(g_socket);
	log("Client disconnected\n");     
		 
    return 0;
} 