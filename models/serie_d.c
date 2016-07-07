/**
 * Copyright (c) 2016 harlequin
 * https://github.com/harlequin/samygo-plugin-dvbapi
 *
 * This file is part of samygo-plugin-dvbapi.
 *
 * samygo-plugin-dvbapi is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h> /*ntohs*/
#include "../dvbapi.h"
#include "../utlist.h"
#include "../hook.h"
#include "../models.h"
#include "../log.h"
#include "../version.h"

#define FILTER_MASK_SIZE 16

#define DMX_HANDLE_19800000 0x19800000
#define DMX_HANDLE_LIVE 	0x19800620
#define DMX_HANDLE_PVR  	0x19800621
#define DMX_HANDLE_UNKNOWN 	0x19800622
#define DMX_HANDLE_PIP  	0x19800623

typedef struct DEMUX_FILTER {
	u16 tableId;
	s32 monHandle;
	u8 demuxId;
	u8 filterId;
	struct DEMUX_FILTER *next;
} demux_filter_t;

static int g_send_PMT_required = 0;
static int g_SID = 0;
static int g_fltDscmb = 0;
static unsigned int g_dmxHandle = DMX_HANDLE_LIVE;
static SdTSData_Settings_t g_dmxParams;
static s32 g_dmxMonHandle = -1;
static s32 g_dmxTableId = -1;
static demux_filter_t *g_demux_filter = NULL;
static SdTSData_Settings_t g_emmParams;

static u32 g_hDesc = 0;
static u32 g_DscmbId = 0;
static u32 g_SourceId = 0;

/*TODO: REWORK */

//spITsd_DescramblerSetKey(m_hDesc, u32DescId, EVEN_KEY, pKeyInfo->pKey, pKeyInfo->keyLen)
//spITsd_DescramblerSetKey(m_hDesc, u32DescId, ODD_KEY, pKeyInfo->pKey, pKeyInfo->keyLen)
//spITsd_DescramblerSetKey(m_hDesc, pCpInst->u32DescId, eCwType, pKeyInfo->pKey, pKeyInfo->keyLen)

typedef enum {
	EVEN_KEY = 0x00,
	ODD_KEY = 0x01
} eCwType;

typedef union {
	const void *procs[15];
	struct	{
		/*Available in libsdal.o*/
		const int (*SdTSData_StartMonitor)(u32 dmx_handle, SdTSData_Settings_t *a1);
		const int (*SdTSData_StopMonitor)(u32 dmx_handle, u32 mon_handle);
		const int (*spITsd_Open)(signed int a1 ,void *hDesc);
		const int (*spITsd_DescramblerAllocate)(u32 hDesc, signed int a2, void *u32DscmbId);
		const int (*spITsd_DescramblerDeallocate)(u32 hDesc, u32 u32DscmbId);
		const int (*spITsd_DescramblerLinkToDmx)(u32 hDesc, u32 u32DscmbId, u32 dmxHandle);

		const int (*spITsd_DescramblerSetKey)(u32 hDesc, u32 DscmbId, eCwType parity, u8 *data, u8 len);

		void **g_pAppWindow;

		const int (*GetSource) (void *window, int *source, int arg3);
		const int (*GetTvChannel)(void *window, void *channel, int arg3);
		const int (*SetChannelQuiet)(void *window, void *channel, int arg3);
		const void* (*TCChannel_Create)(void *channel);
		const void* (*TCChannel_Destroy)(void *channel);
		const int (*ProgramNumber)(void *this);
		//const int (*TCChannel_SizeOfDescriptor)(void *this)
		//const int (*TCChannel_Descriptor)(void *this, int a2, int a3);
		const int (*TPASource_Id)(void);
	};

} api_callbacks_t;

api_callbacks_t api_callbacks = {
		(const void*)"_Z21SdTSData_StartMonitorjP19SdTSData_Settings_tj",
		(const void*)"_Z20SdTSData_StopMonitorjj",
		(const void *)"spITsd_Open",
		(const void *)"spITsd_DescramblerAllocate",
		(const void *)"spITsd_DescramblerDeallocate",
		(const void *)"spITsd_DescramblerLinkToDmx",
		(const void *)"spITsd_DescramblerSetKey",
		(const void *)"g_pAppWindow",
		(const void *)"_ZN8TCWindow9GetSourceEPii",
		(const void *)"_ZN8TCWindow12GetTVChannelEP9TCChanneli",
		(const void *)"_ZN8TCWindow15SetChannelQuietEPK9TCChannelb",
		(const void *)"_ZN9TCChannelC2Ev",
		(const void *)"_ZN9TCChannelD2Ev",
		(const void *)"_ZNK9TCChannel13ProgramNumberEv",
		//    (const void *)"_ZNK9TCChannel16SizeOfDescriptorEv",
		//    (const void *)"_ZNK9TCChannel10DescriptorEii",
		(const void *)"_ZN9TPASource2IdEv",
};

static void stopMonitors() {
	u32 ret;

	if (g_dmxMonHandle >= 0) {
		ret = api_callbacks.SdTSData_StopMonitor(g_dmxHandle, g_dmxMonHandle);
		log("ECM%02X monitor stopped, dmxHandle=0x%08x, monHandle=0x%08x, ret=0x%08x\n",g_dmxTableId, g_dmxHandle, g_dmxMonHandle, ret);
		g_dmxMonHandle = -1;
		g_dmxTableId = -1;
	}
}


static void changeMonitor(unsigned int dmxHandle) {
	if ( g_dmxTableId == -1) {
		return;
	}

	stopMonitors();

	g_dmxHandle = dmxHandle;
	log("using dmxHandle=0x%08X\n", dmxHandle);

	g_dmxMonHandle = api_callbacks.SdTSData_StartMonitor(DMX_HANDLE_LIVE, &g_dmxParams);
	log("ECM%02x monitor restarted, dmxHandle=0x%08x, monHandle=0x%08x\n",g_dmxTableId, g_dmxHandle, g_dmxMonHandle);
}




_HOOK_IMPL(int,SdAVDec_DemuxStop, unsigned int dmxHandle, int eDemuxOut) {
	log("SdAVDec_DemuxStop, dmxHandle=0x%08X, eDemuxOut=0x%08X\n", dmxHandle, eDemuxOut);
	log("g_dmxHandle=0x%08X\n", g_dmxHandle);

	switch (g_dmxHandle) {
	case DMX_HANDLE_LIVE:
		api_callbacks.SdTSData_StopMonitor(DMX_HANDLE_LIVE, 0x00);
		break;
	case DMX_HANDLE_PIP:
	case DMX_HANDLE_PVR:
		log("CHANGE MONITOR NORMALY ...\n");
		changeMonitor(DMX_HANDLE_LIVE);
		break;
	default:
		log("Unknown dmx handle value: 0x%08X\n", dmxHandle);
		break;
	}

	_HOOK_DISPATCH(SdAVDec_DemuxStop, dmxHandle, eDemuxOut);
	return (int)h_ret;
}

_HOOK_IMPL(int,SdAVDec_DemuxStart, unsigned int dmxHandle, int eDemuxOut) {
	log("SdDemux_Start, dmxHandle=0x%08X, eDemuxOut=0x%08X\n", dmxHandle, eDemuxOut);
	log("g_dmxHandle=0x%08X\n", g_dmxHandle);
	_HOOK_DISPATCH(SdAVDec_DemuxStart, dmxHandle, eDemuxOut);

	if ( g_dmxHandle != DMX_HANDLE_PVR) {
		changeMonitor(dmxHandle);
	}

	return (int)h_ret;
}

_HOOK_IMPL(int,DemuxBase_m_Demux_SICallback, u32* data) {
	//log("DemuxBase_m_Demux_SICallback, ra: %p, hmon=0x%08X, pid=0x%08X, buf=0x%08X, len=0x%08X\n", ra, SICallBackSettings_t[0], SICallBackSettings_t[1],SICallBackSettings_t[2],SICallBackSettings_t[3]);
	//void *ra;
	//asm("move %0, $ra\n" : "=r" (ra));

	_HOOK_DISPATCH(DemuxBase_m_Demux_SICallback, data);

	pmt_t *buf;

	u16 sid = 0x00;

	if ( data[3] > 0 ) {

		if ( be8((u8 *)data[2]) == 0x02 ) {

			sid = be16( ((u8*)data[2]) + 0x03 );

			if ( sid == 0x00 ) {
				return (int)h_ret;
			}

			if ( sid == g_SID && g_send_PMT_required == 1 ) {
				buf = malloc(sizeof(pmt_t));
				buf->sid = sid;
				buf->lm = PMT_LIST_FIRST | PMT_LIST_LAST;
				buf->len = be8(((u8*)data[2]) + 0x02) + 0x03 - 0x0A;
				buf->ptr = malloc(buf->len);
				memcpy(buf->ptr, ((u8*)data[2]) + 0x0A , buf->len);
				socket_send_pm_table(buf);
				g_send_PMT_required = 0;
			}

		} else {
			demux_filter_t *filter;
			LL_SEARCH_SCALAR(g_demux_filter, filter, monHandle, data[0]);
			if ( filter ) {
				log(">> EMM%02x ... hmon:0x%08x send data\n", be8((u8 *)data[2]), data[0]);
				socket_send_filter_data( filter->demuxId, filter->filterId, ((u8*)data[2]) , data[3] );
			}
		}
	}

	return (int)h_ret;
}

//const int (*TCCIMManagerBase_HostChannelChangeCompleted)(u32 this, u32 TCChannel, u32 a3, u32 TCCIM_SRouteInformation, u32 ECAStateType);
_HOOK_IMPL(int, TCCIMManagerBase_HostChannelChangeCompleted, u32 this, u32 TCChannel, u32 a3, u32 ESource, u32 a5) {
	//void *ra;
	//asm("move %0, $ra\n" : "=r" (ra));
	log("TCCIMManagerBase_HostChannelChangeCompleted, this: 0x%08x tcchannel: 0x%08x a3: 0x%08x esource: 0x%08x a5: 0x%08x\n",this,TCChannel,a3,ESource,a5);
	_HOOK_DISPATCH(TCCIMManagerBase_HostChannelChangeCompleted, this, TCChannel, a3, ESource, a5);

	if ( TCChannel != 0x00 ) {
		int sid = api_callbacks.ProgramNumber( (void *) TCChannel);
		if ( g_SID != sid ) {

			if ( g_hDesc != 0 ) {
				api_callbacks.spITsd_DescramblerDeallocate(g_hDesc, g_DscmbId);
			}

			g_SID = sid;
			g_send_PMT_required = 1;
			g_SourceId = api_callbacks.TPASource_Id();

			log("Source id=%d\n", g_SourceId);

			u32 all_res = api_callbacks.spITsd_DescramblerAllocate(g_hDesc, g_SourceId, &g_DscmbId);
			log("spITsd_DescramblerAllocate(0x%08x,...)=%d, g_u32DscmbID=0x%08x\n", g_hDesc, all_res, g_DscmbId);

			/*TODO: Where comes the value  0x450E2B1C from and how is this fitting to DMX_HANDLE 0x03D3407C */
			all_res = api_callbacks.spITsd_DescramblerLinkToDmx(g_hDesc, g_DscmbId, 0x450E2B1C);
			log("spITsd_DescramblerLinkToDmx(0x%08x, 0x%08x, 0x450E2B1C)=%d\n", g_hDesc, g_DscmbId, all_res);
			log("Service id changes, new SID: 0x%04x\n", g_SID);
		}
	}

	return (int)h_ret;
}

STATIC dyn_fn_t TCCIMManagerBase_func_table[] = {
		{ 0, "_ZN11TDsSamDemux17m_DemuxSICallbackEPN8CDiDemux20SICallBackSettings_tE" },
		{ 0, "_ZN16TCCIMManagerPlus13ChannelChangeEPK9TCChannelP12TCSourceConf" },
		{ 0, "_Z13SdDemux_Startj13SdDemux_Out_k" },
		{ 0, "_Z12SdDemux_Stopj13SdDemux_Out_k" },
};

STATIC hook_entry_t TCCIMManagerBase_hooks[] =
{
#define _HOOK_ENTRY(F, I) \
		&hook_##F, &TCCIMManagerBase_func_table[I], &x_##F
		{ _HOOK_ENTRY(DemuxBase_m_Demux_SICallback, __COUNTER__) },
		{ _HOOK_ENTRY(TCCIMManagerBase_HostChannelChangeCompleted, __COUNTER__) },
		{ _HOOK_ENTRY(SdAVDec_DemuxStart, __COUNTER__) },
		{ _HOOK_ENTRY(SdAVDec_DemuxStop, __COUNTER__) },
#undef _HOOK_ENTRY
};


//////////////////////////////////////////////////////////////////////////////

int dvbapi_install(void *h) {
	int res = 0;

	log("Install "LIB_TV_MODELS" lib"LIB_NAME" "LIB_VERSION" - "BUILD_GIT_TIME" (c) harlequin 2016\n");

	samyGO_whacky_t_init(h, &api_callbacks, ARRAYSIZE(api_callbacks.procs));

	if ( dyn_sym_tab_init(h, TCCIMManagerBase_func_table, ARRAYSIZE(TCCIMManagerBase_func_table)) >= 0 ) {
		set_hooks(TCCIMManagerBase_hooks, ARRAYSIZE(TCCIMManagerBase_hooks));
		res = 1;
	}

	u32 value = api_callbacks.spITsd_Open(0, &g_hDesc);
	log("spITsd_Open=%d, g_hDesc = 0x%08x\n", value, g_hDesc);

	return res;
}

int dvbapi_server_info(void) {
	//g_SID = -1;

	u8 channel[0x20];
	u32 source = 0; /*TODO Check if source is live tv  0x00 */
	api_callbacks.GetSource(*api_callbacks.g_pAppWindow, &source, 0x01);
	api_callbacks.TCChannel_Create(channel);
	api_callbacks.GetTvChannel(*api_callbacks.g_pAppWindow, channel, 0x01);
	/*TODO: Implement descriptor stuff and check if scrambled */
	//int scrambled = api_callbacks.FlagScrambled(channel);
	//if ( scrambled != 0) {
		api_callbacks.SetChannelQuiet(*api_callbacks.g_pAppWindow, channel, 0x01);
	//}

	return 0;
}

int dvbapi_set_descriptor(ca_descr_t ca_descr) {
	g_fltDscmb = api_callbacks.spITsd_DescramblerSetKey(g_hDesc, g_DscmbId, ca_descr.parity, ca_descr.cw, 8);
	log("spITsd_DescramblerSetKey(0x%08x, 0x%08x, 0x%02x, ...)=%d\n",  g_hDesc, g_DscmbId, ca_descr.parity, g_fltDscmb);
	return g_fltDscmb;
}

int dvbapi_start_filter(u8 demux_index, u8 filter_num, struct dmx_sct_filter_params params){
	/* This pid zero still occurs because the pmt is not send correctly */
	if ( ntohs(params.pid) != 0x00 ) {
		demux_filter_t *filter;

		LL_SEARCH_SCALAR(g_demux_filter, filter, filterId, filter_num );
		if(!filter) {
			filter = malloc(sizeof(demux_filter_t));
			filter->tableId = -1;
			filter->filterId = filter_num;
			filter->demuxId = demux_index;
			filter->monHandle = -1;
			LL_APPEND(g_demux_filter, filter);
		}

		if (filter->monHandle != -1) {
			u32 ret = api_callbacks.SdTSData_StopMonitor(g_dmxHandle, filter->monHandle);
			log("EMM%02X monitor stopped, dmxHandle=0x%08x, monHandle=0x%08x, ret=0x%08x\n",filter->tableId, g_dmxHandle, filter->monHandle, ret);
			filter->monHandle = -1;
			filter->tableId = -1;
		}

		g_emmParams.pid = ntohs(params.pid);
		memcpy(g_emmParams.filter, params.filter.filter, FILTER_MASK_SIZE);
		memcpy(g_emmParams.mask, params.filter.mask, FILTER_MASK_SIZE);

		filter->tableId = params.filter.filter[0];
		filter->demuxId = demux_index;
		filter->filterId = filter_num;
		filter->monHandle = api_callbacks.SdTSData_StartMonitor(DMX_HANDLE_LIVE, &g_emmParams);
		log("EMM%02x monitor started, dmxHandle=0x%08x, monHandle=0x%08x\n",filter->tableId, g_dmxHandle, filter->monHandle);
	}
	return 0;
}
