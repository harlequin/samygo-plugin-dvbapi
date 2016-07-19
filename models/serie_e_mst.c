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

static u32 g_send_PMT_required = 0;
static demux_filter_t *g_demux_filter = NULL;
static int g_SID = 0;
static int g_fltDscmb = 0;
static unsigned int g_dmxHandle = DMX_HANDLE_LIVE;
static SdTSData_Settings_t g_dmxParams;
static s32 g_dmxMonHandle = -1;
static s32 g_dmxTableId = -1;

static SdTSData_Settings2_t g_emmParams;

typedef union {
	const void *procs[17];
	struct	{
		// libSDAL.so
		int (*SdTSData_StartMonitor)(unsigned int dmxHandle, void* dmxParams, unsigned int eDataType);
		int (*SdTSData_StopMonitor)(unsigned int dmxHandle, unsigned int monHandle);

		// libUTOPIA.so
		int (*MDrv_DSCMB2_FltAlloc)(unsigned int u32DscmbID);	// u32DscmbID = 0
		int (*MDrv_DSCMB2_FltFree)(unsigned int u32DscmbID, unsigned int filterId);
		int (*MDrv_DSCMB2_FltConnectFltId)(unsigned int u32DscmbID, unsigned int filterId, unsigned int fltId);
		int (*MDrv_DSCMB2_FltTypeSet)(unsigned int u32DscmbID, unsigned int filterId, unsigned int type); // type = 0
		int (*MDrv_DSCMB2_FltKeySet)(unsigned int u32DscmbID, unsigned int filterId, unsigned int parity, unsigned char* cw);  // parity: even = 1, odd = 2
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
	};

} api_callbacks_t;

api_callbacks_t api_callbacks = {{
		(const void*)"_Z21SdTSData_StartMonitorjP19SdTSData_Settings_tj",
		(const void*)"_Z20SdTSData_StopMonitorjj",

		(const void*)"MDrv_DSCMB2_FltAlloc",
		(const void*)"MDrv_DSCMB2_FltFree",
		(const void*)"MDrv_DSCMB2_FltConnectFltId",
		(const void*)"MDrv_DSCMB2_FltTypeSet",
		(const void*)"MDrv_DSCMB2_FltKeySet",
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
}};

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

	g_dmxMonHandle = api_callbacks.SdTSData_StartMonitor(DMX_HANDLE_LIVE, &g_dmxParams, 0);
	log("ECM%02x monitor restarted, dmxHandle=0x%08x, monHandle=0x%08x\n",g_dmxTableId, g_dmxHandle, g_dmxMonHandle);
}




_HOOK_IMPL(int,SdAVDec_DemuxStop, unsigned int dmxHandle, int eDemuxOut) {
	log("SdAVDec_DemuxStop, dmxHandle=0x%08X, eDemuxOut=0x%08X\n", dmxHandle, eDemuxOut);
	log("g_dmxHandle=0x%08X\n", g_dmxHandle);
	demux_filter_t *filter = NULL;
	LL_FOREACH(g_demux_filter, filter) {
		api_callbacks.SdTSData_StopMonitor(DMX_HANDLE_LIVE, filter->monHandle);
		socket_send_stop(filter->demuxId);
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

_HOOK_IMPL(int,DemuxBase_m_Demux_SICallback, SICallBackSettings_t* data) {
	//log("DemuxBase_m_Demux_SICallback, ra: %p, hmon=0x%08X, pid=0x%08X, buf=0x%08X, len=0x%08X\n", ra, SICallBackSettings_t[0], SICallBackSettings_t[1],SICallBackSettings_t[2],SICallBackSettings_t[3]);
	//void *ra;
	//asm("move %0, $ra\n" : "=r" (ra));

	_HOOK_DISPATCH(DemuxBase_m_Demux_SICallback, data);
	model_demuxbase_demux(data, g_SID, g_demux_filter);
	return (int)h_ret;
}

_HOOK_IMPL(int, SdDemux_Allocate, unsigned int *pDmxHndl, int eSrc, int eDemuxType, int eDemuxOut, int bEnableRealloc) {
	_HOOK_DISPATCH(SdDemux_Allocate, pDmxHndl, eSrc, eDemuxType, eDemuxOut, bEnableRealloc);
	//log("SdDemux_Allocate, pDmxHndl=0x%08X, eSrc=%d, eDemuxType=%d, eDemuxOut=%d, bEnableRealloc=%d, eMainChip=%d\n", *pDmxHndl, eSrc, eDemuxType, eDemuxOut, bEnableRealloc, eMainChip);
	if(*pDmxHndl == 0x19800620) {
		api_callbacks.msAPI_DMX_Init();
	}

	return (int)h_ret;
}

_HOOK_IMPL(int, TCCIMManagerPlus_ChannelChange, void* this, void* TCChannel, unsigned int *TCSourceConf) {
	_HOOK_DISPATCH(TCCIMManagerPlus_ChannelChange, this, TCChannel, TCSourceConf);

	if(TCChannel == 0) return (int)h_ret;

	int sourceid = TCSourceConf[2] < 0xFFFF ? TCSourceConf[2] : TCSourceConf[1] ; 	// sourceid at index 2 on some fw versions

	log("Source id=%d\n", sourceid);

	if(sourceid == 53 || sourceid == 78)
	{
		int sId = api_callbacks.TCChannel_ProgramNumber(TCChannel);
		log("Service changed, new sId=0x%04X\n", sId);

		int dmxIndex = sourceid == 53 ? 0 : sourceid == 78 ? 1 : 2;
		g_SID = sId;
		//g_demux[dmxIndex].serviceId = sId;
		g_send_PMT_required = 1;
		//g_send_PMT = 1;

		if(dmxIndex == 0 /*&& g_demux[1].serviceId == -1*/)
		{
			for(int i = 0; i < 16; i++)
				api_callbacks.MDrv_DSCMB2_FltFree(0, i);

			for(int i = 0; i < 16; i++)
			{
				api_callbacks.MDrv_DSCMB2_FltAlloc(0);
				api_callbacks.MDrv_DSCMB2_FltConnectFltId(0, i, 16 + i);
				api_callbacks.MDrv_DSCMB2_FltTypeSet(0, i, 0);
			}
		}
	}
	return (int)h_ret;
}

STATIC dyn_fn_t TCCIMManagerBase_func_table[] = {
		{ 0, "_ZN13TDsPrimeDemux15t_DemuxCallbackEPN8CDiDemux20SICallBackSettings_tE" },
		{ 0, "_ZN9TCCAMConf13ChannelChangeEP9TCChannelP12TCSourceConf" },
		{ 0, "_Z13SdDemux_Startj13SdDemux_Out_k" },
		{ 0, "_Z12SdDemux_Stopj13SdDemux_Out_k" },
		{ 0, "_Z16SdDemux_AllocatePj10SdSource_k14SdDemux_Type_k13SdDemux_Out_ki"},
};

STATIC hook_entry_t TCCIMManagerBase_hooks[] =
{
#define _HOOK_ENTRY(F, I) \
		&hook_##F, &TCCIMManagerBase_func_table[I], &x_##F
		{ _HOOK_ENTRY(DemuxBase_m_Demux_SICallback, __COUNTER__) },
		{ _HOOK_ENTRY(TCCIMManagerPlus_ChannelChange, __COUNTER__) },
		{ _HOOK_ENTRY(SdAVDec_DemuxStart, __COUNTER__) },
		{ _HOOK_ENTRY(SdAVDec_DemuxStop, __COUNTER__) },
		{ _HOOK_ENTRY(SdDemux_Allocate, __COUNTER__) },
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

	return res;
}

int dvbapi_server_info(void) {
	int source = 0;

	api_callbacks.TCWindow_GetSource(*api_callbacks.g_pAppWindow, &source, 1);
	if(source == 0) {
		unsigned char channel[32] = {0};

		api_callbacks.TCChannel_Create(channel);
		api_callbacks.TCWindow_GetTVChannel(*api_callbacks.g_pAppWindow, channel, 1);

		for(int i = 0; i < api_callbacks.TCChannel_SizeOfDescriptor(channel); i++) {
			if(api_callbacks.TCChannel_Descriptor(channel, 9, i)) {
				api_callbacks.TCWindow_SetChannelQuiet(*api_callbacks.g_pAppWindow, channel, 1);
				break;
			}
		}
		api_callbacks.TCChannel_Destroy(channel);
	}
	return 0;
}

int dvbapi_set_descriptor(ca_descr_t ca_descr) {
	//log("Got CA_SET_DESCR request, adapter=%d, idx=%d, cw parity=%d\n", adapter_index, ca_descr.index, ca_descr.parity);
	//if((adapter_index == 0 && g_demux[1].serviceId == -1) || adapter_index == 1)
	for(int i = 0; i < 16; i++) {
		g_fltDscmb = api_callbacks.MDrv_DSCMB2_FltKeySet(0, i, ca_descr.parity + 1, ca_descr.cw);
		//log("MDrv_DSCMB_FltKeySet=%d g_fltDscmb=%d\n",  g_fltDscmb, g_fltDscmb);
	}

	return g_fltDscmb;
}

void dvbapi_dmx_stop(u8 demux_index, u8 filter_num, u16 pid) {
	demux_filter_t *filter;
	log("DVBAPI_DMX_STOP request, pid=%X, demux_idx=%d, filter_num=%d\n", pid, demux_index, filter_num);
	LL_SEARCH_SCALAR(g_demux_filter, filter, filterId, filter_num);
	if(filter) {
		u32 res = api_callbacks.SdTSData_StopMonitor( g_dmxHandle, filter->monHandle & 0x7FFFFFFF );
		log("Monitor stopped, idx=0x%02X, flt=0x%02X, dmxHandle=0x%08X, monHandle=0x%08X, ret=0x%08X\n", demux_index, filter_num, g_dmxHandle, filter->monHandle & 0x7FFFFFFF, res);
	}
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

		g_emmParams.pid = params.pid;

		g_emmParams.data_type = 0;
		g_emmParams.bCRC_check = 0;
		g_emmParams.filter_type = 1;
		g_emmParams.filter_len = DMX_FILTER_SIZE;

		memset(g_emmParams.filter, 0, DMX_FILTER_SIZE);
		memset(g_emmParams.mask, 0, DMX_FILTER_SIZE);
		memset(g_emmParams.mode, 0, DMX_FILTER_SIZE);

		memcpy(g_emmParams.filter, params.filter.filter, DMX_FILTER_SIZE);
		memcpy(g_emmParams.mask, params.filter.mask, DMX_FILTER_SIZE);

		filter->tableId = params.filter.filter[0];
		filter->demuxId = demux_index;
		filter->filterId = filter_num;


		filter->monHandle = api_callbacks.SdTSData_StartMonitor(DMX_HANDLE_LIVE, &g_emmParams,0);
		log("EMM%02x monitor started, dmxHandle=0x%08x, monHandle=0x%08x\n",filter->tableId, g_dmxHandle, filter->monHandle);
	}
	return 0;
}
