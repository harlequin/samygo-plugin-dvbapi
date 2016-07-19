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

typedef struct DEMUX_FILTER {
	u16 tableId;
	s32 monHandle;
	u8 demuxId;
	u8 filterId;
	struct DEMUX_FILTER *next;
} demux_filter_t;

static int g_send_PMT_required = 0;
static int g_SID = 0;
static unsigned int g_dmxHandle = 0;
static demux_filter_t *g_demux_filter = NULL;
static SdTSData_Settings2_t g_emmParams;

typedef union {
	const void *procs[14];
	struct	{
		const int (*SdTSData_StartMonitor)(u32 dmx_handle, SdTSData_Settings2_t *a1, u32 eDataType, u32 SdMainChip_k);
		const int (*SdTSData_StopMonitor)(u32 dmx_handle, u32 mon_handle, u32 SdMainChip_k);

		// libUTOPIA.so
		uint32_t *gDSCMB_BUFF;
		int (*NW_TZ_DSCMB_FUNC)(int TZ_DSCMB_CMD);

		void* (*TCAPI_GetWindow)(int arg1);
		const int (*TCWindowImpl_GetSource)(void *window, int *source, int a2);
		const int (*TCWindowImpl_GetTVChannel)(void *window, void *channel, int arg3);
		const int (*TCWindowImpl_SetChannelQuiet)(void *window, void *channel, int arg3);
		const int (*TCChannel_Create)(void *channel);
		const int (*TCChannel_Destroy)(void *channel);
		const int (*TCChannel_ProgramNumber)(void *channel);
		const int (*TCChannel_SizeOfDescriptor)(void *channel);
		const int (*TCChannel_Descriptor)(void *channel, int nine, int desc);
		const int (*TPASource_Id)(void *this);
	};

} api_callbacks_t;

api_callbacks_t api_callbacks = {
		(const void*)"_Z21SdTSData_StartMonitorjP19SdTSData_Settings_tj12SdMainChip_k",
		(const void*)"_Z20SdTSData_StopMonitorjj12SdMainChip_k",

		(const void*)"gDSCMB_BUFF",
		(const void*)"_Z16NW_TZ_DSCMB_FUNC12TZ_DSCMB_CMD",

		(const void*)"_ZN5TCAPI9GetWindowEN8TCWindow7EWindowE",
		(const void*)"_ZN12TCWindowImpl9GetSourceEPii",
		(const void*)"_ZN12TCWindowImpl12GetTVChannelEP9TCChanneli",
		(const void*)"_ZN12TCWindowImpl15SetChannelQuietEPK9TCChannelb",
		(const void*)"_ZN9TCChannelC2Ev",
		(const void*)"_ZN9TCChannelD2Ev",
		(const void*)"_ZNK9TCChannel13ProgramNumberEv",
		(const void*)"_ZNK9TCChannel16SizeOfDescriptorEv",
		(const void*)"_ZNK9TCChannel10DescriptorEii",
		(const void*)"_ZN9TPASource2IdEv",
};

//////////////////////////////////////////////////////////////////////////////
// HELPER FUNCTIONS
//////////////////////////////////////////////////////////////////////////////
int NW_TZ_DSCMB_FUNC(int TZ_DSCMB_CMD) {
	return api_callbacks.NW_TZ_DSCMB_FUNC(TZ_DSCMB_CMD);
}

static uint32_t F_MDrv_DSCMB2_FltAlloc(int unused) {
	NW_TZ_DSCMB_FUNC(2);
	return (uint32_t)*api_callbacks.gDSCMB_BUFF;
}

static uint32_t F_MDrv_DSCMB2_FltConnectFltId(int unused, uint32_t allocatedFilter, int filterNumber) {
	api_callbacks.gDSCMB_BUFF[0]=allocatedFilter;
	api_callbacks.gDSCMB_BUFF[1]=filterNumber;
	return NW_TZ_DSCMB_FUNC(6);
	//return *hCTX.gDSCMB_BUFF;
}

static uint32_t F_MDrv_DSCMB2_FltTypeSet(int unused, uint32_t allocatedFilter, int pDscmbType) {
	api_callbacks.gDSCMB_BUFF[0]=allocatedFilter;
	api_callbacks.gDSCMB_BUFF[8]=pDscmbType;
	return NW_TZ_DSCMB_FUNC(3);
	//return *hCTX.gDSCMB_BUFF;
}

static uint32_t F_MDrv_DSCMB2_FltKeySet(int unused, uint32_t allocatedFilter, int oddOrEven, uint32_t *keyTable) {
	api_callbacks.gDSCMB_BUFF[0]=allocatedFilter;
	api_callbacks.gDSCMB_BUFF[3]=keyTable[0];
	api_callbacks.gDSCMB_BUFF[4]=keyTable[1];
	api_callbacks.gDSCMB_BUFF[5]=keyTable[2];
	api_callbacks.gDSCMB_BUFF[6]=keyTable[3];
	api_callbacks.gDSCMB_BUFF[7]=oddOrEven;
	return NW_TZ_DSCMB_FUNC(4);
	//return *hCTX.gDSCMB_BUFF;
}
static uint32_t F_MDrv_DSCMB2_FltIVSet(int unused, uint32_t allocatedFilter, int oddOrEven, uint32_t *ivTable) {
	api_callbacks.gDSCMB_BUFF[0]=allocatedFilter;
	api_callbacks.gDSCMB_BUFF[3]=ivTable[0];
	api_callbacks.gDSCMB_BUFF[4]=ivTable[1];
	api_callbacks.gDSCMB_BUFF[5]=ivTable[2];
	api_callbacks.gDSCMB_BUFF[6]=ivTable[3];
	api_callbacks.gDSCMB_BUFF[7]=oddOrEven;
	return NW_TZ_DSCMB_FUNC(5);
	//return *hCTX.gDSCMB_BUFF;
}

static uint32_t F_MDrv_DSCMB2_FltConnectPid(int unused, uint32_t allocatedFilter, uint32_t u32Pid) {
	api_callbacks.gDSCMB_BUFF[0]=allocatedFilter;
	api_callbacks.gDSCMB_BUFF[2]=u32Pid;
	NW_TZ_DSCMB_FUNC(7);
	//return *hCTX.gDSCMB_BUFF;
	//it looks here not the first element of array is used...
	return api_callbacks.gDSCMB_BUFF[9];
}

static uint32_t F_MDrv_DSCMB2_FltFree(int unused, int u32DscmbId) {
	api_callbacks.gDSCMB_BUFF[0]=u32DscmbId;
	return NW_TZ_DSCMB_FUNC(1);
	//return (uint32_t)*hCTX.gDSCMB_BUFF;
}

static uint32_t F_MDrv_DSCMB2_FltDisconnectPid(int unused, uint32_t u32DscmbId, uint32_t u32Pid) {
	api_callbacks.gDSCMB_BUFF[0]=u32DscmbId;
	api_callbacks.gDSCMB_BUFF[2]=u32Pid;
	return NW_TZ_DSCMB_FUNC(8);
	///return (uint32_t)*hCTX.gDSCMB_BUFF;
}

_HOOK_IMPL(int,SdAVDec_DemuxStop, unsigned int dmxHandle, int eDemuxOut) {
	log("SdAVDec_DemuxStop, dmxHandle=0x%08X, eDemuxOut=0x%08X\n", dmxHandle, eDemuxOut);
	_HOOK_DISPATCH(SdAVDec_DemuxStop, dmxHandle, eDemuxOut);
	g_dmxHandle = dmxHandle;
	log("g_dmxHandle=0x%08X\n", g_dmxHandle);
	return (int)h_ret;
}

_HOOK_IMPL(int,SdAVDec_DemuxStart, unsigned int dmxHandle, int eDemuxOut) {
	log("SdDemux_Start, dmxHandle=0x%08X, eDemuxOut=0x%08X\n", dmxHandle, eDemuxOut);
	g_dmxHandle = dmxHandle;
	log("g_dmxHandle=0x%08X\n", g_dmxHandle);
	_HOOK_DISPATCH(SdAVDec_DemuxStart, dmxHandle, eDemuxOut);
	return (int)h_ret;
}

_HOOK_IMPL(int,DemuxBase_m_Demux_SICallback, u32* data) {
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
				buf->len = data[2];
				buf->ptr = malloc(buf->len);
				memcpy(buf->ptr, (u8*)data[2], buf->len);
				socket_send_capmt(buf);
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

_HOOK_IMPL(int, TCCIMManagerBase_HostChannelChangeCompleted, u32 this, u32 TCChannel, u32 *TCSourceConf) {
	u32 i;
	_HOOK_DISPATCH(TCCIMManagerBase_HostChannelChangeCompleted, this, TCChannel, TCSourceConf);

	if ( TCChannel != 0x00 ) {
		int sid = api_callbacks.TCChannel_ProgramNumber( (void *) TCChannel);
		if ( g_SID != sid ) {
			g_SID = sid;

			for(i = 0; i < 16; i++) {
				F_MDrv_DSCMB2_FltFree(0, i);
			}

			for(int i = 0; i < 16; i++)	{
				F_MDrv_DSCMB2_FltAlloc(0);
				F_MDrv_DSCMB2_FltConnectFltId(0, i, 16 + i);
				F_MDrv_DSCMB2_FltTypeSet(0, i, 0);
			}

			g_send_PMT_required = 1;
			log("Service id changes, new SID: 0x%04x\n", g_SID);
		}
	}

	return (int)h_ret;
}

STATIC dyn_fn_t TCCIMManagerBase_func_table[] = {
		{ 0, "_ZN9DemuxBase18m_Demux_SICallbackEPN8CDiDemux20SICallBackSettings_tE" },
		{ 0, "_ZN9TCCAMConf13ChannelChangeEPK9TCChannelP12TCSourceConf" },
		{ 0, "_Z13SdDemux_Startj13SdDemux_Out_k12SdMainChip_k" },
		{ 0, "_Z12SdDemux_Stopj13SdDemux_Out_k12SdMainChip_k" },
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

	return res;
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

int dvbapi_server_info(void) {
	int source = 0;

	api_callbacks.TCWindowImpl_GetSource(api_callbacks.TCAPI_GetWindow(0), &source, 1);
	if(source == 0) {
		u32 channel[32] = {0};

		api_callbacks.TCChannel_Create(channel);
		api_callbacks.TCWindowImpl_GetTVChannel(api_callbacks.TCAPI_GetWindow(0), channel, 1);

		for(int i = 0; i < api_callbacks.TCChannel_SizeOfDescriptor(channel); i++) {
				if(api_callbacks.TCChannel_Descriptor(channel, 9, i)) {
					api_callbacks.TCWindowImpl_SetChannelQuiet(api_callbacks.TCAPI_GetWindow(0), channel, 1);
					break;
				}
		}
		api_callbacks.TCChannel_Destroy(channel);
	}
}

int dvbapi_set_descriptor(ca_descr_t ca_descr) {
	u32 i;
	log("Got CA_SET_DESCR request, adapter=%d, idx=%d, cw parity=%d\n", 0, ca_descr.index, ca_descr.parity);
	for(int i = 0; i < 16; i++) {
		F_MDrv_DSCMB2_FltKeySet(0, i, ca_descr.parity + 1, (u32 *)ca_descr.cw);
	}
	return 0;
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
			u32 ret = api_callbacks.SdTSData_StopMonitor(g_dmxHandle, filter->monHandle,0 );
			log("EMM%02X monitor stopped, dmxHandle=0x%08x, monHandle=0x%08x, ret=0x%08x\n",filter->tableId, g_dmxHandle, filter->monHandle, ret);
			filter->monHandle = -1;
			filter->tableId = -1;
		}

		g_emmParams.pid = ntohs(params.pid);

		g_emmParams.data_type = 0;
		g_emmParams.bCRC_check = 0;
		g_emmParams.filter_type = 1;
		g_emmParams.filter_data_len = DMX_FILTER_SIZE;
		g_emmParams.filter = malloc(DMX_FILTER_SIZE);
		g_emmParams.mask = malloc(DMX_FILTER_SIZE);
		g_emmParams.mode = malloc(DMX_FILTER_SIZE);

		memset(g_emmParams.filter, 0, DMX_FILTER_SIZE);
		memset(g_emmParams.mask, 0, DMX_FILTER_SIZE);
		memset(g_emmParams.mode, 0, DMX_FILTER_SIZE);

		memcpy(g_emmParams.filter, params.filter.filter, DMX_FILTER_SIZE);
		memcpy(g_emmParams.mask, params.filter.mask, DMX_FILTER_SIZE);

		filter->tableId = params.filter.filter[0];
		filter->demuxId = demux_index;
		filter->filterId = filter_num;
		filter->monHandle = api_callbacks.SdTSData_StartMonitor(g_dmxHandle, &g_emmParams,0 ,0);
		log("EMM%02x monitor started, dmxHandle=0x%08x, monHandle=0x%08x\n",filter->tableId, g_dmxHandle, filter->monHandle);
	}
	return 0;
}
