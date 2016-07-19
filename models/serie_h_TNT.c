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

static int g_send_PMT_required = 0;
static int g_SID = 0;
static int g_fltDscmb = 0;
static unsigned int g_dmxHandle = 0;
static demux_filter_t *g_demux_filter = NULL;
static SdTSData_Settings2_t g_emmParams;

static u32 g_hDesc = 0;
static u32 g_DescId = 0;

#define CWB 	6

typedef struct {
	unsigned char au8EvenCW[8];                 /*!< Odd control word                           */
	unsigned char au8OddCW[8];                  /*!< Even control word                          */
}ST_DRV_TSPU_DESC_CWB_DVB_CSA_PARAMS, *PST_DRV_TSPU_DESC_CWB_DVB_CSA_PARAMS;

typedef struct {
	unsigned char b8DefaultCWEnable;                                          /*!< Enable Default control word            */
	unsigned char au8DefaultCW[8];              /*!< Default control word                   */
}ST_DRV_TSPU_DESC_MODE_DVB_CSA_PARAMS, *PST_DRV_TSPU_DESC_MODE_DVB_CSA_PARAMS;

typedef struct {
	int           enDescMode;                                                 /*!< DESC operation mode            */
	union {
		ST_DRV_TSPU_DESC_MODE_DVB_CSA_PARAMS        stDvbCsaParams;                             /*!< DVB CSA Parameters             */
	} unCfg;
}ST_DRV_TSPU_DESC_CFG_PARAMS, *PST_DRV_TSPU_DESC_CFG_PARAMS;

typedef struct {
	unsigned int u32DpHandle;												/*!< reserve for futher use                                         */
}ST_DRV_TSPU_DESC_PID_OPEN_PARAMS, *PST_DRV_TSPU_DESC_PID_OPEN_PARAMS;

typedef struct {
	unsigned short u16PidPattern;                                              /*!< PID Pattern value                  */
	int            enCWB;                                                      /*!< Control Word Bank Value            */
	int			   enLayer;                                                    /*!< encrypted layer TS/PES             */
}ST_DRV_TSPU_DESC_PID_CFG_PARAMS, *PST_DRV_TSPU_DESC_PID_CFG_PARAMS;


typedef union {
	const void *procs[23];
	struct	{
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

} api_callbacks_t;

api_callbacks_t api_callbacks = {
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

_HOOK_IMPL(int,DemuxBase_m_Demux_SICallback, SICallBackSettings_t* data) {
	_HOOK_DISPATCH(DemuxBase_m_Demux_SICallback, data);
	model_demuxbase_demux(data, g_SID, g_demux_filter);
	return (int)h_ret;
}

_HOOK_IMPL(int, TCCIMManagerBase_HostChannelChangeCompleted, u32 this, u32 TCChannel, u32 *TCSourceConf) {
	_HOOK_DISPATCH(TCCIMManagerBase_HostChannelChangeCompleted, this, TCChannel, TCSourceConf);

	if ( TCChannel != 0x00 ) {
		int sid = api_callbacks.TCChannel_ProgramNumber( (void *) TCChannel);
		if ( g_SID != sid ) {
			g_SID = sid;

			ST_DRV_TSPU_DESC_CFG_PARAMS pstCfgParams;
			memset(&pstCfgParams, 0, sizeof(ST_DRV_TSPU_DESC_CFG_PARAMS));

			pstCfgParams.enDescMode = 1;

			int dpHandle = -1;
			log("PLAT_TSPU_GetDpHandleByDemuxHdl=0x%08X, g_dmxHandle=0x%08X, dpHandle=0x%08X\n", api_callbacks.PLAT_TSPU_GetDpHandleByDemuxHdl(g_dmxHandle, &dpHandle), g_dmxHandle, dpHandle);

			log("DRV_TSPU_DESC_CWB_Disable=0x%08X\n", api_callbacks.DRV_TSPU_DESC_CWB_Disable(dpHandle, CWB));
			log("DRV_TSPU_DESC_Config=0x%08X\n", api_callbacks.DRV_TSPU_DESC_Config( dpHandle, &pstCfgParams ));
			log("DRV_TSPU_DESC_CWB_Enable=0x%08X\n", api_callbacks.DRV_TSPU_DESC_CWB_Enable(dpHandle, CWB));

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

	log("spITsd_Open=%d, g_hDesc = 0x%08X\n", api_callbacks.spITsd_Open(0, 4096, &g_hDesc), g_hDesc);

	return res;
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
	return 0;
}

int dvbapi_set_descriptor(ca_descr_t ca_descr) {
	g_fltDscmb = api_callbacks.spITsd_DescramblerSetKey(g_hDesc, g_DescId, ca_descr.parity, ca_descr.cw, 8);
	log("spITsd_DescramblerSetKey(0x%08X, 0x%08X, 0x%02X, ...)=%d\n",g_hDesc,g_DescId, ca_descr.parity, g_fltDscmb);
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
			u32 ret = api_callbacks.SdTSData_StopMonitor(g_dmxHandle, filter->monHandle,0 );
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
		filter->monHandle = api_callbacks.SdTSData_StartMonitor(g_dmxHandle, &g_emmParams,0 ,0);
		log("EMM%02x monitor started, dmxHandle=0x%08x, monHandle=0x%08x\n",filter->tableId, g_dmxHandle, filter->monHandle);
	}
	return 0;
}

