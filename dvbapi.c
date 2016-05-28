/**
 * Copyright (c) 2016 harlequin
 * https://github.com/harlequin/samygo-plugin-dvbapi
 *
 * This file is part of samygo-plugin-dvbapi.
 * The project is based on following open-source projects:
 * vdr-plugin-dvbapi (manio): https://github.com/manio/vdr-plugin-dvbapi
 * libOSCAM v0.4.0 (bugficks): (sorry, cannot find URL with original code)
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
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <memory.h>
#include <glob.h>
#include <stdarg.h>
#include <pthread.h>
#include <execinfo.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h> /* socket handler */
#include <arpa/inet.h> /* inet_pton */

#include "version.h"


#include "hook.h"
#include "common.h"
#include "C_support.h"
#include "tv_info.h"
#include "utlist.h"
#include "types.h"
#include "util.h"

/* CONFIGURATION */
static u8* oscam_server_ip = NULL;
static u16 oscam_server_port = 0;
static u8 oscam_emm_enabled;

#define DMX_HANDLE_19800000	0x19800000
#define DMX_HANDLE_LIVE	0x19800620
#define DMX_HANDLE_PVR		0x19800621
#define DMX_HANDLE_UNKNOWN	0x19800622
#define DMX_HANDLE_PIP		0x19800623

static int tv_model = -1;
static int tv_type = -1;

static pthread_t x_thread_socket_handler;
static int g_send_PMT_required = 1;
static int g_SID = 0;
static int _hooked = 0;
static int g_fltDscmb = 0;
static unsigned int g_dmxHandle = DMX_HANDLE_LIVE;

static int g_pidVideo = 0x0;
static int g_pidAudio = 0x0;

typedef struct {
	/* 0 */ u32 pid;
	/* 1 */ u32 res;
	/* 2 */ u32 res2;
	/* 3 */ u32 filter;
	/* 4 */ u32 res3;
	/* 5 */ u32 res4;
	/* 6 */ u32 res5;
	/* 7 */ u8 mask[0x10];
} SdTSData_Settings_t;

static SdTSData_Settings_t g_dmxParams80;
static SdTSData_Settings_t g_dmxParams81;
static s32 g_monHandle81 = -1;
static s32 g_monHandle80 = -1;
static u8 g_80_demux_id;
static u8 g_80_filter_id;
static u8 g_81_demux_id;
static u8 g_81_filter_id;

static u8 socket_connected = 0x00; /* will be set to 1 if handshake was done */
static struct PMT *_pmt = NULL;
static int protocol_version = 0;
static u8 adapter_index;
static int sock;



typedef union {
	const void *procs[19];
	struct	{
		const int (*SdTSData_StartMonitor)(u32 dmx_handle, SdTSData_Settings_t *a1);
		const int (*SdTSData_StopMonitor)(u32 dmx_handle, u32 mon_handle);
		const int (*MDrv_DSCMB_Init)(void);
		void **g_pAppWindow;
		const int (*TCCIMManagerBase_HostChannelChangeCompleted)(u32 a1, u32 a2, u32 a3, u32 a4, u32 a5);
		const int (*GetSource) (void *window, int *source, int arg3);
		const int (*GetTvChannel)(void *window, void *channel, int arg3);
		const int (*SetChannelQuiet)(void *window, void *channel, int arg3);
		const void* (*TCChannel_Create)(void *channel);
		const void* (*TCChannel_Destroy)(void *channel);
		const int (*ProgramNumber)(void *this);
		const int (*FlagScrambled)(void *this);
		const int (*MDrv_DSCMB_FltDisconnectPid)(unsigned int u32DscmbId, unsigned int u32Pid);
		const int (*MDrv_DSCMB_FltFree)(unsigned int u32DscmbId);
		const int (*MDrv_DSCMB_FltConnectPid)(unsigned int u32DscmbId, unsigned int u32Pid);
		const int (*MDrv_DSCMB_FltTypeSet)(unsigned int u32DscmbId, unsigned int eType);
		const int (*MDrv_DSCMB_FltAlloc)(void);
		const int (*MDrv_DSCMB_FltKeySet)(u32 u32DscmbId, DSCMB_Key_Type eKeyType, u8 *pu8Key);
		const int (*SdAVDec_DemuxStart) (unsigned int dmxHandle, int eDemuxOut);
	};

} TCCIMManagerBase_t;

TCCIMManagerBase_t TCCIMManagerBase = {
	(const void*)"_Z21SdTSData_StartMonitorjP19SdTSData_Settings_tj",
	(const void*)"_Z20SdTSData_StopMonitorjj",
	(const void*)"MDrv_DSCMB_Init",
	(const void*)"g_pAppWindow",
	(const void*)"_ZN16TCCIMManagerBase26HostChannelChangeCompletedEP9TCChanneliN8TCWindow7ESourceE",
	(const void*)"_ZN8TCWindow9GetSourceEPii",
	(const void*)"_ZN8TCWindow12GetTVChannelEP9TCChanneli",
	(const void*)"_ZN8TCWindow15SetChannelQuietEPK9TCChannelb",
	(const void*)"_ZN9TCChannelC2Ev",
	(const void*)"_ZN9TCChannelD2Ev",
	(const void*)"_ZNK9TCChannel13ProgramNumberEv",
	(const void*)"_ZNK9TCChannel13FlagScrambledEv",
	(const void*)"MDrv_DSCMB_FltDisconnectPid",
	(const void*)"MDrv_DSCMB_FltFree",
	(const void*)"MDrv_DSCMB_FltConnectPid",
	(const void*)"MDrv_DSCMB_FltTypeSet",
	(const void*)"MDrv_DSCMB_FltAlloc",
	(const void*)"MDrv_DSCMB_FltKeySet",
	(const void*)"_Z18SdAVDec_DemuxStartj18SdAVDec_DemuxOut_k",
};



static void print_hash(u8 *ptr, u32 len){
	char buffer[1024] = "";
	u8 i = 0;

	while(len--) {
		sprintf(buffer,"%s %02x",buffer, *ptr++);
		if((++i % 16) == 0) {
			log("	%s\n", buffer);
			buffer[0] = '\0';
		}
	}
	log("	%s\n", buffer);

}



static void socket_send_filter_data(u8 demux_id, u8 filter_num, u8 *data, u32 len) {
	if(!socket_connected) {return;}
	log("send filter data demux_id: 0x%02x filter_num: 0x%02x\n", demux_id, filter_num);
	//log(">>>\n"); print_hash(data, len); log("<<<\n");
	unsigned char buff[6 + len];
	u32 req = htonl(DVBAPI_FILTER_DATA);
	memcpy(&buff[0], &req, 4);
	buff[4] = demux_id;
	buff[5] = filter_num;
	memcpy(buff + 6, data, len);
	write(sock, buff, sizeof(buff));

}

static void socket_send_client_info() {
	int len = sizeof(INFO_VERSION) - 1;					//ignoring null termination
	unsigned char buff[7 + len];
	u32 req = htonl(DVBAPI_CLIENT_INFO);				//type of request
	memcpy(&buff[0], &req, 4);
	u16 proto_version = htons(DVBAPI_PROTOCOL_VERSION);	//supported protocol version
	memcpy(&buff[4], &proto_version, 2);
	buff[6] = len;
	memcpy(&buff[7], &INFO_VERSION, len);				//copy info string
	write(sock, buff, sizeof(buff));
}

static void socket_send_pm_table(pmt_t *pmt) {
	if(!socket_connected) {return;}

	if ( pmt->len == 0){return;}
	u8 offset = 0x0A;
	u8 caPMT[pmt->len + offset];

	u32 mod_len = pmt->len + 4;

	caPMT[0] = 0x9F;
	caPMT[1] = 0x80;
	caPMT[2] = 0x32;
	caPMT[3] = 0x82;
	caPMT[4] = mod_len >> 0x08;
	caPMT[5] = mod_len & 0xFF;
	caPMT[6] = pmt->lm & 0xFF;
	caPMT[7] = pmt->sid >> 0x08;
	caPMT[8] = pmt->sid & 0xFF;
	caPMT[9] = 0;

	memcpy(caPMT + offset, pmt->ptr, pmt->len);
	//print_hash((u8*)caPMT, pmt->len + offset);
	write(sock, caPMT, pmt->len + offset);
}

static void stopMonitors() {
	u32 ret;

	if (g_monHandle80 >= 0) {
		ret = TCCIMManagerBase.SdTSData_StopMonitor(g_dmxHandle, g_monHandle80);
		log("ECM80 monitor stopped, dmxHandle=0x%08x, monHandle=0x%08x, ret=0x%08x\n", g_dmxHandle, g_monHandle80, ret);
		g_monHandle80 = -1;
	}
	if (g_monHandle81 >= 0) {
		ret = TCCIMManagerBase.SdTSData_StopMonitor(g_dmxHandle, g_monHandle81);
		log("ECM81 monitor stopped, dmxHandle=0x%08x, monHandle=0x%08x, ret=0x%08x\n", g_dmxHandle, g_monHandle81, ret);
		g_monHandle81 = -1;
	}
}


static void changeMonitor(unsigned int dmxHandle) {
	stopMonitors();

	g_dmxHandle = dmxHandle;
	log("using dmxHandle=0x%08X\n", dmxHandle);

	if ( g_dmxParams80.pid != 0x00) {
		g_monHandle80 = TCCIMManagerBase.SdTSData_StartMonitor(DMX_HANDLE_LIVE, &g_dmxParams80);/*maybe add 0x00 as parameter*/
		log("ECM80 monitor restarted, dmxHandle=0x%08x, monHandle=0x%08x\n", g_dmxHandle, g_monHandle80);
	}

	if ( g_dmxParams81.pid != 0x00 ) {
		g_monHandle81 = TCCIMManagerBase.SdTSData_StartMonitor(DMX_HANDLE_LIVE, &g_dmxParams81);/*maybe add 0x00 as parameter*/
		log("ECM81 monitor restarted, dmxHandle=0x%08x, monHandle=0x%08x\n", g_dmxHandle, g_monHandle81);
	}
}




_HOOK_IMPL(int,SdAVDec_DemuxStop, unsigned int dmxHandle, int eDemuxOut) {
	log("SdAVDec_DemuxStop, dmxHandle=0x%08X, eDemuxOut=0x%08X\n", dmxHandle, eDemuxOut);
	log("g_dmxHandle=0x%08X\n", g_dmxHandle);

	switch (g_dmxHandle) {
		case DMX_HANDLE_LIVE:
			TCCIMManagerBase.SdTSData_StopMonitor(DMX_HANDLE_LIVE, 0x00);
			break;
		case DMX_HANDLE_PIP:
		case DMX_HANDLE_PVR:
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
	void *ra;
	asm("move %0, $ra\n" : "=r" (ra));

	_HOOK_DISPATCH(DemuxBase_m_Demux_SICallback, data);

	pmt_t *buf;

	u16 sid = 0x00;

	if ( data[3] > 0 ) {

		switch (be8((u8 *)data[2])) {
			case 0x02:
				sid = be16( ((u8*)data[2]) + 0x03 );
				LL_SEARCH_SCALAR(_pmt, buf, sid, sid);
				if ( !buf ) {
					//log("GOT PMT SID: 0x%04x\n", sid);
					buf = malloc(sizeof(pmt_t));
					//print_hash((u8*)data[2], data[3]);
					buf->sid = sid;
					buf->lm = PMT_LIST_FIRST | PMT_LIST_LAST;
					buf->len = be8(((u8*)data[2]) + 0x02) + 0x03 - 0x0A;
					buf->ptr = malloc(buf->len);
					memcpy(buf->ptr, ((u8*)data[2]) + 0x0A , buf->len);
					LL_APPEND(_pmt, buf);
					g_send_PMT_required = 1;
				}
				break;


			case 0x80:
				if ( data[3] < 0x400 ) {
					log("GOT ECM%02x\n", be8((u8 *)data[2]));
					if (g_monHandle80 != -1){
						socket_send_filter_data( g_80_demux_id, g_80_filter_id, ((u8*)data[2]), data[3] );
					}
				}
				break;
			case 0x81:
				if ( data[3] < 0x400 ) {
					log("GOT ECM%02x\n", be8((u8 *)data[2]));
					if (g_monHandle81 != -1){
						socket_send_filter_data( g_81_demux_id, g_81_filter_id, ((u8*)data[2]), data[3] );
					}
				}
				break;

			default:
				//print_hash((u8 *)data[2], data[3]);
				break;
		}

	}

	if(g_send_PMT_required == 1 && g_SID != 0x00) {
		LL_SEARCH_SCALAR(_pmt, buf, sid, g_SID);
		if ( buf ) {
			socket_send_pm_table(_pmt);
			g_send_PMT_required = 0;
		}
	}

	return (int)h_ret;
}

_HOOK_IMPL(int, TCCIMManagerBase_HostChannelChangeCompleted, u32 this, u32 TCChannel, u32 a3, u32 ESource, u32 a5) {
	void *ra;
	asm("move %0, $ra\n" : "=r" (ra));
	log("TCCIMManagerBase_HostChannelChangeCompleted, this: 0x%08x tcchannel: 0x%08x a3: 0x%08x esource: 0x%08x a5: 0x%08x\n",this,TCChannel,a3,ESource,a5);
	_HOOK_DISPATCH(TCCIMManagerBase_HostChannelChangeCompleted, this, TCChannel, a3, ESource, a5);

	if ( TCChannel != 0x00 ) {
		int sid = TCCIMManagerBase.ProgramNumber( (void *) TCChannel);
		if ( g_SID != sid ) {
			g_SID = sid;
			g_send_PMT_required = 1;
			log("Service id changes, new SID: 0x%04x\n", g_SID);
		}
	}

	return (int)h_ret;
}

_HOOK_IMPL(int,TCCIMManagerBase_SetAVPID, u32 a1, u32 pid_video, u32 pid_audio, u32 a4, u32 a5 /*u32 pidVideo, u32 pidAudio, unsigned int eWindow*/) {
	void *ra;
	asm("move %0, $ra\n" : "=r" (ra));
	log("TCCIMManagerBase_SetAVPID, ra:%p, a1: 0x%08x, a2: 0x%08x, a3: 0x%08x, a4: 0x%08x, a5: 0x%08x\n",ra, a1, pid_video, pid_audio, a4, a5);
	_HOOK_DISPATCH(TCCIMManagerBase_SetAVPID, a1, pid_video, pid_audio, a4, a5);

	u32 res;
	if (g_fltDscmb == 1) {
		TCCIMManagerBase.MDrv_DSCMB_FltDisconnectPid(0, pid_video);
		TCCIMManagerBase.MDrv_DSCMB_FltDisconnectPid(0, pid_audio);
		TCCIMManagerBase.MDrv_DSCMB_FltFree(0);
		g_fltDscmb = 0;
	}
	TCCIMManagerBase.MDrv_DSCMB_FltAlloc();
	res = TCCIMManagerBase.MDrv_DSCMB_FltConnectPid( 0, pid_video);
	log("MDrv_DSCMB_FltConnectPid=%d\n", res);
	res = TCCIMManagerBase.MDrv_DSCMB_FltConnectPid( 0, pid_audio);
	log("MDrv_DSCMB_FltConnectPid=%d\n", res);
	res = TCCIMManagerBase.MDrv_DSCMB_FltTypeSet(0, 0);
	log("MDrv_DSCMB_FltTypeSet=%d\n", res);

	return (int)h_ret;
}

STATIC dyn_fn_t TCCIMManagerBase_func_table[] = {
	{ 0, "_ZN13TDsPrimeDemux15t_DemuxCallbackEPN8CDiDemux20SICallBackSettings_tE" },
	{ 0, "_ZN16TCCIMManagerBase26HostChannelChangeCompletedEP9TCChanneliN8TCWindow7ESourceE" },
	{ 0, "_Z18SdAVDec_DemuxStartj18SdAVDec_DemuxOut_k" },
	{ 0, "_Z17SdAVDec_DemuxStopj18SdAVDec_DemuxOut_k" },
	{ 0, "_ZN16TCCIMManagerBase8SetAVPIDEiii"},	
};

STATIC hook_entry_t TCCIMManagerBase_hooks[] =
{
#define _HOOK_ENTRY(F, I) \
	&hook_##F, &TCCIMManagerBase_func_table[I], &x_##F
	{ _HOOK_ENTRY(DemuxBase_m_Demux_SICallback, __COUNTER__) },
	{ _HOOK_ENTRY(TCCIMManagerBase_HostChannelChangeCompleted, __COUNTER__) },
	{ _HOOK_ENTRY(SdAVDec_DemuxStart, __COUNTER__) },
	{ _HOOK_ENTRY(SdAVDec_DemuxStop, __COUNTER__) },
	{ _HOOK_ENTRY(TCCIMManagerBase_SetAVPID, __COUNTER__) },
#undef _HOOK_ENTRY
};

void handle_dvbapi_ca_set_descr(unsigned char *buf)
{
	ca_descr_t ca_descr;
	memcpy(&ca_descr, &buf[4], sizeof(ca_descr_t));
	ca_descr.index = ntohl(ca_descr.index);
	ca_descr.parity = ntohl(ca_descr.parity);
	log("Got CA_SET_DESCR request, index=0x%04x parity=0x%04x\n", ca_descr.index, ca_descr.parity);

	g_fltDscmb = TCCIMManagerBase.MDrv_DSCMB_FltKeySet(0 /*ca_descr.index*/ , ca_descr.parity + 1 , ca_descr.cw);
	log("MDrv_DSCMB_FltKeySet=%d g_fltDscmb=%d\n", g_fltDscmb, g_fltDscmb);
}

void handle_dmx_set_filter(unsigned char *buf)
{
	struct dmx_sct_filter_params params;
	unsigned char demux_index = buf[4];
	unsigned char filter_num = buf[5];
	memcpy(&params, &buf[6], sizeof(struct dmx_sct_filter_params));
	log("Got DMX_SET_FILTER request, pid=0x%02x, byte1=0x%02x, mask1=0x%02x\n", ntohs(params.pid), params.filter.filter[0], params.filter.mask[0] );

	stopMonitors();

	switch (params.filter.filter[0]) {
		case 0x80:
			g_dmxParams81.pid = 0;
			g_80_demux_id = demux_index;
			g_80_filter_id = filter_num;
			g_dmxParams80.pid = ntohs(params.pid);
			g_dmxParams80.filter = params.filter.filter[0];
			g_dmxParams80.mask[0] = params.filter.mask[0];
			g_monHandle80 = TCCIMManagerBase.SdTSData_StartMonitor(DMX_HANDLE_LIVE, &g_dmxParams80);/*maybe add 0x00 as parameter*/
			log("ECM80 monitor started, dmxHandle=0x%08x, monHandle=0x%08x\n", g_dmxHandle, g_monHandle80);
			break;
		case 0x81:
			g_dmxParams80.pid = 0;
			g_81_demux_id = demux_index;
			g_81_filter_id = filter_num;
			g_dmxParams81.pid = ntohs(params.pid);
			g_dmxParams81.filter = params.filter.filter[0];
			g_dmxParams81.mask[0] = params.filter.mask[0];
			g_monHandle81 = TCCIMManagerBase.SdTSData_StartMonitor(DMX_HANDLE_LIVE, &g_dmxParams81);/*maybe add 0x00 as parameter*/
			log("ECM81 monitor started, dmxHandle=0x%08x, monHandle=0x%08x\n", g_dmxHandle, g_monHandle81);
			break;
		default:
			break;
	}
}

void handle_dvbapi_server_info(unsigned char *buf)
{
	g_SID = -1;

	u8 channel[0x20];
	u32 source = 0; /*TODO Check if source is live tv 0x00 */
	TCCIMManagerBase.GetSource(*TCCIMManagerBase.g_pAppWindow, &source, 0x01);
	TCCIMManagerBase.TCChannel_Create(channel);
	TCCIMManagerBase.GetTvChannel(*TCCIMManagerBase.g_pAppWindow, channel, 0x01);
	int scrambled = TCCIMManagerBase.FlagScrambled(channel);
	if ( scrambled != 0) {
		TCCIMManagerBase.SetChannelQuiet(*TCCIMManagerBase.g_pAppWindow, channel, 0x01);
	}

	u16 *proto_ver_ptr = (u16 *) &buf[4];
	protocol_version = ntohs(*proto_ver_ptr);
	log("Got SERVER_INFO: %s, protocol_version = %d\n", &buf[6], protocol_version);
	socket_connected = 0x01;
}

void handle_dvbapi_ecm_info(unsigned char *buf)
{
	char cardsystem[255];
	char reader[255];
	char from[255];
	char protocol[255];
	unsigned char len, hops;
	int i = 4;

	u16 *sid_ptr = (u16 *) &buf[i];		//ServiceID
	u16 sid = ntohs(*sid_ptr);
	i += 2;

	u16 *caid_ptr = (u16 *) &buf[i];	//CAID
	u16 caid = ntohs(*caid_ptr);
	i += 2;

	u16 *pid_ptr = (u16 *) &buf[i];		//PID
	u16 pid = ntohs(*pid_ptr);
	i += 2;

	u32 *prid_ptr = (u32 *) &buf[i];	//ProviderID
	u32 prid = ntohl(*prid_ptr);
	i += 4;

	u32 *ecmtime_ptr = (u32 *) &buf[i];	//ECM time
	u32 ecmtime = ntohl(*ecmtime_ptr);

	//cardsystem name
	recv(sock, &len, 1, MSG_DONTWAIT);	//string length
	recv(sock, cardsystem, len, MSG_DONTWAIT);
	cardsystem[len] = 0;					//terminate the string

	//reader name
	recv(sock, &len, 1, MSG_DONTWAIT);	//string length
	recv(sock, reader, len, MSG_DONTWAIT);
	reader[len] = 0;						//terminate the string

	//source (from)
	recv(sock, &len, 1, MSG_DONTWAIT);	//string length
	recv(sock, from, len, MSG_DONTWAIT);
	from[len] = 0;							//terminate the string

	//protocol name
	recv(sock, &len, 1, MSG_DONTWAIT);	//string length
	recv(sock, protocol, len, MSG_DONTWAIT);
	protocol[len] = 0;						//terminate the string

	recv(sock, &hops, 1, MSG_DONTWAIT);	//hops

	log("Got ECM_INFO: adapter_index=%d, SID = %04X, CAID = %04X (%s), PID = %04X, ProvID = %06X, ECM time = %d ms, reader = %s, from = %s, protocol = %s, hops = %d\n",
					adapter_index,sid, caid, cardsystem, pid, prid, ecmtime, reader, from, protocol, hops);
}

void socket_open_connection()
{
	// connecting via TCP socket to OSCam
	struct addrinfo hints, *servinfo, *p;
	int rv;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(oscam_server_ip, itoa(oscam_server_port), &hints, &servinfo)) != 0)
	{
		log("getaddrinfo error: %s", strerror(rv));
		return;
	}

	// loop through all the results and connect to the first we can
	for (p = servinfo; p != NULL; p = p->ai_next)
	{
		int sockfd;
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
		{
			log("%s: socket error: %s", __FUNCTION__, strerror(errno));
			continue;
		}
		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
		{
			close(sockfd);
			log("%s: connect error: %s", __FUNCTION__, strerror(errno));
			continue;
		}
		sock = sockfd;
		break; // if we get here, we must have connected successfully
	}

	if (p == NULL)
	{
		// looped off the end of the list with no connection
		log("Cannot connect to OSCam. Check your configuration and firewall settings.");
		sock = 0;
	}

	freeaddrinfo(servinfo); // all done with this structure

	if (sock)
		log("created socket with socket_fd=%d", sock);
}

void socket_close_connection()
{
	if (sock > 0)
	{
		close(sock);
		sock = 0;
	}
}


/* SOCKET HANDLER */
static void *socket_handler(void *ptr){
	int faults = 0;
	log("create socket handler\n");

	socket_open_connection();
	if (sock > 0)
	{
		log("Successfully (re)connected to OSCam");
		log("Sending DVBAPI_CLIENT_INFO ...\n");
		faults = 0;
		socket_send_client_info();
		//capmt sendall
	}
	else {
		faults++; // unused for now
		return NULL;
	}

	int running = 1;
	int c_read;
	unsigned char buf[262];
	int skip_bytes = 0;
	u32 *request;

	while(running==1) {
		c_read = recv(sock, &buf[skip_bytes], sizeof(int)-skip_bytes, MSG_DONTWAIT);

		if (c_read <= 0) {
			//if (c_read == 0)
			//	break;

			//log that connection is broken and everything is stopped

			//cCondWait::SleepMs(20);
			continue;
		}

		request = (unsigned int *) &buf;
		skip_bytes = 0;

		if (ntohl(*request) != DVBAPI_SERVER_INFO) {
			// first byte -> adapter_index
			c_read = recv(sock, &adapter_index, 1, MSG_DONTWAIT);
			if (c_read <= 0) {
				//if (cRead == 0)
				//	CloseConnection();
				//cCondWait::SleepMs(20);
				continue;
			}
			//adapter_index -= AdapterIndexOffset;
		}

		*request = ntohl(*request);
		if (DVBAPI_CA_SET_DESCR == *request) {
			c_read = recv(sock, buf+4, sizeof(ca_descr_t), MSG_DONTWAIT);
		} else if (DVBAPI_CA_SET_PID == *request) {
			/*TODO: Shall we use this?*/
			c_read = recv(sock, buf+4, sizeof(ca_pid_t), MSG_DONTWAIT);
			continue;
		} else if (DMX_SET_FILTER == *request) {
			c_read = recv(sock, buf+4, sizeof(struct dmx_sct_filter_params), MSG_DONTWAIT);
		} else if (DVBAPI_SERVER_INFO == *request) {
			unsigned char len;
			recv(sock, buf+4, 2, MSG_DONTWAIT);
			recv(sock, &len, 1, MSG_DONTWAIT);
			c_read = recv(sock, buf+6, len, MSG_DONTWAIT);
			buf[6+len] = 0;
		} else if (DVBAPI_ECM_INFO == *request) {
			recv(sock, buf+4, 14, MSG_DONTWAIT);
		} else if (CA_SET_DESCR_MODE == *request) {
			/*TODO: Shall we use this?*/
			c_read = recv(sock, buf+4, sizeof(ca_descr_mode_t), MSG_DONTWAIT);
			continue;
		} else {
			log("read failed unknown command: %08x\n", *request);
			usleep(2000);
			continue;
		}


		if (c_read <= 0) {
			//if (c_read == 0)
			//	CloseConnection();
			//	cCondWait::SleepMs(20);
			continue;
		}

		if (DVBAPI_CA_SET_DESCR == *request) {
			handle_dvbapi_ca_set_descr((unsigned char *)&buf);
		} else if (DMX_SET_FILTER == *request) {
			handle_dmx_set_filter((unsigned char *)&buf);
		} else if(DVBAPI_SERVER_INFO == *request) {
			handle_dvbapi_server_info((unsigned char *)&buf);
		} else if (DVBAPI_ECM_INFO == *request) {
			handle_dvbapi_ecm_info((unsigned char *)&buf);
		} else {
			log("Unknown request: %02X %02X %02X %02X\n", request[0], request[1], request[2], request[3]);
		}

	}
	socket_close_connection();
}

EXTERN_C void lib_init(void *_h, const char *libpath) {
	u32 argc;
	char *argv[100],*optstr;

	unsigned long *cur_addr,ret,i,k,D, LOG_ALL=0;

	if(_hooked) {
		log("Injecting once is enough!\n");
		return;
	}

	unlink(LOG_FILE);
	log("SamyGO "LIB_TV_MODELS" lib"LIB_NAME" "LIB_VERSION" - "BUILD_GIT_TIME" (c) element 2016\n");

	void *h = dlopen(0, RTLD_LAZY);

	if(!h) {
		char *serr = dlerror();
		log("dlopen error %s\n", serr);
		return;
	}

	patch_adbg_CheckSystem(h);

	samyGO_whacky_t_init(h, &TCCIMManagerBase, ARRAYSIZE(TCCIMManagerBase.procs));
	if ( dyn_sym_tab_init(h, TCCIMManagerBase_func_table, ARRAYSIZE(TCCIMManagerBase_func_table)) >= 0 ) {
		set_hooks(TCCIMManagerBase_hooks, ARRAYSIZE(TCCIMManagerBase_hooks));
		_hooked = 1;
	}

	/* commandline parameters */
	oscam_emm_enabled = 0;
	argc = getArgCArgV(libpath, argv);

	optstr = getOptArg(argv, argc, "OSCAM_SERVER_IP:");
	if(optstr) {
		oscam_server_ip = optstr;
	}

	optstr = getOptArg(argv, argc, "OSCAM_SERVER_PORT:");
	if ( optstr ) {
		oscam_server_port = atoi(optstr);
	}

	optstr = getOptArg(argv, argc, "EMM");
	if ( optstr ) {
		oscam_emm_enabled = 1;
		log("warning: emm handler activated! please be careful\n");
	}

	if ( !oscam_server_ip || oscam_server_port == 0 ) {
		log("error: oscam network mode needs oscam server ip and oscam server port argument\n");
		return;
	}

	tv_model = getTVModel();
	tv_type = getTVType();
	log("TV Model: %s, Type: %s\n", tvModelToStr(tv_model), tvTypeToStr(tv_type));

	dlclose(h);
	log("Hooking the system done ...\n");

	u32 init = TCCIMManagerBase.MDrv_DSCMB_Init();
	log("MDrc_DSCMB_Init=0x%04x\n", init);

	if(pthread_create(&x_thread_socket_handler, NULL, socket_handler, NULL)) {
		log("error creating socket handler thread\n");
	}
}

EXTERN_C void lib_deinit(void *_h) {
	log("If you see this message you forget to specify -r when invoking hijack :)\n");
}


