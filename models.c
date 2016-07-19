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
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

#include "utlist.h"
#include "hook.h"
#include "common.h"
#include "types.h"
#include "log.h"
#include "models.h"
#include "dvbapi.h"

static pmt_t *g_capmt = NULL;


const char *model_type_string(int m) {
	switch(m) {
	case TV_MODEL_UNK:
		return "Unknown";
	case TV_MODEL_C:
		return "C Series";
	case TV_MODEL_D:
		return "D Series";
	case TV_MODEL_E:
		return "E Series";
	case TV_MODEL_F:
		return "F Series";
	case TV_MODEL_H:
		return "H Series";
	default:
		return "ERROR";
	}
}

const char *model_firmware_string(int t) {
	switch(t) {
	case TV_TYPE_UNK:
		return "Unknown";
	case TV_TYPE_MST:
		return "T-MST";
	case TV_TYPE_GFS_GFP:
		return "T-GFS/T-GFP";
	case TV_TYPE_NT:
		return "T-NT";
	default:
		return "ERROR";
	}
}

int model_firmware() {
	char pinfo[256] = { 0 };

	FILE *f = fopen("/mtd_exe/.product", "r");
	if(!f) {
		f = fopen("/.info", "r"); //on C there is no .product
		if(!f)
			return -1;
	}

	fseek(f, 0, SEEK_END);
	long nread = ftell(f);
	fseek(f, 0, SEEK_SET);

	if(nread > sizeof(pinfo) - 1)
		nread = sizeof(pinfo) - 1;

	nread = fread(pinfo, 1, nread, f);
	if(nread >= 0)
		pinfo[nread] = 0;

	fclose(f);

	while(pinfo[nread-1] == '\n' || pinfo[nread-1] == '\r')
		pinfo[--nread] = 0;

	log("firmware: %s\n", pinfo);

	if(strncmp("T-MST", pinfo, 5) == 0) {
		return TV_TYPE_MST;
	} else if(strncmp("T-GFS", pinfo, 5) == 0 || strncmp("T-GFP", pinfo, 5) == 0) {
		return TV_TYPE_GFS_GFP;
	} else if(strncmp("T-NT", pinfo, 4) == 0) {
		return TV_TYPE_NT;
	} else {
		log("Not able to determine fw version '%s'\n", pinfo);
		return TV_TYPE_UNK;
	}

}

int model_type() {
	int i,model;

	hook_t syms[] = {
			{ "_ZNSt5dequeIN10jpegplayer6effect9SlideShow4ItemESaIS3_EE16_M_push_back_auxERKS3_",  TV_MODEL_C },
			{ "_ZN13CViewerNormal10t_SetSleepEv",  TV_MODEL_D },
			{ "_ZN13CViewerNormal11t_ShowSleepEb",  TV_MODEL_E },
			{ "_ZN13CViewerNormal10m_SetSleepEb",  TV_MODEL_F },
			{ "_ZN8TCTvImpl7m_TunerEN8TCWindow7EWindowE",  TV_MODEL_F },
			{ "_ZN10CNormalWnd10m_SetSleepEb",  TV_MODEL_H },
			{ "_ZN8TCTvImpl27m_RecoverSettingsWithBootUpEv",  TV_MODEL_H },
	};

	void *h = dlopen(0, RTLD_LAZY);
	if(!h)
		return TV_MODEL_UNK;

	model = TV_MODEL_UNK;
	for(i = 0; i < ARRAYSIZE(syms); i++) {
		if(dlsym(h, syms[i].name)) {
			model = syms[i].model;
			break;
		}
	}

	dlclose(h);

	return model;
}

void model_demuxbase_demux(SICallBackSettings_t *data, u32 service_id, demux_filter_t *active_filter) {
	pmt_t *buf;
	pmt_t *tmp;
	u16 sid = 0x00;

	if ( data->len > 0 && data->len <= 1024) {

		if ( be8(data->ptr) == 0x02 ) {

			sid = be16( (data->ptr) + 0x03 );

			if ( sid == 0x00 ) {
				return;
			}

			//on new sid or if content not the same
			LL_SEARCH_SCALAR(g_capmt, buf, sid, sid);
			if ( !buf || memcmp( data->ptr, buf->ptr, data->len ) != 0) {
				//no sid in list found
				buf = malloc(sizeof(pmt_t));
				buf->sid = sid;
				buf->lm = PMT_LIST_MORE;
				buf->len = data->len;
				buf->ptr = malloc(buf->len);
				memcpy(buf->ptr, data->ptr, buf->len);
				LL_APPEND(g_capmt, buf);

				//u8 lm = PMT_LIST_FIRST;
				LL_FOREACH_SAFE(g_capmt, buf, tmp) {
					if ( buf->sid == service_id ) {
						if ( g_capmt == buf ){ buf->lm |= PMT_LIST_FIRST; }
						if ( buf->next == NULL ) { buf->lm |= PMT_LIST_LAST; }
						socket_send_capmt(buf);
						buf->lm = PMT_LIST_UPDATE;
					}
				}
				//g_send_PMT_required = 0;
			}
		} else {
			demux_filter_t *filter;
			LL_SEARCH_SCALAR(active_filter, filter, monHandle, data->hmon);
			if ( filter ) {
				log(">> EMM%02x ... hmon:0x%08x send data\n", be8(data->ptr), data->hmon);
				socket_send_filter_data( filter->demuxId, filter->filterId, data->ptr , data->len );
			}
		}
	}
}

