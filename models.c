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

