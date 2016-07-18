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
#ifndef MODELS_H_
#define MODELS_H_

#include "types.h"

typedef enum {
	TV_MODEL_UNK   = -1,
	TV_MODEL_C     = 0,
	TV_MODEL_D     = 1,
	TV_MODEL_E     = 2,
	TV_MODEL_F     = 3,
	TV_MODEL_H     = 4,
} model_type_e;

typedef enum {
	TV_TYPE_UNK = -1,
	TV_TYPE_MST = 1,
	TV_TYPE_GFS_GFP = 2,
	TV_TYPE_NT = 3,
} model_firmware_e;

typedef struct {
	const char *name;
	int model;
} hook_t;

const char *model_type_string(int m);
const char *model_firmware_string(int t);
int model_firmware();
int model_type();


int dvbapi_install(void *h);
int dvbapi_server_info(void);
//int dvbapi_stop_filter(stop_filter_t stop_filter);
int dvbapi_set_descriptor(ca_descr_t ca_descr);
int dvbapi_start_filter(u8 demux_index, u8 filter_num, struct dmx_sct_filter_params params);

void dvbapi_dmx_stop(u8 demux_index, u8 filter_num, u16 pid);
int dvbapi_set_pid ( ca_pid_t ca_pid );

#endif /* MODELS_H_ */
