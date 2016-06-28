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
#include <stdarg.h>
#include "log.h"

void LOG(const char *fmt, ...) {
#ifdef LOG_FILE
    va_list ap;

    FILE *f = fopen(LOG_FILE, "a+");
    if(f) {
        va_start(ap, fmt);
        vfprintf(f, fmt, ap);
        va_end(ap);

        fflush(f);
        fclose(f);
    }
#endif
}

void print_hash(u8 *ptr, u32 len){
	char buffer[1024] = "";
	u8 i = 0;

	while(len--) {
		sprintf(buffer,"%s %02x",buffer, *ptr++);
		if((++i % 16) == 0) {
			log("    %s\n",  buffer);
			buffer[0] = '\0';
		}
	}
	log("    %s\n",  buffer);

}
