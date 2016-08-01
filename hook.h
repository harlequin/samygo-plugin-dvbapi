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
#ifndef __HOOK_H__
#define __HOOK_H__


#include "common.h"
#include "log.h"

#define STATIC static

#define _FILE_OFFSET_BITS 64

#ifndef _LARGEFILE64_H
#define _LARGEFILE64_H
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#ifdef SPECIAL_HOOK
  #define HIJACK_SIZE 16
#else
  #define HIJACK_SIZE 12
#endif


typedef struct
{
    void *addr;
    unsigned char o_code[HIJACK_SIZE];
    unsigned char n_code[HIJACK_SIZE];
} sym_hook_t;


typedef union
{
    const void *procs[100];
    const char *names[100];
} samyGO_CTX_t;

typedef struct
{
    void *fn;
    const char *name;
} dyn_fn_t;

typedef struct
{
    sym_hook_t *hook;
    dyn_fn_t *dyn_fn;
    void *fnHook;
} hook_entry_t;

#define _HOOK_IMPL(F_RET,F, ...) \
    typedef F_RET (*F)(__VA_ARGS__); \
    STATIC sym_hook_t hook_##F; \
    STATIC F_RET x_##F(__VA_ARGS__)


#define _HOOK_DISPATCH(F, ...) \
    hijack_pause(&hook_##F); \
    void *h_ret = (void *) ((F)hook_##F.addr)(__VA_ARGS__); \
    hijack_resume(&hook_##F)

#define _HOOK_DISPATCH_LOG(F, ...) \
    log(">>> %s\n", __func__); \
    _HOOK_DISPATCH(F, __VA_ARGS__); \
    log("<<< %s %p\n", __func__, h_ret)

#define cacheflush(from, size)   __clear_cache((void*)from, (void*)((unsigned long)from+size))



EXTERN_C_BEGIN



void hijack_start(
        sym_hook_t *sa, void *target, void *_new);

void hijack_pause(
        sym_hook_t *sa);

void hijack_resume(
        sym_hook_t *sa);

void hijack_stop(
        sym_hook_t *sa);



int patch_adbg_CheckSystem(void *h);
int getArgCArgV(const char *libpath, char **argv);
char* getOptArg(char **argv, int argc, char *option);
int set_hooks(hook_entry_t *hooks, uint32_t cnt);

EXTERN_C_END

int dyn_sym_tab_init(void *h, dyn_fn_t *fn_tab, uint32_t cnt);
int samyGO_whacky_t_init(void *h, void *paramCTX, uint32_t cnt);

#endif //__HOOK_H__
