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
#include <errno.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "hook.h"
#include "log.h"

#define cacheflush(from, size)   __clear_cache((void*)from, (void*)((unsigned long)from+size))
#define JUMP_T9 0x03200008
#define NOP 0
#define LUI_T9_0 0x3C190000
#define ORI_T9_0 0x37390000

int dyn_sym_tab_init(void *h, dyn_fn_t *fn_tab, uint32_t cnt) {
    void *sdal=dlopen("libSDAL.so",RTLD_LAZY);
    for(int i = 0; i < cnt; i++) {
		void *fn=0;
		if(sdal)
        	fn = dlsym(sdal, fn_tab[i].name);
		if(!fn)
        	fn = dlsym(h, fn_tab[i].name);
        if(!fn)
        {
            log("dlsym '%s' failed.\n", fn_tab[i].name);
            continue;
            //return -1;
        }

        log("%s [%p].\n", fn_tab[i].name, fn);

        fn_tab[i].fn = fn;
    }
    return 0;
}

int samyGO_whacky_t_init(void *h, void *paramCTX, uint32_t cnt) {
	int res = 0;
    samyGO_CTX_t *ctx;
    ctx=paramCTX;
	void *fn;
    void *sdal=dlopen("libSDAL.so",RTLD_LAZY);
    for(int i = 0; i < cnt ; i++) {
        if(!ctx->procs[i])
            continue;
		fn=0;
		if(sdal)
        	fn = dlsym(sdal, ctx->procs[i]);
		if(!fn)
        	fn = dlsym(h, ctx->procs[i]);

        if(!fn && !(fn=C_find(h,ctx->procs[i]))) {
            log("dlsym '%s' failed.\n", ctx->procs[i]);
        } else {
            log("%s [%p].\n",  ctx->procs[i], fn);
            res++;
        }
        ctx->procs[i] = fn;
    }
    return res;
}

void hijack_start(sym_hook_t *sa, void *target, void *_new) {
    unsigned char o_code[HIJACK_SIZE], n_code[HIJACK_SIZE];


	//addiu = (left  & 0xffff) | ORI_A1_0;
    // ldr pc, [pc, #0]; .long addr; .long addr
    //memcpy(n_code, "\x00\xf0\x9f\xe5\x00\x00\x00\x00\x00\x00\x00\x00", HIJACK_SIZE);

#ifdef SPECIAL_HOOK
    unsigned long lui,ori;
	lui = ((((unsigned long)_new) >> 16) & 0xffff) | LUI_T9_0;
	ori = (((unsigned long)_new) & 0xffff) | ORI_T9_0;
    *(unsigned long *)&n_code[0] = lui;
    *(unsigned long *)&n_code[4] = ori;
    *(unsigned long *)&n_code[8] = JUMP_T9;
    *(unsigned long *)&n_code[12] = NOP;
#else
    if ( (unsigned long)target % 4 == 0 )
    {
        // ldr pc, [pc, #0]; .long addr; .long addr
        memcpy(n_code, "\x00\xf0\x9f\xe5\x00\x00\x00\x00\x00\x00\x00\x00", HIJACK_SIZE);
        *(unsigned long *)&n_code[4] = (unsigned long)_new;
        *(unsigned long *)&n_code[8] = (unsigned long)_new;
    }
    else // Thumb
    {
        // add r0, pc, #4; ldr r0, [r0, #0]; mov pc, r0; mov pc, r0; .long addr
        memcpy(n_code, "\x01\xa0\x00\x68\x87\x46\x87\x46\x00\x00\x00\x00", HIJACK_SIZE);
        *(unsigned long *)&n_code[8] = (unsigned long)_new;
        target--;
    }
#endif


    #if __DEBUG__
    printf("Hooking function 0x%p with 0x%p\n", target, _new);
    #endif

    memcpy(o_code, target, HIJACK_SIZE);

    memcpy(target, n_code, HIJACK_SIZE);
    cacheflush(target, HIJACK_SIZE);

    sa->addr = target;
    memcpy(sa->o_code, o_code, HIJACK_SIZE);
    memcpy(sa->n_code, n_code, HIJACK_SIZE);

}

void hijack_pause(
       sym_hook_t *sa)
{
    #if __DEBUG__
    printf("Pausing function hook 0x%p\n", target);
    #endif

    memcpy(sa->addr, sa->o_code, HIJACK_SIZE);
    cacheflush(sa->addr, HIJACK_SIZE);
}

void hijack_resume(
       sym_hook_t *sa)
{
    #if __DEBUG__
    printf("Resuming function hook 0x%p\n", target);
    #endif

    memcpy(sa->addr, sa->n_code, HIJACK_SIZE);
    cacheflush(sa->addr, HIJACK_SIZE);
}

void hijack_stop(
       sym_hook_t *sa)
{
    #if __DEBUG__
    printf("Unhooking function 0x%p\n", target);
    #endif

    memcpy(sa->addr, sa->o_code, HIJACK_SIZE);
    cacheflush(sa->addr, HIJACK_SIZE);
}


int patch_adbg_CheckSystem(void *h) {
	return 0;
}

static void dumpbin(
        const char *path, const void *data, size_t cnt)
{
    FILE *f = fopen(path, "wb+");
    //mylog("test2");
    //mylog("test","test");
    if(f)
    {
        fwrite(data, cnt, 1, f);
        fflush(f);
        fclose(f);
    }
    else
        log("Error saving file '%s'\n", path);
}

void log_buf(char *name, unsigned char *buf)
{
    int i;
    log("%s: ",name);
    for(i=0;i<16;i++)
        LOG("0x%02x ",buf[i]);
    LOG("\n");
}



int set_hooks(hook_entry_t *hooks, uint32_t cnt) {
    for(int i = 0; i < cnt; i++) {
        void *fn = hooks[i].dyn_fn->fn;
        if(!fn)
            continue;

        if(!hooks[i].fnHook)
            continue;

        uint32_t paligned = (uint32_t)fn & ~4095;
        mprotect((uint32_t *)paligned, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);

        hijack_start(hooks[i].hook, fn, hooks[i].fnHook);
    }
    return 0;
}

STATIC int remove_hooks(
        hook_entry_t *hooks, uint32_t cnt)
{
    for(int i = 0; i < cnt; i++)
    {
        hijack_stop(hooks[i].hook);
    }
}


void *sgo_shmem_open(
        const char *path, size_t size)
{
    char _path[PATH_MAX + 1] = { 0 };
    //mkdir(SAMYGO_RT_DIR, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    strncpy(_path,path,PATH_MAX);

    errno = 0;
    int fd=-1;
    int created = 0, tmp=0;
    if((fd = open(_path, O_RDWR , (mode_t)0600)) > 0)
        created=0;
    else if((fd = open(_path, O_RDWR | O_CREAT, (mode_t)0600)) > 0)
        created=1;
    else
        return 0;

        lseek(fd, size, SEEK_SET);
        tmp=write(fd, "", 1);

        //logf("SHM, created: %d\n",created);

    void *mem = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if(!mem)
        return 0;
    if(created)
        memset(mem, 0, size);

    return mem;
}
void *sgo_shmem_init(const char *path, size_t size)
{
    void *shm = sgo_shmem_open(path, size);
    if(!shm)
    {
        logf("Error: shmem open '%s'.\n", path);
        return 0;
    }
    return shm;
}
void sgo_shmem_close(void *mem, size_t size)
{
    size_t aligned = size & ~0xFFF + 0x1000;
    msync(mem, aligned, MS_SYNC);
    munmap(mem, size);
}

