#define STATIC static

#define _FILE_OFFSET_BITS 64

#ifndef _LARGEFILE64_H
#define _LARGEFILE64_H
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif
#include <sys/types.h>
#include <sys/stat.h>

#include "log.h"

static int patch_adbg_CheckSystem(void *h) {
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

static int getArgCArgV(
        const char *libpath, char **argv)
{
    const int EXTRA_COOKIE = 0x82374021;

    uint32_t argc = 1;
    argv[0] = (char *)libpath;
    void *mem = (void*)(libpath + strlen(libpath) + 1);

    uint32_t aligned = (uint32_t)mem;
    aligned = (aligned + 3) & ~3;

    uint32_t *extra = (uint32_t*)aligned;
    if(extra[0] != EXTRA_COOKIE)
        return 0;

    argc += extra[1];
    uint32_t *_argv = &extra[2];
    for(int i = 0; i < argc; i++)
        argv[i + 1] = (char *)(aligned + _argv[i]);

    return argc;
}

char* getOptArg(char **argv, int argc, char *option)
{
    for(int i=0;i<argc;i++)
    {
        if(strstr(argv[i],option)==argv[i])
        {
            return argv[i]+strlen(option);
        }
    }
    return 0;
}

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

typedef struct 
{
    void *fn;
    const char *name;
} dyn_fn_t;



STATIC int dyn_sym_tab_init(
        void *h, dyn_fn_t *fn_tab, uint32_t cnt)
{
    void *sdal=dlopen("libSDAL.so",RTLD_LAZY);
    for(int i = 0; i < cnt; i++)
    {
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

void log_buf(char *name, unsigned char *buf)
{
    int i;
    log("%s: ",name);
    for(i=0;i<16;i++)
        LOG("0x%02x ",buf[i]);
    LOG("\n");
}

typedef struct
{
    sym_hook_t *hook;
    dyn_fn_t *dyn_fn;
    void *fnHook;
} hook_entry_t;

STATIC int set_hooks(
        hook_entry_t *hooks, uint32_t cnt)
{
    for(int i = 0; i < cnt; i++)
    {
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

typedef union
{
    const void *procs[100];
    const char *names[100];
} samyGO_CTX_t;

//STATIC int samyGO_whacky_t_init(void *h, samyGO_whacky_t *ctx, uint32_t cnt)
STATIC int samyGO_whacky_t_init(void *h, void *paramCTX, uint32_t cnt)
{
    samyGO_CTX_t *ctx;
    ctx=paramCTX;
	void *fn;
    void *sdal=dlopen("libSDAL.so",RTLD_LAZY);
    for(int i = 0; i < cnt ; i++)
    {
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
        }
        ctx->procs[i] = fn;
    }
    return 0;
}
#include <errno.h>

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
