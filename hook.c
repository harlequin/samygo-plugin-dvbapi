#include "hook.h"
#include "log.h"
#include <dlfcn.h>
#include <string.h>

#define cacheflush(from, size)   __clear_cache((void*)from, (void*)((unsigned long)from+size))
#define JUMP_T9 0x03200008
#define NOP 0
#define LUI_T9_0 0x3C190000
#define ORI_T9_0 0x37390000

typedef union
{
    const void *procs[100];
    const char *names[100];
} samyGO_CTX_t;


int dyn_sym_tab_init(void *h, dyn_fn_t *fn_tab, uint32_t cnt) {
	int result = 0;
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
            result = -1;
            continue;
        }

        log("%s [%p].\n", fn_tab[i].name, fn);

        fn_tab[i].fn = fn;
    }
    return result;
}



int samyGO_whacky_t_init(void *h, void *paramCTX, uint32_t cnt) {
	int result = 0;
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
            result++;
            continue;
        } else {
            log("%s [%p].\n",  ctx->procs[i], fn);
        }
        ctx->procs[i] = fn;
    }
    return result;
}







void hijack_start(
       sym_hook_t *sa, void *target, void *_new)
{
    unsigned char o_code[HIJACK_SIZE], n_code[HIJACK_SIZE];
	unsigned long lui,ori;
			        //addiu = (left  & 0xffff) | ORI_A1_0;
        // ldr pc, [pc, #0]; .long addr; .long addr
    //memcpy(n_code, "\x00\xf0\x9f\xe5\x00\x00\x00\x00\x00\x00\x00\x00", HIJACK_SIZE);
	lui = ((((unsigned long)_new) >> 16) & 0xffff) | LUI_T9_0;
	ori = (((unsigned long)_new) & 0xffff) | ORI_T9_0;
    *(unsigned long *)&n_code[0] = lui;
    *(unsigned long *)&n_code[4] = ori;
    *(unsigned long *)&n_code[8] = JUMP_T9;
    *(unsigned long *)&n_code[12] = NOP;
/*
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
	*/

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
