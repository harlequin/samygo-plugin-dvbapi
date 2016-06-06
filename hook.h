#ifndef __HOOK_H__
#define __HOOK_H__


#include "common.h"
#include "C_support.h"


//#define HIJACK_SIZE 12
#define HIJACK_SIZE 16

typedef struct
{
    void *addr;
    unsigned char o_code[HIJACK_SIZE];
    unsigned char n_code[HIJACK_SIZE];
} sym_hook_t;




EXTERN_C_BEGIN

typedef struct
{
    void *fn;
    const char *name;
} dyn_fn_t;

void hijack_start(
        sym_hook_t *sa, void *target, void *_new);

void hijack_pause(
        sym_hook_t *sa);

void hijack_resume(
        sym_hook_t *sa);

void hijack_stop(
        sym_hook_t *sa);


EXTERN_C_END

int dyn_sym_tab_init(void *h, dyn_fn_t *fn_tab, uint32_t cnt);
int samyGO_whacky_t_init(void *h, void *paramCTX, uint32_t cnt);

#endif //__HOOK_H__
