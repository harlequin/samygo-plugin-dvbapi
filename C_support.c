#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <dlfcn.h>

#define F_SEEK_UP 4
#define F_SEEK_DOWN -4

#define BRANCH_B 0xea000000
#define BRANCH_BL 0xeb000000
#define BX_LR 0xE12FFF1E

void LOG(const char *fmt, ...); 

//#define clog(fmt, ...) LOG("[RCremap] " fmt, ...)
#define clog(fmt, ...) LOG("[RecTitle] " fmt, __VA_ARGS__)
void* get_dlsym_addr(void *h, char *fn_name)
{
 	unsigned long *addr=dlsym(h, fn_name);	
	if(!addr)
	{
		clog("dlsym '%s' failed.\n", fn_name);
		return 0;
	}
	else
		clog("Found %s location at: 0x%08x\n",fn_name,addr);
	return addr;
}
unsigned long check_is_LDR_RD( unsigned long offset, unsigned long val)
{
    if( (val >> 16) != 0xE59F ) return 0; // not LDR RD
        return  offset + 8 + (val & 0xFFF);
}
unsigned int * find_function_start(unsigned int *addr)
{
        unsigned int *cur_addr,tmp;
        cur_addr=addr;
        while(1)
        {
                cur_addr--;
				tmp=*cur_addr;
                //if((tmp & 0xe92d4000) == 0xe92d4000)
                if((tmp & 0xFFFFF000) == 0xe92d4000)
                        break;

        }
        return cur_addr;
}
unsigned int * find_next_function_start(unsigned int *addr)
{
        unsigned int *cur_addr,tmp;
        cur_addr=addr;
        while(1)
        {
                cur_addr++;
				tmp=*cur_addr;
                //if((tmp & 0xe92d4000) == 0xe92d4000)
                if((tmp & 0xFFFFF000) == 0xe92d4000)
                        break;

        }
        return cur_addr;
}
unsigned int* find_function_end(unsigned int*addr)
{
        unsigned int*cur_addr;
        cur_addr=addr;
        while(1)
        {
                cur_addr++;
                //if((*cur_addr & 0xe89da000) == 0xe89da000)
                if((*cur_addr & 0xFFFFF000) == 0xe89da000)
                        break;

        }
        return cur_addr;
}
unsigned int calculate_branch(unsigned int from, unsigned int to, unsigned int b_type)
{
        int b_addr,branch;
        if(from > to)
                b_addr = 0xffffff-((from+4-to)/4);
        else
                b_addr= from/4 - to/4 -2;
        b_addr=b_addr & 0xffffff;
        branch=b_addr | b_type;
        return branch;
}

unsigned int calculate_branch_addr(unsigned int *from)
{
        unsigned int b_addr,branch;
    branch = (*from & 0xffffff);
    if(branch > 0x800000)
        b_addr = ((unsigned int)from) + 4 - (0xffffff-branch)*4;
    else
        b_addr = ((unsigned int)from) + 8 + branch*4;

        return b_addr;
}
unsigned int* find_func_by_string(void *h, char *fName, char *f_string, int seek_step, int offset)
{
        unsigned long *rodata_begin=0, *rodata_end=0, addr=0, *s_addr=0;
        unsigned long text_range=0x50000, steps=0, *ldr_addr,*p_addr,cur_addr,tmp;
        unsigned char *string_buf;

        addr=(unsigned long)get_dlsym_addr(h,fName)+offset;
        rodata_begin=get_dlsym_addr(h,"_fini");
        rodata_end = rodata_begin + 0x2200000;
        {
                clog("text range: @0x%08x -> @0x%08x\n", addr,(uint)(addr+(text_range*(seek_step/4))));
                clog("rodata range: @0x%08x -> @0x%08x\n", rodata_begin,rodata_end);
        }
        for(cur_addr=addr;(cur_addr < (addr+text_range)) && (steps < text_range) ;steps+=4,cur_addr+=seek_step)
        {
                //read_mem(pid, &tmp, 1, cur_addr);
				tmp=*(unsigned long*)cur_addr;
                if(ldr_addr=(void*)check_is_LDR_RD((unsigned long)cur_addr,tmp) )
                {
                   //     read_mem(pid, &p_addr, 1, ldr_addr);
				   		p_addr=(void*)*ldr_addr;
				   		//clog("P_LDR: 0x%08x\n",p_addr);
                        if((p_addr > rodata_begin) && (p_addr < rodata_end))
                        {
				   				//clog("P_LDR: 0x%08x\n",p_addr);
                                //read_mem(pid,(void*)string_buf,5,p_addr);
                                //string_buf[30]=0;
								string_buf=(char*)p_addr;
                                if(!strncmp(string_buf,f_string,20))
                                {
                                        s_addr=(unsigned long*)cur_addr;
                                        clog("Found %s at @0x%08x\n", f_string, (uint) cur_addr);
                                        break;
                                }

                        }
                }

        }
        return (unsigned int *)s_addr;
}
#define C_CASE(fn) static void* addr_##fn;\
	if(!strcmp(fn_name,""#fn)) \
	{ \
		if(addr_##fn) \
			return addr_##fn; \
		strncpy(fname,""#fn,200);\
		ret=&addr_##fn; \
		addr=0;
#define C_FOUND(addr) clog("Found %s at: 0x%08x\n",fname,addr);
#define C_RET(addr) *ret = (void*)addr;\
	return *ret; \
	}
#include "C_find.h"
#include <stdio.h>
#include "tv_info.h"

void *C_find(void *h, const char *fn_name)
{
    static int model=TV_MODEL_UNK;
	if(model == TV_MODEL_UNK)
	    model=getTVModel();
	if(model!=TV_MODEL_C)
		return 0;
	else
		return C_sub_find(h,fn_name);
}
