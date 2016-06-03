/* 
 *  bugficks
 *	(c) 2013
 *
 *  License: GPLv3
 *
 */
//////////////////////////////////////////////////////////////////////////////

#ifndef __TV_INFO_H__
#define __TV_INFO_H__

//////////////////////////////////////////////////////////////////////////////

#include "common.h"

//////////////////////////////////////////////////////////////////////////////

static const char *getTVInfo()
{
    static char pinfo[256] = { 0 };
    
    FILE *f = fopen("/mtd_exe/.product", "r");
    if(!f)
    {
    	f = fopen("/.info", "r"); //on C there is no .product
		if(!f)
				return 0;
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
    
    return pinfo;
}

enum eTV_MODEL
{
    TV_MODEL_UNK   = -1,
    TV_MODEL_C     = 0,
    TV_MODEL_D     = 1,
    TV_MODEL_E     = 2,
    TV_MODEL_F     = 3,
    TV_MODEL_H     = 4,
};

static int getTVModel()
{
    static const struct
    {
        const char *name;
        int model;
    }
    syms[] =
    {
        { "_ZNSt5dequeIN10jpegplayer6effect9SlideShow4ItemESaIS3_EE16_M_push_back_auxERKS3_",  TV_MODEL_C },
        { "_ZN13CViewerNormal10t_SetSleepEv",  TV_MODEL_D },
        { "_ZN13CViewerNormal11t_ShowSleepEb",  TV_MODEL_E },
        { "_ZN13CViewerNormal10m_SetSleepEb",  TV_MODEL_F }, //exeAPP
        { "_ZN8TCTvImpl7m_TunerEN8TCWindow7EWindowE",  TV_MODEL_F },         //exeTV
        { "_ZN10CNormalWnd10m_SetSleepEb",  TV_MODEL_H }, //exeAPP
        { "_ZN8TCTvImpl27m_RecoverSettingsWithBootUpEv",  TV_MODEL_H },         //exeTV
    };

    void *h = dlopen(0, RTLD_LAZY);
    if(!h)
        return TV_MODEL_UNK;

    int i,model;
    //if(strstr(getTVInfo(),"VALDEUC"))
    //{
    	//dlclose(h);
	//return TV_MODEL_C;
    //}

    model = TV_MODEL_UNK;
    for(i = 0; i < ARRAYSIZE(syms); i++)
    {
        if(dlsym(h, syms[i].name))
        {
            model = syms[i].model;
            break;
        }
    }

    dlclose(h);

    return model;
}


static const char *tvModelToStr(
        int m)
{
    switch(m)
    {
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
            return 0;
    }
}

//////////////////////////////////////////////////////////////////////////////

#endif // #ifndef __TV_INFO_H__

//////////////////////////////////////////////////////////////////////////////
