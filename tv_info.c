#include "tv_info.h"

inline static int getTVType()
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

    if(strncmp("T-MST", pinfo, 5) == 0)
        return TV_TYPE_MST;
    else if(strncmp("T-GFS", pinfo, 5) == 0 || strncmp("T-GFP", pinfo, 5) == 0)
        return TV_TYPE_GFS_GFP;
    else if(strncmp("T-NT", pinfo, 4) == 0)
        return TV_TYPE_NT;

    return TV_TYPE_NON_MST;
}

inline static const char *tvTypeToStr(int t)
{
    switch(t)
    {
        case TV_TYPE_MST:
            return "T-MST";
        case TV_TYPE_GFS_GFP:
            return "T-GFS/T-GFP";
        case TV_TYPE_NT:
            return "T-NT";
        case TV_TYPE_NON_MST:
            return "Non-MST";
        default:
            return "UNKNOWN";
    }
}

inline static int getTVModel()
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


inline static const char *tvModelToStr(int m)
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