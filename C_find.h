unsigned int SetTransportStreamId_C_STUB(void *program, short streamId) 
{ 
	return 0; 
}
void *C_sub_find(void *h, const char *fn_name)
{
	char fname[256];
	void **ret;
	unsigned int *addr,bl_cnt;
    C_CASE(_ZN10TCChNumber16SetProgramNumberEt)
		addr=get_dlsym_addr(h,"_ZN9TCChannel7SetTypeEi");
		if(addr)
		{
			while((*addr  & 0xff000000) != BRANCH_BL) addr++;
			addr=(uint*)calculate_branch_addr(addr);
			if(addr)
			{
				int bl_cnt=0;
				while(*addr!=0xE52DB004 || ++bl_cnt!=8)
					addr++;
				C_FOUND(addr);
			}

		}
    C_RET(addr);
    C_CASE(_ZN10TCChNumber7SetTypeEi)
		addr=get_dlsym_addr(h,"_ZN9TCChannel7SetTypeEi");
		if(addr)
		{
			while((*addr  & 0xff000000) != BRANCH_BL) addr++;
			addr=(uint*)calculate_branch_addr(addr);
			C_FOUND(addr);
		}
    C_RET(addr);
    C_CASE(_ZN10TCChNumber10SetChannelEttt)
		addr=get_dlsym_addr(h,"_ZN9TCChannel10SetChannelEttt");
		if(addr)
		{
			while((*addr  & 0xff000000) != BRANCH_BL) addr++;
			addr=(uint*)calculate_branch_addr(addr);
			C_FOUND(addr);
		}
    C_RET(addr);
    C_CASE(_ZN9TCProgram20SetTransportStreamIdEt)
	C_RET(SetTransportStreamId_C_STUB);
    C_CASE(_ZN9TCProgram15SetExtendedTextEPci)
		unsigned int *set_text;
		unsigned int *get_title=get_dlsym_addr(h,"_ZNK9TCProgram8GetTitleEPcPj");
		if(get_title)
		{
			while(*get_title!=0xE3530004)
				get_title++;
			addr=set_text=get_title;
			clog("Found _ZN9TCProgram9m_SetTextEPcii at: 0x%08x\n",set_text);
			bl_cnt=0;
			while(1)
			{
				addr++;
				if(((*addr  & 0xff000000) == BRANCH_BL) && ((uint)set_text==calculate_branch_addr(addr)) && ++bl_cnt == 3)
				{
			        addr=find_function_start(addr);
					C_FOUND(addr);
					break;
				}
			}

		}
    C_RET(addr);
    C_CASE(_ZN9TCProgram8SetTitleEPci)
		unsigned int *set_text;
		unsigned int *get_title=get_dlsym_addr(h,"_ZNK9TCProgram8GetTitleEPcPj");
		if(get_title)
		{
			while(*get_title!=0xE3530004)
				get_title++;
			addr=set_text=get_title;
			clog("Found _ZN9TCProgram9m_SetTextEPcii at: 0x%08x\n",set_text);
			bl_cnt=0;
			while(1)
			{
				addr++;
				if(((*addr  & 0xff000000) == BRANCH_BL) && ((uint)set_text==calculate_branch_addr(addr)) && ++bl_cnt == 4)
				{
			        addr=find_function_start(addr);
					C_FOUND(addr);
					break;
				}
			}

		}
    C_RET(addr);
    C_CASE(_ZN9TCProgramC2Ev)
		addr=get_dlsym_addr(h,"_ZN9TCProgramC1Ev");
    C_RET(addr);
    C_CASE(_ZN9TCProgram10SetEventIdEt)
		addr=get_dlsym_addr(h,"_ZNK9TCProgram9StartTimeEv");
		if(addr)
		{
			int bl_cnt=0;
			addr--;
			while(*addr!=0xE52DB004 || ++bl_cnt!=3)
				addr--;
			C_FOUND(addr);
		}
    C_RET(addr);
    C_CASE(_ZN9TCProgram7SetTimeEjj)
		addr=get_dlsym_addr(h,"_ZNK9TCProgram9StartTimeEv");
		if(addr)
		{
			int bl_cnt=0;
			addr--;
			while(*addr!=0xE52DB004 || ++bl_cnt!=2)
				addr--;
			C_FOUND(addr);
		}
    C_RET(addr);
    C_CASE(_ZN12CCSortedList7DestroyEv)
		addr=get_dlsym_addr(h,"_ZN12CCSortedList4SizeEv");
		if(addr)
		{
			addr--;
			while(*addr!=0xE52DB004)
				addr--;
			C_FOUND(addr);
		}
    C_RET(addr);
    C_CASE(_ZN12CCSortedList3AddEiPv)
		addr=get_dlsym_addr(h,"_ZN12CCSortedList4DataEv");
		if(addr)
		{
			addr=find_next_function_start(addr);
			C_FOUND(addr);
		}
    C_RET(addr);
    C_CASE(_ZN12CCSortedList6CreateEv)
		addr=get_dlsym_addr(h,"_ZN12CCSortedList4DataEv");
		if(addr)
		{
			addr-=2;
			while(*addr!=BX_LR) addr--;
			addr++;
			C_FOUND(addr);
		}
    C_RET(addr);
    C_CASE(CPVRCoreControlMgr_GetMediaInfo)
		addr=find_func_by_string(h, "_XmlParser_handleCharacterData", "GetMediaInfo", F_SEEK_UP,0x80000);
		if(addr)
		{
			addr=find_function_start(addr);
			C_FOUND(addr);
		}
    C_RET(addr);
    C_CASE(CPVRUtil_WritePVRFileInfo)
		addr=find_func_by_string(h, "_XmlParser_handleCharacterData", "WritePVRFileInfo", F_SEEK_UP,0x100000);
		if(addr)
		{
			addr=find_function_start(addr);
			C_FOUND(addr);
		}
    C_RET(addr);
    C_CASE(_ZN9PCWString7ConvertEPcPKtiiPi)
		unsigned int *convert;
		convert=get_dlsym_addr(h,"_ZN9PCWString7ConvertEPtPKciiPi");
		if(convert)
		{
			convert-=0x100/4;
			convert=find_function_start(convert);
			C_FOUND(convert);
		}
    C_RET(convert);
    //C_RET(0x00175DD4);
    C_CASE(_ZN8CPVRUtil10StringSwapEPtPcii)
		unsigned int *trans, *swap=0, *xml, *seekEnd;
		trans=get_dlsym_addr(h,"_ZN8CAppUtil8TransStrEPtPh");
		xml=get_dlsym_addr(h,"_XmlParser_handleCharacterData");
		if(trans && xml)
		{
			seekEnd=xml+0x180000/4;
			for(;xml<seekEnd;xml++)
			{
				if(((*xml & 0xff000000) == BRANCH_BL) && calculate_branch_addr(xml)==(uint)trans)
				{
					clog("Found _ZN8CAppUtil8TransStrEPtPh branch at: 0x%08x\n",xml);
					swap=find_function_start(xml);
					while(*swap!=0xE3510000)
						swap--;
					C_FOUND(swap);
				}
			}
		}
    C_RET(swap);
    return 0;
}
