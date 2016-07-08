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
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/time.h>   
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <memory.h>
#include <glob.h>
#include <stdarg.h>
#include <pthread.h>
#include <execinfo.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h> /* socket handler */
#include <arpa/inet.h> /* inet_pton */
#include <unistd.h>

#include "utlist.h"
#include "version.h"
#include "hook.h"
#include "common.h"
#include "tv_info.h"
#include "types.h"
#include "log.h"
#include "models.h"

/* CONFIGURATION */
static u8* oscam_server_ip = NULL;
static u16 oscam_server_port = 0;
static u8 oscam_emm_enabled;

static u32 tv_model = 0x00;
static pthread_t x_thread_socket_handler;
static int _hooked = 0;
static u8 socket_connected = 0x00; /* will be set to 1 if handshake was done */
static int protocol_version = 0;
static u8 adapter_index;
static int sockfd;

void socket_send_filter_data(u8 demux_id, u8 filter_num, u8 *data, u32 len) {
	if(!socket_connected) {return;}
	log("send filter data demux_id: 0x%02x filter_num: 0x%02x\n", demux_id, filter_num);
	//log(">>>\n"); print_hash(data, len); log("<<<\n");
	unsigned char buff[6 + len];
	u32 req = htonl(DVBAPI_FILTER_DATA);
	memcpy(&buff[0], &req, 4);
	buff[4] = demux_id;
	buff[5] = filter_num;
	memcpy(buff + 6, data, len);
	write(sockfd, buff, sizeof(buff));

}

static void socket_send_client_info() {
	int len = sizeof(INFO_VERSION) - 1;                     //ignoring null termination
	unsigned char buff[7 + len];
	u32 req = htonl(DVBAPI_CLIENT_INFO);               //type of request
	memcpy(&buff[0], &req, 4);
	u16 proto_version = htons(DVBAPI_PROTOCOL_VERSION); //supported protocol version
	memcpy(&buff[4], &proto_version, 2);
	buff[6] = len;
	memcpy(&buff[7], &INFO_VERSION, len);                   //copy info string
	write(sockfd, buff, sizeof(buff));
}

void socket_send_capmt(pmt_t *pmt) {
	int len = 3 + ((pmt->ptr[1] & 0x0F) << 8) + pmt->ptr[2];

	if( len > 1024 ) {
		log("Unable to send pmt, wrong length: %d\n", len);
		return;
	}

	unsigned char caPMT[1040];
	//program_info_length (+1 for ca_pmt_cmd_id, +4 for CAPMT_DESC_DEMUX)
	int program_info_length = ((pmt->ptr[10] & 0x0F) << 8) + pmt->ptr[11] + 4 + 1;
	int length_field = len - 5;						// 17 - 6 + len - 4 - 12

	//ca_pmt_tag
	caPMT[0] = 0x9F;
	caPMT[1] = 0x80;
	caPMT[2] = 0x32;
	caPMT[3] = 0x82;              					//2 following bytes for size

	caPMT[4] = length_field >> 8;
	caPMT[5] = length_field & 0xff;

	caPMT[6] = pmt->lm; 							//list management
	caPMT[7] = pmt->ptr[3];          				//program_number
	caPMT[8] = pmt->ptr[4];        					//program_number
	caPMT[9] = 0;               					//version_number, current_next_indicator

	caPMT[10] = program_info_length >> 8;           //reserved+program_info_length
	caPMT[11] = program_info_length & 0xFF;         //reserved+program_info_length (+1 for ca_pmt_cmd_id, +4 for above CAPMT_DESC_DEMUX)

	caPMT[12] = 0x01;             					//ca_pmt_cmd_id = CAPMT_CMD_OK_DESCRAMBLING
	//adding own descriptor with demux and adapter_id
	caPMT[13] = 0x82;           					//CAPMT_DESC_DEMUX
	caPMT[14] = 0x02;           					//length
	caPMT[15] = 0x00;           					//demux id
	caPMT[16] = (char)adapter_index;   				//adapter id

	memcpy(caPMT + 17, pmt->ptr + 12, len - 16);  	//copy pmt data starting at program_info block

	write(sockfd, caPMT, length_field + 6);			// dont send the last 4 bytes (CRC)
}

/* SOCKET HANDLER */
static void *socket_handler(void *ptr){
	log("create socket handler\n");

	#define MAXBUF 512

    struct sockaddr_in dest;
    char buffer[MAXBUF];

    /*---Open socket for streaming---*/
    if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
    	log("socket connection error\n");
    } else {
		/*---Initialize server address/port struct---*/
		bzero(&dest, sizeof(dest));
		dest.sin_family = AF_INET;
		dest.sin_port = htons(oscam_server_port);
		if ( inet_pton(AF_INET, oscam_server_ip, &dest.sin_addr) <= 0 ) {
		   log("can't set oscam server destination\n");
		} else {
			/*---Connect to server---*/
			if ( connect(sockfd, (struct sockaddr*)&dest, sizeof(dest)) != 0 ) {
				log("can't connect oscam server destination\n");
				log("%s: connect error: %s", __FUNCTION__, strerror(errno));
			} else {
				log("Client connected ... send DVBAPI_CLIENT_INFO ...\n");
				socket_send_client_info();


				int running = 1;

				int c_read;
				unsigned char buf[262];
				int skip_bytes = 0;
				u32 *request;

				while(running==1) {



					usleep(200);



					c_read = recv(sockfd, &buf[skip_bytes], sizeof(int)-skip_bytes, MSG_DONTWAIT);

					if (c_read <= 0) {
						//if (c_read == 0)
					    //    break;

						//log that connection is broken and everything is stopped

					    //cCondWait::SleepMs(20);
					    continue;
					}

					request = (unsigned int *) &buf;
					skip_bytes = 0;

					if (ntohl(*request) != DVBAPI_SERVER_INFO) {
						// first byte -> adapter_index
						c_read = recv(sockfd, &adapter_index, 1, MSG_DONTWAIT);
						if (c_read <= 0) {
							//if (cRead == 0)
							//	CloseConnection();
							//cCondWait::SleepMs(20);
							continue;
						}
						//adapter_index -= AdapterIndexOffset;
					}



					*request = ntohl(*request);
				    if (*request == DVBAPI_CA_SET_DESCR) {
				    	c_read = recv(sockfd, buf+4, sizeof(ca_descr_t), MSG_DONTWAIT);
				    }else if (*request == DVBAPI_CA_SET_PID) {
				    	/*TODO: Shall we use this?*/
					    c_read = recv(sockfd, buf+4, sizeof(ca_pid_t), MSG_DONTWAIT);
					    continue;
					}else if (*request == DMX_SET_FILTER) {
					    c_read = recv(sockfd, buf+4, sizeof(struct dmx_sct_filter_params), MSG_DONTWAIT);
					} else if (*request == DVBAPI_SERVER_INFO) {
						unsigned char len;
						recv(sockfd, buf+4, 2, MSG_DONTWAIT);
						recv(sockfd, &len, 1, MSG_DONTWAIT);
						c_read = recv(sockfd, buf+6, len, MSG_DONTWAIT);
						buf[6+len] = 0;
					}else if (*request == DVBAPI_ECM_INFO) {
						recv(sockfd, buf+4, 14, MSG_DONTWAIT);

					}else if (*request == DVBAPI_DMX_STOP) {
						c_read = recv(sockfd, buf+4, 2 + 2, MSG_DONTWAIT);

					} else if (*request == CA_SET_DESCR_MODE) {
						/*TODO: Shall we use this?*/
						c_read = recv(sockfd, buf+4, sizeof(ca_descr_mode_t), MSG_DONTWAIT);
						continue;
					} else {
				      log("read failed unknown command: %08x\n", *request);
				      usleep(2000);
				      continue;
				    }

					if (c_read <= 0) {
						//if (c_read == 0)
					    //    CloseConnection();
					    //  cCondWait::SleepMs(20);
					    continue;
					}


					 if (*request == DVBAPI_CA_SET_DESCR) {
						 ca_descr_t ca_descr;
						 memcpy(&ca_descr, &buf[4], sizeof(ca_descr_t));
						 ca_descr.index = ntohl(ca_descr.index);
						 ca_descr.parity = ntohl(ca_descr.parity);
						 log("Got CA_SET_DESCR request, index=0x%04x parity=0x%04x\n", ca_descr.index, ca_descr.parity);
						 dvbapi_set_descriptor(ca_descr);
					 }

					 else if (*request == DVBAPI_DMX_STOP) {
						 u8 demux_index = buf[4];
						 u8 filter_num = buf[5];
						 u16 *pid_ptr = (u16 *) &buf[6];
						 u16 pid = ntohs(*pid_ptr);
						 dvbapi_dmx_stop(demux_index, filter_num, pid);
					 }


					else if (*request == DMX_SET_FILTER) {
						struct dmx_sct_filter_params params;
						unsigned char demux_index = buf[4];
						unsigned char filter_num = buf[5];
						memcpy(&params, &buf[6], sizeof(struct dmx_sct_filter_params));
					    log("Got DMX_SET_FILTER request, pid=0x%02x, byte1=0x%02x, mask1=0x%02x\n", ntohs(params.pid), params.filter.filter[0], params.filter.mask[0] );
					    dvbapi_start_filter (demux_index, filter_num, params);
					} else if(*request == DVBAPI_SERVER_INFO) {
						u16 *proto_ver_ptr = (u16 *) &buf[4];
						protocol_version = ntohs(*proto_ver_ptr);
						log("Got SERVER_INFO: %s, protocol_version = %d\n", &buf[6], protocol_version);
						socket_connected = 0x01;
						dvbapi_server_info();


					}else if (*request == DVBAPI_ECM_INFO) {

						char cardsystem[255];
						char reader[255];
						char from[255];
						char protocol[255];
						      unsigned char len, hops;
						      int i = 4;

						      u16 *sid_ptr = (u16 *) &buf[i];       //ServiceID
						      u16 sid = ntohs(*sid_ptr);
						      i += 2;

						      u16 *caid_ptr = (u16 *) &buf[i];      //CAID
						      u16 caid = ntohs(*caid_ptr);
						      i += 2;

						      u16 *pid_ptr = (u16 *) &buf[i];       //PID
						      u16 pid = ntohs(*pid_ptr);
						      i += 2;

						      u32 *prid_ptr = (u32 *) &buf[i];      //ProviderID
						      u32 prid = ntohl(*prid_ptr);
						      i += 4;

						      u32 *ecmtime_ptr = (u32 *) &buf[i];   //ECM time
						      u32 ecmtime = ntohl(*ecmtime_ptr);

						      //cardsystem name
						      recv(sockfd, &len, 1, MSG_DONTWAIT);               //string length
						      recv(sockfd, cardsystem, len, MSG_DONTWAIT);
						      cardsystem[len] = 0;                             //terminate the string

						      //reader name
						      recv(sockfd, &len, 1, MSG_DONTWAIT);               //string length
						      recv(sockfd, reader, len, MSG_DONTWAIT);
						      reader[len] = 0;                                 //terminate the string

						      //source (from)
						      recv(sockfd, &len, 1, MSG_DONTWAIT);               //string length
						      recv(sockfd, from, len, MSG_DONTWAIT);
						      from[len] = 0;                                   //terminate the string

						      //protocol name
						      recv(sockfd, &len, 1, MSG_DONTWAIT);               //string length
						      recv(sockfd, protocol, len, MSG_DONTWAIT);
						      protocol[len] = 0;                               //terminate the string

						      recv(sockfd, &hops, 1, MSG_DONTWAIT);              //hops

						      log("Got ECM_INFO: adapter_index=%d, SID = %04X, CAID = %04X (%s), PID = %04X, ProvID = %06X, ECM time = %d ms, reader = %s, from = %s, protocol = %s, hops = %d\n", adapter_index, sid, caid, cardsystem, pid, prid, ecmtime, reader, from, protocol, hops);
					} else {
						log("Unknown request: %02X %02X %02X %02X\n", request[0], request[1], request[2], request[3]);
					}

				}
				close(sockfd);
			}

		}
    }
    log("--NEVER BE HERE--\n");
    return NULL;
}

int getArgCArgV(const char *libpath, char **argv) {
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

char* getOptArg(char **argv, int argc, char *option) {
    for(int i=0;i<argc;i++)
    {
        if(strstr(argv[i],option)==argv[i])
        {
            return argv[i]+strlen(option);
        }
    }
    return 0;
}

EXTERN_C void lib_init(void *_h, const char *libpath) {
	u32 argc;
	char *argv[100],*optstr;

    unsigned long *cur_addr,ret,i,k,D, LOG_ALL=0;

    if(_hooked) {
        log("Injecting once is enough!\n");
        return;
    }

    unlink(LOG_FILE);

	void *h = dlopen(0, RTLD_LAZY);

	if(!h) {
		char *serr = dlerror();
		log("dlopen error %s\n", serr);
		return;
	}

	patch_adbg_CheckSystem(h);
	_hooked = dvbapi_install(h);

	/* commandline parameters */
	argc = getArgCArgV(libpath, argv);

	optstr = getOptArg(argv, argc, "OSCAM_SERVER_IP:");
	if(optstr) {
		oscam_server_ip = optstr;
	}

	optstr = getOptArg(argv, argc, "OSCAM_SERVER_PORT:");
	if ( optstr ) {
		oscam_server_port = atoi(optstr);
	}

	if ( !oscam_server_ip || oscam_server_port == 0 ) {
		log("error: oscam network mode needs oscam server ip and oscam server port argument\n");
		return;
	}
	dlclose(h);

	log ("Samsung %s Series [%s]\n", model_type_string(model_type()), model_firmware_string(model_firmware()));
    log ("Hooking the system done ...\n");

    if(pthread_create(&x_thread_socket_handler, NULL, socket_handler, NULL)) {
    	log("error creating socket handler thread\n");
    }
}

EXTERN_C void lib_deinit(void *_h) {
    log("If you see this message you forget to specify -r when invoking hijack :)\n");
}
