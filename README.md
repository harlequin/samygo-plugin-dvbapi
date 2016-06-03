# samygo-plugin-dvbapi
free samygo dvbapi injection

SOFTWARE IS CURRENTLY IN DEVELOPMENT

Based on:
 * vdr-plugin-dvbapi (manio): https://github.com/manio/vdr-plugin-dvbapi
 * libOSCAM v0.4.0 (bugficks): (sorry, cannot find URL with original code)

### Command line arguments
- OSCAM_SERVER_IP:xxx.xxx.xxx.xxx - OSCAM dvbapi server address
- OSCAM_SERVER_PORT:xxxxx - OSCAM dvbapi listenport
- EMM - Enables emm messages

### Example call format
samyGOso -D -r -l /mtd_rwdata/oscam/libdvbapi.so OSCAM_SERVER_IP:192.168.1.48 OSCAM_SERVER_PORT:20000 EMM