TARGETS=libdvbapi.so
 
CFLAGS += -fPIC -O2 -std=gnu99 -I../include -mglibc -march=34kc
CFLAGS += -ldl -DBUILD_GIT_SHA=\"$(GIT_VERSION)\"
GIT_VERSION := $(shell git describe --dirty --always --abbrev=4)

# DEFAULT VERSION INFORMATION
CFLAGS += -DLIB_NAME=\""dvbapi"\" -DLIB_VERSION=\""v0.1"\" -DLIB_TV_MODELS=\""D T-MST"\"

all: ${TARGETS} 
    	
libdvbapi.so: dvbapi.c hook.c C_support.c log.c models/serie_d_mst.c $(wildcard *.h) $(wildcard ../include/*.h)
	$(CROSS)gcc $(filter %.c %.cpp,$^) ${CFLAGS} -mel -shared -Wl,-soname,$@ -o $@

clean:
	rm -f ${TARGETS}

ifeq (${TARGET_IP}, )
endif

install: ${TARGETS}
	ping -c1 -W1 -w1 ${TARGET_IP} >/dev/null && \
        lftp -v -c "open ${TARGET_IP};cd ${TARGET_DEST_DIR};mput $^;"

.PHONY: clean
.PHONY: install
