CFLAGS += -fPIC -O2 -std=gnu99 -I../include -mglibc
CFLAGS += -ldl -DBUILD_GIT_SHA=\"$(GIT_VERSION)\"
GIT_VERSION := $(shell git describe --dirty --always --abbrev=7)
APP=libdvbapi_H_T-MST-${GIT_VERSION}.so

all: dvbapi.c hook.c C_support.c log.c $(wildcard *.h) $(wildcard ../include/*.h)
	$(CROSS)gcc $(filter %.c %.cpp,$^) ${CFLAGS} -shared -Wl,-soname,${APP} -o ${APP}
    	

clean:
	rm -f libdvbapi*.so

ifeq (${TARGET_IP}, )
endif

install: ${TARGETS}
	ping -c1 -W1 -w1 ${TARGET_IP} >/dev/null && \
        lftp -v -c "open ${TARGET_IP};cd ${TARGET_DEST_DIR};mput $^;"

.PHONY: clean
.PHONY: install
