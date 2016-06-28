APP_OBJ = dvbapi.o hook.o C_support.o log.o
LIB_TV_MODEL= 
CFLAGS += -fPIC -O2 -std=gnu99 
CFLAGS += -ldl -DBUILD_GIT_SHA=\"$(GIT_VERSION)\"
GIT_VERSION := $(shell git describe --dirty --always --abbrev=4)
BRANCH := $(shell git symbolic-ref --short -q HEAD)

ifeq ($(PLATFORM), D-MST)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += models/serie_d_mst.o
	CFLAGS += -mel -mglibc -march=34kc 
endif

ifeq ($(PLATFORM), H-MST)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += models/serie_h_mst.o
	CFLAGS +=  
endif



OBJS = $(APP_OBJ)
LIB:=libdvbapi-${PLATFORM}-${BRANCH}-${GIT_VERSION}.so

# DEFAULT VERSION INFORMATION
CFLAGS += -DLIB_NAME=\""dvbapi"\" -DLIB_VERSION=\""${BRANCH}"\" -DLIB_TV_MODELS=\""${LIB_TV_MODEL}"\"  

all: libdvbapi.so
ifeq ($(LIB_TV_MODEL), )
	$(error No platform selected!)
endif

libdvbapi.so: $(OBJS)	
	$(CROSS)gcc $(CFLAGS) $(OBJS) -shared -Wl,-soname,$(LIB) -o $(LIB)
	
	
#$(CROSS)gcc $(CFLAGS) $(OBJS) -shared -Wl,-soname,$@ -o $@

.c.o:
	$(CROSS)gcc $(CFLAGS) -c -o $@ $<   
   
clean:
	rm -f $(OBJS) ${TARGETS} ./models/*.o

.PHONY: clean
.PHONY: install
