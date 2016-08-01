APP_OBJ = dvbapi.o hook.o log.o models.o
LIB_TV_MODEL= 
CFLAGS += -fPIC -O2 -std=gnu99 -Wall
CFLAGS += -ldl -DBUILD_GIT_SHA=\"$(GIT_VERSION)\"
GIT_VERSION := $(shell git describe --dirty --always --abbrev=7)
TAG := $(shell git describe --tags)


ifeq ($(PLATFORM), D-MST)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += models/serie_d_mst.o
	CFLAGS += -mglibc -march=34kc -mel -DSPECIAL_HOOK  
endif

ifeq ($(PLATFORM), H-MST)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += models/serie_h_mst.o
	CFLAGS +=  
endif

ifeq ($(PLATFORM), E)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += models/serie_e.o
	CFLAGS +=  
endif

ifeq ($(PLATFORM), E-MST)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += models/serie_e_mst.o
	CFLAGS +=  
endif

ifeq ($(PLATFORM), D)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += models/serie_d.o
	CFLAGS +=  
endif

ifeq ($(PLATFORM), F)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += models/serie_f.o
	CFLAGS +=  
endif

ifeq ($(PLATFORM), F-MST)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += models/serie_f_mst.o
	CFLAGS +=  
endif


ifeq ($(PLATFORM), H-TNT)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += models/serie_h_TNT.o
	CFLAGS +=  
endif

OBJS = $(APP_OBJ)
LIB:=libdvbapi-${PLATFORM}-${TAG}.so

# DEFAULT VERSION INFORMATION
CFLAGS += -DLIB_NAME=\""dvbapi"\" -DLIB_VERSION=\""${TAG}"\" -DLIB_TV_MODELS=\""${LIB_TV_MODEL}"\"  

all: libdvbapi.so
ifeq ($(LIB_TV_MODEL), )
	$(error No platform selected!)
endif

libdvbapi.so: $(OBJS)	
	$(CROSS)gcc $(CFLAGS) $(OBJS) $(LDFLAGS) -shared -Wl,-soname,$(LIB) -o $(LIB)
	
	
#$(CROSS)gcc $(CFLAGS) $(OBJS) -shared -Wl,-soname,$@ -o $@

.c.o:
	$(CROSS)gcc $(CFLAGS) -c -o $@ $<   
   
clean:
	rm -f $(OBJS) ${TARGETS} ./models/*.o *.so

.PHONY: clean
.PHONY: install