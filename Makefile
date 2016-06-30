APP_OBJ = dvbapi.o hook.o C_support.o log.o
LIB_TV_MODEL= 
CFLAGS += -fPIC -O2 -std=gnu99 
CFLAGS += -ldl -DBUILD_GIT_SHA=\"$(GIT_VERSION)\"
GIT_VERSION := $(shell git describe --dirty --always --abbrev=4)
TAG := $(shell git describe --tags)

SUPPORTED_PLATFORMS = $(subst .c,,$(subst ./models/serie_,, $(wildcard ./models/*.c)))

ifeq ($(filter $(PLATFORM),$(SUPPORTED_PLATFORMS)),)
  $(warning PLATFORM NOT AVAILABLE "$(PLATFORM)")
  $(warning AVAILABLE PLATFORMS "$(SUPPORTED_PLATFORMS)")
  $(error )
endif

APP_OBJ += models/serie_$(PLATFORM).o
LIB_TV_MODEL=${PLATFORM}

ifeq ($(PLATFORM), D-MST)
	CFLAGS += -mglibc -march=34kc -mel 
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
	echo $(SUPPORTED_PLATFORMS)
	$(CROSS)gcc $(CFLAGS) -c -o $@ $<   
   
clean:
	rm -f $(OBJS) ${TARGETS} ./models/*.o

.PHONY: clean
.PHONY: install
