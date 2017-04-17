APP_OBJ = 
LIB_TV_MODEL= 
CFLAGS += -fPIC -O2 -std=gnu99 -Wall
CFLAGS += -ldl -DBUILD_GIT_SHA=\"$(GIT_VERSION)\"
GIT_VERSION := $(shell git describe --dirty --always --abbrev=7)
TAG := $(shell git describe --tags)
SVN_REV:=999

ifeq ($(PLATFORM), D-MST)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += src/oscamLib_D_T-MST.o common_D/hook.o
	CFLAGS += -mglibc -march=34kc -mel -DSPECIAL_HOOK  
endif

ifeq ($(PLATFORM), D-MST-NEW)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += src/oscamLib_D_T-MST_NEW.o common_D/hook.o
	CFLAGS += -mglibc -march=34kc -mel -DSPECIAL_HOOK  
endif

ifeq ($(PLATFORM), E)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += src/oscamLib_E_NON-MST.o common/hook.o
	CFLAGS +=  
endif

ifeq ($(PLATFORM), H-MST)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += src/oscamLib_H_T-MST.o common/hook.o
	CFLAGS +=  
endif

ifeq ($(PLATFORM), E-MST)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += src/oscamLib_E_T-MST.o common/hook.o
	CFLAGS +=  
endif

ifeq ($(PLATFORM), F)
	LIB_TV_MODEL=${PLATFORM}	
	APP_OBJ += src/oscamLib_F_NON-MST.o common/hook.o
	CFLAGS +=  
endif

ifeq ($(PLATFORM), F-MST)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += src/oscamLib_F_T-MST.o common/hook.o	
	CFLAGS +=  
endif

ifeq ($(PLATFORM), H-GFS)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += src/oscamLib_T-GFS.o common/hook.o		
	CFLAGS +=  
endif

ifeq ($(PLATFORM), H-TNT)
	LIB_TV_MODEL=${PLATFORM}
	APP_OBJ += src/oscamLib_T-NT.o common_T-NT/hook.o		
	CFLAGS +=  
endif


OBJS = $(APP_OBJ)
LIB:=libdvbapi-${PLATFORM}-${TAG}.so

# DEFAULT VERSION INFORMATION
CFLAGS += -DLIB_NAME=\""libdvbapi_$(PLATFORM)"\" -DSVN_REV=\""$(SVN_REV)"\" 
#-DLIB_VERSION=\""${TAG}"\" -DLIB_TV_MODELS=\""${LIB_TV_MODEL}"\"  

all: libdvbapi.so
ifeq ($(LIB_TV_MODEL), )
	$(error No platform selected!)
endif

libdvbapi.so: $(OBJS)	
	$(CROSS)gcc $(CFLAGS) $(OBJS) $(LDFLAGS) -shared -Wl,-soname,$(LIB) -o $(LIB)
	
.c.o:
	$(CROSS)gcc $(CFLAGS) -c -o $@ $<   
   
clean:
	rm -f $(OBJS) ${TARGETS} ./src/*.o *.so common/*.o common_D/*.o common_T-NT/*.o

.PHONY: clean
.PHONY: install