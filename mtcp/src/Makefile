# TODO: Make this Makefile.in pretty

.PHONY: clean libccp

### TARGET ###
PS=0
DPDK=1
ENFORCE_RX_IDLE=0
NETMAP=0
ONVM=0
LRO=0
CCP=
HWCSUM=1
MTCP_LIB_DIR=../lib
MTCP_LIB=libmtcp.a
MTCP_HDR_DIR=../include
MTCP_HDR = mtcp_api.h mtcp_epoll.h
NIC_CACHE=1
PKGCONF = pkg-config
### GCC ###
GCC=gcc

### FLAGS ###
ifeq ($(shell uname -m),x86_64)
GCC_OPT = -m64
else
GCC_OPT =
endif

#
# DBGMSG      	= Enable macro to print all ingress icmp, ip & ip packets (in _log file)
# DBGFUNC     	= Enable macro to print func trace as followed by an ingress packet (in _log file)
# STREAM      	= Enable macro to print tcp_streams module operations (in _log file)
# STATE       	= Enable macro to print change in tcp states (in _log file)
# STAT        	= Not used
# APP         	= Enable macro to print app-specific debug statements (in _log file)
# EPOLL       	= Enable macro to print epoll-related operations (in _log file)
# DUMP_STREAM 	= Enable macro to print tcp_streams (in _log file)
# NETSTAT     	= Enable macro to print net stats
# INFO        	= Enable macro to print general statements
# DBGERR      	= Enable macro to print error statements
# DBGCERR     	= Enable macro to print error statements
#

GCC_OPT += -Wall -fPIC -fgnu89-inline -DENABLE_FLEX_BUFFER -DUSE_DPDK_MEMPOOL -DENABLE_FLEX_RATE_LIMIT -DENABLE_META_BATCH=0
#-DENABLE_RTT_CHECK #-DENABLE_HRCHY_SCHED -DENABLE_DUMMY_CMD 
#DBG_OPT = -DDBGMSG -DDBGFUNC -DSTREAM -DSTATE -DTSTAT -DAPP -DEPOLL
#DBG_OPT = -DDBGMSG -DDBGFUNC -DSTREAM -DSTATE
#DBG_OPT = -DDBGFUNC
#DBG_OPT += -DPKTDUMP
#DBG_OPT += -DDUMP_STREAM
#GCC_OPT += -g -DNETSTAT -DINFO -DDBGERR -DDBGCERR
GCC_OPT += -DNDEBUG -g -DNETSTAT -DINFO -DDBGERR -DDBGCERR
#GCC_OPT += -DNDEBUG -g -DNETSTAT -DINFO -DDBGERR -DDBGCERR
GCC_OPT += $(DBG_OPT)
GCC_OPT += -D__USRLIB__

ifeq ($(LRO),1)
GCC_OPT += -DENABLELRO
endif

ifeq ($(CCP),1)
GCC_OPT += -DUSE_CCP
endif

ifeq ($(HWCSUM),0)
GCC_OPT += -DDISABLE_HWCSUM
endif

### LIBRARIES AND INCLUDES ###
INC_DIR=./include
INC= -I$(INC_DIR)

ifeq ($(PS),1)
LIBS = -lps
else
INC += -DDISABLE_PSIO
endif

ifeq ($(NETMAP),1)
# do nothing
else
INC += -DDISABLE_NETMAP
endif

ifeq ($(ONVM),1)
ifeq ($(RTE_TARGET),)
$(error "Please define RTE_SDK environment variable")
endif
INC += -I/onvm_nflib
INC += -I/lib
INC += -DENABLE_ONVM
LDFLAGS += /onvm_nflib/$(RTE_TARGET)/libonvm.a
LDFLAGS += /lib/$(RTE_TARGET)/lib/libonvmhelper.a -lm
endif


# PacketShader LIBRARY and HEADER
PS_DIR=../../io_engine
INC += -I$(PS_DIR)/include

# CFLAGS for DPDK-related compilation
ifeq ($(DPDK), 1)
#include $(RTE_SDK)/mk/rte.vars.mk
CFLAGS+=-g -D_GNU_SOURCE#-O2
CFLAGS+= $(shell $(PKGCONF) --cflags libdpdk)
ifeq ($(ENFORCE_RX_IDLE), 1)
INC += -DENFORCE_RX_IDLE -DRX_IDLE_THRESH=0
endif
else
INC += -DDISABLE_DPDK
endif

ifeq ($(CCP), 1)
LIBCCP_PATH=./libccp
CCP_LIBS = -L$(LIBCCP_PATH) -lccp
CCP_INC = -I$(LIBCCP_PATH)
endif

### SOURCE CODE ###
SRCS = core.c tcp_stream.c config.c api.c eventpoll.c socket.c pipe.c \
	   tcp_util.c eth_in.c ip_in.c tcp_in.c eth_out.c ip_out.c tcp_out.c \
	   arp.c timer.c cpu.c rss.c addr_pool.c fhash.c memory_mgt.c logger.c debug.c \
	   tcp_rb_frag_queue.c tcp_ring_buffer.c tcp_send_buffer.c tcp_sb_queue.c tcp_stream_queue.c \
	   psio_module.c io_module.c dpdk_module.c netmap_module.c onvm_module.c icmp.c  \
	   mtcp_sendfile.c zero_copy.c file_buffer.c frd_liburing.c rate_limit.c frd_offload_ctrl.c\
	   flex_buffer.c cache_buffer.c general_data_buffer.c aligned_mempool.c flex_debug.c \
	   frd_rate_limit.c meta_offload.c
#frd_mmap.c frd_liburing.c frd_posix_read.c frd_libaio.c frd_liburing_sq_poll.c


ifeq ($(NIC_CACHE), 1)
CFLAGS += -DENABLE_JUMBO_FRAME=0 -DENABLE_NIC_CACHE=1 -DENABLE_NIC_CACHE_FUNC_CALL=1 -I/home/ubuntu/flexserver/control_plane/include
CFLAGS += -DENABLE_MTCP_TSO=1 -DZERO_COPY=1 #-DENABLE_FILE_READ_WORKER=1
CFLAGS += -DENABLE_ASYNC_FILE_READ=1 
SRCS += nic_cache.c meta_send_buffer.c
endif

ifeq ($(CCP), 1)
SRCS += ccp.c clock.c pacing.c
endif

OBJS = $(patsubst %.c,%.o,$(SRCS))
DEPS = $(patsubst %.c,.%.d,$(SRCS))

ifeq ($V,) # no echo
	export MSG=@echo
	export HIDE=@
else
	export MSG=@\#
	export HIDE=
endif

### GOALS ###
ifeq ($(CCP), 1)
all: default libccp
else
all: default
endif

default: $(OBJS) $(MTCP_HDR)
	mkdir -p $(MTCP_LIB_DIR)
	ar rvs $(MTCP_LIB_DIR)/$(MTCP_LIB) $(OBJS) 

ifeq ($(CCP), 1)
libccp:
	$(MAKE) -C ./libccp
endif

$(OBJS): %.o: %.c Makefile
	$(MSG) "   CC $<"
	$(HIDE) $(GCC) $(CFLAGS) $(GCC_OPT) $(INC) -c $< -o $@
$(DEPS): .%.d: %.c Makefile
	$(HIDE) $(GCC) $(GCC_OPT) $(INC) -MM $(CFLAGS) $< > $@

-include $(DEPS)

$(MTCP_HDR):
	cp $(INC_DIR)/$@ $(MTCP_HDR_DIR)/$@

clean: clean-library
	$(MSG) "   CLEAN *.o's"
	$(HIDE) rm -f *.o *~ core
	$(MSG) "   CLEAN *.d's"
	$(HIDE) rm -f .*.d

clean-library:
	$(MSG) "   CLEAN *.a"
	$(HIDE) rm -f $(MTCP_LIB_DIR)/*
	$(MSG) "   CLEAN *.h"
	$(HIDE) rm -f $(MTCP_HDR_DIR)/*

distclean: clean
	rm -f Makefile
