project('cnic', 'c', meson_version : '>=0.53.0')

base_dir = meson.source_root()
bin_dir = base_dir + '/bin'
cc = meson.get_compiler('c')
cnic_deps=[]
cflags = []
library_name = ['numa', 'dl', 'rt', 'm', 'libc']

libdpdk = dependency('libdpdk')

foreach name : library_name 
	l = cc.find_library(name, required : true)
	cnic_deps += l
endforeach

cnic_deps += cc.find_library('uring', required : true, static : true)

cnic_deps += libdpdk
cnic_deps += dependency('threads')

optimization = get_option('optimization')
sources=files(
	'dataplane.c',
	'dpdk_io.c',
	'blk.c',
	'chnk_ht.c',
	'config.c',
	'debug.c',
	'log.c',
	'rate_limit.c',
	'fht.c',
	'frd_offload.c',
    'memory_mgt.c',
    'aligned_mempool.c',
    'fb.c',
    'meta_reply.c',
)

cflags += ['-D_GNU_SOURCE', '-DENABLE_REPLY_BATCH=0', '-DENABLE_FRD_OFFLOAD=0'] 
cflags += ['-g']
#cflags += ['-D_NOTIFYING_MBPS'] # -D_GOODPUT

executable('dataplane',
		   sources : sources,
		   dependencies : cnic_deps,
		   c_args : cflags)
		   #		   include_directories : ['liburing/src/include'],
		   #link_args : link_args)

configure_file(input : 'dataplane.cfg',
			   output : 'dataplane.cfg',
			   copy : true)
