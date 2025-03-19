srv_deps = [
	dependency('threads'),
	dependency('libxxhash'),
]

srv_deps += libdpdk

#cp_inc = [dpdk_include]
#cp_ldflags = [dpdk_ldflags]

src = [
	'core.c',
	'config.c',
	'item.c',
	'item_mp.c',
	'item_queue.c',
	'rb_tree.c',
	'cache.c',
	'hashtable.c',
	'debug.c',
	'log.c',
	'net.c',
	'l2cache/block.c',
	'cache/hyperbolic.c',
	'cache/lfu.c',
	'cache/lru.c',
]

c_args = [
	'-D_GNU_SOURCE',
	'-march=native',
	'-g',
]

libcp = static_library('cp',
	sources : src,
	#	include_directories : cp_inc,
	c_args : c_args,
	#link_args : cp_ldflags,
	dependencies : srv_deps,
	install : true,
	install_dir : lib_path)

install_headers('control_plane.h',
	install_dir : inc_path)

subdir('log')
