project('control_plane', 'c',
		meson_version : '>=0.53')

home_dir = meson.current_source_dir()
cc = meson.get_compiler('c')
# pkg = import('pkgconfig')

#rte_sdk = get_option('RTE_SDK') + '/'
#rte_target = get_option('RTE_TARGET')
inc_path=home_dir + '/include'
lib_path=home_dir + '/lib'

#if rte_sdk == ' '
	#error('Configure RTE_SDK')
#endif

#if rte_target == ' '
	#error('Configure RTE_TARGET')
#endif

#dpdk_include = include_directories(rte_sdk + rte_target + '/include')
#dpdk_ldflags = run_command('cat', rte_sdk + rte_target + '/lib/ldflags.txt',
		#capture : true,
		#check : true).stdout().strip().split()
libdpdk = dependency('libdpdk')
srv_bin_path = home_dir + '/bin'

subdir('src')
