from distutils.core import setup, Extension

nl = Extension('_netlink',
			   sources = ['netlink.c'])

setup (name = 'nl',
	   version = '1.0',
	   description = 'netlink stuff',
	   ext_modules = [nl])
