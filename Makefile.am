SUBDIRS = lib bin include 

EXTRA_DIST = \
	     README \
	     syslog-inifilefs.conf \
	     libinifilefs.pc.in \
	     $(top_srcdir)/include \
	     $(top_srcdir)/build/Makefile.common

pkgconfigdir = @pkgconfigdir@
pkgconfig_DATA = libinifilefs.pc

$(pkgconfig_DATA): config.status
