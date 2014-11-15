include $(top_srcdir)/build/Makefile.common

lib_LTLIBRARIES = libinifilefs.la
libinifilefs_la_SOURCES = inifilefs.c
libinifilefs_la_LDFLAGS = @fuseldflags@ @iniparserdir@/libiniparser.a 
libinifilefs_la_CFLAGS = @fusecflags@ -I@iniparserdir@/src 

