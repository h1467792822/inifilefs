AC_INIT([inifilefs],[0.1],[1467792822@qq.com])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
LT_INIT
AC_PROG_CC
AC_ARG_WITH(pkgconfigdir,
	    [ --with-pkgconfigdir=DIR ],
	    [pkgconfigdir=$withval],
	    [pkgconfigdir='$(libdir)/pkgconfig'])
AC_SUBST(pkgconfigdir)
AC_ARG_WITH(fusecflags,
	    AS_HELP_STRING([--with-fusecflags=CFLAGS default = pkg-config --cflags fuse]),
	    [fusecflags=$withval],
	    [fusecflags=`pkg-config --cflags fuse`])
AC_SUBST(fusecflags)
AC_ARG_WITH(fuseldflags,
	    AS_HELP_STRING([--with-fuseldflags=LDFLAGS default = pkg-config --libs fuse]),
	    [fuseldflags=$withval],
	    [fuseldflags=`pkg-config --libs fuse`])
AC_SUBST(fuseldflags)
AC_ARG_WITH(iniparserdir,
	    AS_HELP_STRING([--with-iniparserdir=DIR the root dir of github.com/nedevilla/iniparser in local]),
	    [iniparserdir=$withval],[iniparserdir=])
AC_SUBST(iniparserdir)
AS_IF([test "x$iniparserdir" = "x"],
      [AC_MSG_ERROR([*** iniparser could not be located,Please use the --with-iniparserdir option ***.])])
AC_CONFIG_FILES([Makefile \
		 include/Makefile \
		 bin/Makefile \
		 lib/Makefile \
		 libinifilefs.pc])
AC_OUTPUT
