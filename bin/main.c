/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall inifile.c `pkg-config fuse --cflags --libs` -o inifile
*/

#include <inifilefs.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	if( argc < 3 ) {
		fprintf(stderr,"failed! usage: %s <mout_dir> [mout_args ...] <inifile>\n",argv[0]);
		return 1;
	}	
	int err = inifilefs_mount(argv[argc - 1],argc - 1, argv);
	if ( err ) {
		fprintf(stderr,"failed to inifilefs_mount: inifile=%s,root=%s\n",argv[argc - 1],argv[1]);
	}
	return err;
}
