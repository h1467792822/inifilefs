
#ifndef _INIFILE_FS_H_
#define _INIFILE_FS_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @param inifile the filename, if not existed, it will be created.
 * @param argc be passed to fuse.
 * @param argv be passed to fuse.
 * @return 0 is ok,others is failed.
 */
int inifilefs_mount(const char* inifile,int argc,char* argv[]);

#ifdef __cplusplus
}
#endif

#endif

