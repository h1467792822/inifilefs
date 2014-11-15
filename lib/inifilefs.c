/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall inifile.c `pkg-config fuse --cflags --libs` -o inifile
*/

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <iniparser.h>
#include <syslog.h>
#include <assert.h>

static dictionary* g_ini = 0;
static const char* g_file_name = 0;

enum {
	null_flag = 0,
	key_flag = 1,
	sec_flag = 2,
	root_flag = 3,
};

struct dic_key {
	int flag;
	char* key;
	char* semi;
};

#define ini_log syslog

static inline void path_to_dic_key(const char* p,struct dic_key* key) 
{
	char* path = (char*)p;
	memset(key,0,sizeof(*key));
	key->key = path + 1;
	if( 0 == *key->key) {
		key->flag = root_flag;
		return;
	}
	 
	char* sep = strchr(key->key, '/');
	if (0 == sep) {
		key->flag = sec_flag;
		return;
	}

	char* next = sep + 1;
	if ( 0 == *next) {
		key->flag = sec_flag;
		key->semi = sep;
		*key->semi = 0;
		return;
	}

	if (0 == strchr(next,'/')) {
		key->flag = key_flag;
		key->semi = sep;
		*key->semi = ':';
		return;
	}
	ini_log(LOG_ERR,"invalid path: %s",p);
	key->flag = null_flag;
	return;
}

static inline void dic_key_fini(struct dic_key* key)
{
	if(key->semi) *key->semi = '/';	
}

static int inifile_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;
	char* value;
	struct dic_key dic_key;
	path_to_dic_key(path,&dic_key);
	switch(dic_key.flag) {
	case root_flag:
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		stbuf->st_size = iniparser_getnsec(g_ini);
		break;
	case sec_flag:
		if(iniparser_find_entry(g_ini,dic_key.key)){
			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 2;
			stbuf->st_size = iniparser_getsecnkeys(g_ini,dic_key.key);
		}else {
			res = -ENOENT;
		}
		break;
	case key_flag:
		if(iniparser_find_entry(g_ini,dic_key.key)){
			stbuf->st_mode = S_IFREG | 0755;
			stbuf->st_nlink = 1;
			value = iniparser_getstring(g_ini,dic_key.key,(char*)"");	
			stbuf->st_size = value ? strlen(value) : 0;
		}else {
			res = -ENOENT;
		}
		break;
	default:
		res = -ENOENT;
		break;
	}
	dic_key_fini(&dic_key);
	return res;
}

static inline void inifile_readsecset(struct dic_key* dic_key, void *buf, fuse_fill_dir_t filler)
{
	int cnt = iniparser_getnsec(g_ini);
	int i = 0 ;
	char* sec_name;
	(void)dic_key;
	filler(buf,".",NULL,0);
	filler(buf,"..",NULL,0);
	for(;i < cnt; ++i) {
		sec_name = iniparser_getsecname(g_ini,i);	
		filler(buf,sec_name,NULL,0);
	} 
}

static inline void inifile_readkeyset(struct dic_key* dic_key, void *buf, fuse_fill_dir_t filler)
{
	int cnt = iniparser_getsecnkeys(g_ini,dic_key->key);
	char** key_names = iniparser_getseckeys(g_ini,dic_key->key);
	char* key;
	int i = 0 ;
	filler(buf,".",NULL,0);
	filler(buf,"..",NULL,0);
	for(;i < cnt; ++i) {
		key = strchr(key_names[i],':');
		assert(key);
		++key;
		filler(buf,key,NULL,0);
	} 
}

static int inifile_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;
	int res = 0 ;
	struct dic_key dic_key;
	path_to_dic_key(path,&dic_key);

	switch(dic_key.flag) {
	case root_flag:
		inifile_readsecset(&dic_key,buf,filler);
		break;
	case sec_flag:
		inifile_readkeyset(&dic_key,buf,filler);
		break;
	default:
		res = -ENOENT;
		break;
	}
	dic_key_fini(&dic_key);
	return res;
}

static inline int inifile_readstring(struct dic_key* dic_key, char *buf, size_t size, off_t offset)
{
	char* value = iniparser_getstring(g_ini,dic_key->key,(char*)"");
	size_t len = value ? strlen(value) : 0;
	if (offset < len) {
		if(offset + size > len) size = len - offset;
		memcpy(buf,value + offset,size);
	}else {
		size = 0;
	}
	return size;
}

static int inifile_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	(void) fi;
	int res = -ENOENT ;
	struct dic_key dic_key;
	path_to_dic_key(path,&dic_key);
	if (dic_key.flag == key_flag) {
		res = inifile_readstring(&dic_key,buf,size,offset);
	}
	dic_key_fini(&dic_key);
	return res;
}

static inline int inifile_writestring(struct dic_key* dic_key, const char *buf, size_t size, off_t offset)
{
	if(size + offset > 1024) {
		return -ENOMEM;
	}
	char new_value[size + offset];
	memset(new_value,' ',size + offset);
	memcpy(new_value + offset,buf,size);
	char* value = iniparser_getstring(g_ini,dic_key->key,(char*)"");
	size_t len = value ? strlen(value) : 0;
	if (offset < len) {
		memcpy(new_value,value,offset);
	}else {
		memcpy(new_value,value,len);
	}
	iniparser_set(g_ini,dic_key->key,new_value);
	return size;
}

static int inifile_write(const char *path, const char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	const char* nend = buf;
	while(*nend && (nend - buf) < size && *nend != '\n' && *nend != '\r') ++nend;	
	size_t avail_size = nend - buf;
	if(avail_size < size) {
		ini_log(LOG_WARNING,"invalid char(s) in buf: %*s",(int)size,buf);
	}
	(void) fi;
	int res = -ENOENT ;
	struct dic_key dic_key;
	path_to_dic_key(path,&dic_key);
	if (dic_key.flag == key_flag) {
		inifile_writestring(&dic_key,buf,avail_size,offset);
		res = size;
	}
	dic_key_fini(&dic_key);
	return res;
}

static void* inifile_init(struct fuse_conn_info* ci)
{
	(void)ci;
	openlog("FS_INI",LOG_PID,LOG_USER);
	return 0;
}

static int inifile_flush(const char* path,struct fuse_file_info* fi);
static void inifile_destroy(void* user_data) 
{
	(void)user_data;
	(void)inifile_flush(0,0);
	if(g_ini) iniparser_freedict(g_ini);
	if(g_file_name) free(g_file_name);
	g_ini = 0;
}

static int inifile_truncate_do(struct dic_key* dic_key,off_t offset)
{
	char* value = iniparser_getstring(g_ini,dic_key->key,(char*)"");
	if (value){
	size_t len = strlen(value);
	if (offset < len) {
		value[offset] = 0;
		iniparser_set(g_ini,dic_key->key,value);
	}
	}
	return 0;
}

static int inifile_truncate(const char* path,off_t offset)
{
	int res = -ENOENT ;
	struct dic_key dic_key;
	path_to_dic_key(path,&dic_key);
	if (dic_key.flag == key_flag){
		res = inifile_truncate_do(&dic_key,offset);
	}
	dic_key_fini(&dic_key);
	return res;		
}

static inline int inifile_mkdir_do(struct dic_key* dic_key)
{
	int res = iniparser_set(g_ini,dic_key->key,"");
	if( res == 0) return 0;
	return -EEXIST;	
}

static int inifile_mkdir(const char* path,mode_t mode)
{
	(void)mode;
	int res = -ENOENT ;
	struct dic_key dic_key;
	path_to_dic_key(path,&dic_key);
	if (dic_key.flag == sec_flag) {
		res = inifile_mkdir_do(&dic_key);
	}
	dic_key_fini(&dic_key);
	return res;
}

static inline int inifile_mknod_do(struct dic_key* dic_key)
{
	int found = iniparser_find_entry(g_ini,dic_key->key);
	if (found) return -EEXIST;
	(void)iniparser_set(g_ini,dic_key->key,"");
	return 0;
}

static int inifile_mknod(const char* path,mode_t mode,dev_t dev)
{
	(void)dev;
	(void)mode;
	int res = -ENOENT ;
	struct dic_key dic_key;
	path_to_dic_key(path,&dic_key);
	if (dic_key.flag == key_flag) {
		res = inifile_mknod_do(&dic_key);
	}
	dic_key_fini(&dic_key);
	return res;
}

static int inifile_create(const char* path,mode_t mode,struct fuse_file_info* fi)
{
	(void)mode;
	(void)fi;
	int res = -ENOENT;
	struct dic_key dic_key;
	path_to_dic_key(path,&dic_key);
	if(dic_key.flag == key_flag) {
		int found = iniparser_find_entry(g_ini,dic_key.key);
		if( 0 == found) {
			if(0 == iniparser_set(g_ini,dic_key.key,"")) res = 0;
		}
	}
	dic_key_fini(&dic_key);
	return res;
}

static int inifile_open(const char* path,struct fuse_file_info* fi)
{
	int res = -ENOENT;
	struct dic_key dic_key;
	path_to_dic_key(path,&dic_key);
	if(dic_key.flag == key_flag) {
	int found = iniparser_find_entry(g_ini,dic_key.key);
	if(found) {
		res = 0;
		if(fi->flags & O_TRUNC) {
			iniparser_set(g_ini,dic_key.key,"");
		}
	}else if(fi->flags & O_CREAT){
		res = 0;
		iniparser_set(g_ini,dic_key.key,"");
	}
	}
	dic_key_fini(&dic_key);
	return res;
}

static int inifile_opendir(const char* path,struct fuse_file_info* fi)
{
	(void)fi;
	int res = -ENOENT;
	struct dic_key dic_key;
	path_to_dic_key(path,&dic_key);
	if(dic_key.flag == root_flag) {
		res = 0;
	}else if( dic_key.flag == sec_flag) {
		int found = iniparser_find_entry(g_ini,dic_key.key);
		if (found) res = 0;
	}
	dic_key_fini(&dic_key);
	return res;
}

static int inifile_flush(const char* path,struct fuse_file_info* fi)
{
	(void)path;
	(void)fi;
	int res = -ENOMEM;
	FILE* f = fopen(g_file_name,"w+");
	if (f) {
		iniparser_dump_ini(g_ini,f);
		fclose(f);
		res = 0;
	}
	return res;
}

#define inifile_release inifile_releasedir

static int inifile_releasedir(const char* path,struct fuse_file_info* fi)
{
	(void)path;
	(void)fi;
	return 0;
}

static int inifile_fgetattr(const char* path,struct stat* stat,struct fuse_file_info* fi)
{
	(void)fi;
	return inifile_getattr(path,stat);
}

static int inifile_ftruncate(const char* path,off_t offset,struct fuse_file_info* fi)
{
	(void)fi;
	return inifile_truncate(path,offset);
}

static int inifile_fsync(const char* path,int n,struct fuse_file_info* fi)
{
	(void)path;
	(void)fi;
	(void)n;
	return 0;
}

#define inifile_fsyncdir inifile_fsync

static int inifile_access(const char* path,int access)
{
	(void)path;
	(void)access;
	return 0;
}

static int inifile_utimens (const char * path, const struct timespec tv[2])
{
	(void)path;
	(void)tv;
	return 0;
}

static struct fuse_operations inifile_oper = {
	.getattr	= inifile_getattr,
	.readdir	= inifile_readdir,
	.read		= inifile_read,
	.write		= inifile_write,
	.init		= inifile_init,
	.destroy	= inifile_destroy,
	.truncate	= inifile_truncate,
	.mkdir		= inifile_mkdir,
	.mknod		= inifile_mknod,
	.flush		= inifile_flush,
	.open		= inifile_open,
	.release	= inifile_release,
	.opendir	= inifile_opendir,
	.releasedir	= inifile_releasedir,
	.create		= inifile_create,
	.fgetattr	= inifile_fgetattr,
	.ftruncate	= inifile_ftruncate,
	.fsync		= inifile_fsync,
	.fsyncdir	= inifile_fsyncdir,
	.access		= inifile_access,
	.utimens	= inifile_utimens,
};

int inifilefs_mount(const char* ini,int argc, char *argv[])
{
	assert(ini);
	if( argc < 2 ) {
		ini_log(LOG_ERR,"%s","lack of mounted dir");
		return 1;
	}	

	int err = 0;
	int len = strlen(ini);
	g_file_name = malloc(len + 1);
	if (0 == g_file_name) {
		ini_log(LOG_ERR,"%s","lack of mounted dir");
	}
	strcpy(g_file_name,ini);

	FILE* f = fopen(g_file_name,"a+");
	if(f) {
		fclose(f);
	}
	g_ini = iniparser_load(g_file_name);	
	if (g_ini == 0) {
		ini_log(LOG_ERR,"failed to load inifile: %s\n",argv[argc - 1]);
		err = 1;
		goto fail;
	}
	err = fuse_main(argc, argv, &inifile_oper, NULL);
	if ( err ) {
		ini_log(LOG_ERR,"failed to fuse_main: %s\n",argv[1]);
	}
	iniparser_freedict(g_ini);
fail:
	free(g_file_name);
	return err;
}


