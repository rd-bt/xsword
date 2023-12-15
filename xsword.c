/*******************************************************************************
 *License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>*
 *This is free software: you are free to change and redistribute it.           *
 *******************************************************************************/
#define _GNU_SOURCE
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <limits.h>
#include <dirent.h>
#include <termios.h>
#define VT_I8 0
#define VT_U8 1
#define VT_I16 2
#define VT_U16 3
#define VT_I32 4
#define VT_U32 5
#define VT_I64 6
#define VT_U64 7
#define VT_FLOAT 8
#define VT_DOUBLE 10
#define VT_LDOUBLE 12
#define VT_ASCII 13
#define VT_STR 14
#define VT_ARRAY 16
#define BUFSIZE 4096
#define FBUFSIZE ((LDBL_MAX_10_EXP+128+16+15)&~15)
#define BUFSIZE_PATH 64
#define BUFSIZE_STDOUT (1024*1024)
#define SIZE_ASET (1024*1024*8)
#define VBUFSIZE (sizeof(long double)>sizeof(uintmax_t)?sizeof(long double):sizeof(uintmax_t))
#define TOCSTR(x) TOCSTR0(x)
#define TOCSTR0(x) #x
const char copyleft[]={
	"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
	"This is free software: you are free to change and redistribute it.\n"};
enum smode {SEARCH_NORMAL,SEARCH_COMPARE,SEARCH_FUZZY,SEARCH_FUZZYFIX};
float epsilon_float=FLT_EPSILON;
double epsilon_double=DBL_EPSILON;
long double epsilon_ldouble=LDBL_EPSILON;
volatile sig_atomic_t freezing=0;
volatile sig_atomic_t next_freezing=0;
char fbuf[FBUFSIZE];
char buf_stdout[BUFSIZE_STDOUT];
char keywords[BUFSIZE];
const char space[256]={[0 ... 255]=' '};
size_t keylen=0;
char cperms[8]={"****"};
size_t align=1;
int quiet=0;
struct addrval {
	off_t addr;
	char val[VBUFSIZE];
};
struct addrset {
	struct addrval *buf;
	size_t size,n;
	int valued;
};
size_t minz(size_t s1,size_t s2){
	return s1>s2?s2:s1;
}
const char *bfname(const char *path){
	const char *p;
	if(path[0]=='/'&&path[1]=='\0')return path;
	p=strrchr(path,'/');
	return p?p+1:path;
}
pid_t getpidbycomm(const char *comm){
	DIR *d;
	long l;
	struct dirent *d1;
	char buf[BUFSIZE];
	int fd;
	ssize_t r;
	pid_t ret=0;
	d=opendir("/proc");
	if(d==NULL)return 0;
	while((d1=readdir(d))){
		if(d1->d_type!=DT_DIR||!(l=atol(bfname(d1->d_name))))continue;
		sprintf(buf,"/proc/%s/comm",d1->d_name);
		fd=open(buf,O_RDONLY);
		if(fd<0)continue;
		if((r=read(fd,buf,BUFSIZE))>0){
			buf[r]=0;
			*strchr(buf,'\n')=0;
			if(!strcmp(buf,comm))ret=(pid_t)l;
		}
		close(fd);
		sprintf(buf,"/proc/%s/cmdline",d1->d_name);
		fd=open(buf,O_RDONLY);
		if(fd<0)continue;
		if(read(fd,buf,BUFSIZE)>0){
			if(!strcmp(buf,comm))ret=(pid_t)l;
		}
		close(fd);
	}
	closedir(d);
	return ret;
}
int vfdprintf_atomic(int fd,const char *restrict format,va_list ap){
	int r;
	char buf[PIPE_BUF];
	if((r=vsnprintf(buf,PIPE_BUF,format,ap))==EOF)return EOF;
	return write(fd,buf,minz(r,PIPE_BUF));
}
int fprintf_atomic(FILE *restrict stream,const char *restrict format,...){
	int fd,r;
	va_list ap;
	fd=fileno(stream);
	if(fd<0)return fd;
	va_start(ap,format);
	r=vfdprintf_atomic(fd,format,ap);
	va_end(ap);
	return r;
}
int fdprintf_atomic(int fd,const char *restrict format,...){
	int r;
	va_list ap;
	va_start(ap,format);
	r=vfdprintf_atomic(fd,format,ap);
	va_end(ap);
	return r;
}
void *memmem_aligned(const void *haystack, size_t haystacklen,const void *needle, size_t needlelen,size_t alignment){
	const char *hay;
	switch(alignment){
		case 1:
			return memmem(haystack,haystacklen,needle,needlelen);
		case 0:
			return NULL;
		default:
			hay=haystack;
			while(haystacklen>=needlelen){
				if(!memcmp(hay,needle,needlelen))return (void *)hay;
				haystacklen-=alignment;
				hay+=alignment;
			}
			return NULL;
	}
}
void aset_init(struct addrset *restrict aset){
	aset->buf=NULL;
	aset->size=0;
	aset->n=0;
	aset->valued=0;
}

int aset_addv(struct addrset *restrict aset,off_t addr,const void *_Nullable val,size_t len){
	void *nbuf;
	while(aset->n>=aset->size){
		nbuf=realloc(aset->buf,(aset->size+SIZE_ASET)*sizeof(struct addrval));
		if(!nbuf)return -errno;
		aset->buf=nbuf;
		aset->size+=SIZE_ASET;
	}
	aset->buf[aset->n].addr=addr;
	if(val){
		memcpy(aset->buf[aset->n].val,val,len>=VBUFSIZE?VBUFSIZE:len);
		aset->valued=1;
	}
	++aset->n;
	return 0;
}
int aset_add(struct addrset *restrict aset,off_t addr){
	void *nbuf;
	while(aset->n>=aset->size){
		nbuf=realloc(aset->buf,(aset->size+SIZE_ASET)*sizeof(struct addrval));
		if(!nbuf)return -errno;
		aset->buf=nbuf;
		aset->size+=SIZE_ASET;
	}
	aset->buf[aset->n].addr=addr;
	memset(aset->buf[aset->n].val,0,VBUFSIZE);
	++aset->n;
	return 0;
}
void aset_free(struct addrset *restrict aset){
	if(aset->buf)free(aset->buf);
	aset->buf=NULL;
}
void aset_wipe(struct addrset *restrict aset){
	aset_free(aset);
	aset_init(aset);
}
void aset_list(struct addrset *restrict aset,int fdmem,int vtype,size_t len){
	size_t i;
	char *buf;
	int64_t l;
	uint64_t u;
	int toa=0,r;
		switch(vtype){
			case VT_STR:
			case VT_ASCII:
				break;
			case VT_I8:
			case VT_U8:
				len=sizeof(int8_t);
				goto num;
			case VT_I16:
			case VT_U16:
				len=sizeof(int16_t);
				goto num;
			case VT_I32:
			case VT_U32:
				len=sizeof(int32_t);
				goto num;
			case VT_I64:
			case VT_U64:
				len=sizeof(int64_t);
				goto num;
num:
				toa=1;
				break;
			case VT_FLOAT:
				len=sizeof(float);
				goto fnum;
			case VT_DOUBLE:
				len=sizeof(double);
				goto fnum;
			case VT_LDOUBLE:
				len=sizeof(long double);
				goto fnum;
fnum:
				toa=2;
				break;
			default:
				break;
		}
	buf=malloc((len+15)&~15);
	if(!buf){
		fdprintf_atomic(STDERR_FILENO,"failed (%s)\n",strerror(errno));
		return;
	}
		freezing=1;
	for(i=0;i<aset->n&&freezing;++i){
		if(pread(fdmem,buf,len,aset->buf[i].addr)<=0){
			fprintf(stdout,"%lx ???\n",aset->buf[i].addr);
			continue;
		}
		fprintf(stdout,"%lx :",aset->buf[i].addr);
		switch(toa){
			case 1:
			l=(buf[len-1]&0x80)?-1:0;
			memcpy(&l,buf,len);
			u=0;
			memcpy(&u,buf,len);
			fprintf(stdout," %ld\t%luu\t0%lo\t0x%lx",l,u,u,u);
			if(aset->valued&&memcmp(aset->buf[i].val,buf,len)){
				l=(aset->buf[i].val[len-1]&0x80)?-1:0;
				memcpy(&l,aset->buf[i].val,len);
				u=0;
				memcpy(&u,aset->buf[i].val,len);
				fprintf(stdout," from : %ld\t%luu\t0%lo\t0x%lx",l,u,u,u);
			}
			break;
			case 2:
			switch(vtype){
			case VT_FLOAT:
			r=sprintf(fbuf," %.128f",*(float *)buf);
			goto endf;
			case VT_DOUBLE:
			r=sprintf(fbuf," %.128lf",*(double *)buf);
			goto endf;
			case VT_LDOUBLE:
			r=sprintf(fbuf," %.128Lf",*(long double *)buf);
			goto endf;
endf:
			fbuf[r]='0';
			while(fbuf[--r]=='0');
			fwrite(fbuf,1,r+2,stdout);
			if(aset->valued&&memcmp(aset->buf[i].val,buf,len))
				switch(vtype){
					case VT_FLOAT:
					r=sprintf(fbuf," %.128f",*(float *)aset->buf[i].val);
					goto endf1;
					case VT_DOUBLE:
					r=sprintf(fbuf," %.128lf",*(double *)aset->buf[i].val);
					goto endf1;
					case VT_LDOUBLE:
					r=sprintf(fbuf," %.128Lf",*(long double *)aset->buf[i].val);
					goto endf1;
endf1:
				fbuf[r]='0';
				while(fbuf[--r]=='0');
				fwrite(" from :",1,8,stdout);
				fwrite(fbuf,1,r+2,stdout);
				default:
					break;
			}
			break;
			default:
			fprintf(stdout," ???");
			break;
			}
			break;
			case 0:
				fwrite(buf,1,len,stdout);
				break;
		}
		fputc('\n',stdout);
	}
	fflush(stdout);
	freezing=0;
	free(buf);
}
void aset_wlist(struct addrset *restrict aset,int fdmem,int vtype){
	size_t i=0,len;
	char *buf;
		switch(vtype){
			case VT_STR:
			case VT_ASCII:
				return;
			case VT_I8:
			case VT_U8:
				len=sizeof(int8_t);
				break;
			case VT_I16:
			case VT_U16:
				len=sizeof(int16_t);
				break;
			case VT_I32:
			case VT_U32:
				len=sizeof(int32_t);
				break;
			case VT_I64:
			case VT_U64:
				len=sizeof(int64_t);
				break;
			case VT_FLOAT:
				len=sizeof(float);
				break;
			case VT_DOUBLE:
				len=sizeof(double);
				break;
			case VT_LDOUBLE:
				len=sizeof(long double);
				break;
			default:
				return;
		}
	buf=malloc((len+15)&~15);
	freezing=1;
	while(i<aset->n&&freezing){
		if(pread(fdmem,buf,len,aset->buf[i].addr)==len){
			aset->valued=1;
			memcpy(aset->buf[i].val,buf,len);
		}
		++i;
	}
	freezing=0;
	free(buf);
}
void aset_write(struct addrset *restrict aset,int fdmem,void *val,size_t len){
	size_t i=0;
	while(i<aset->n){
		pwrite(fdmem,val,len,aset->buf[i].addr);
		++i;
	}
}
int permscmp(const char *restrict s1,const char *restrict s2){
	int i;
	for(i=0;i<4;++i){
		if(s1[i]!=s2[i]&&s1[i]!='*'&&s2[i]!='*')return 1;
	}
	return 0;
}

ssize_t readall(int fd,void **pbuf){
	char *buf,*p;
	size_t bufsiz,r1;
	ssize_t r,ret=0;
	int i;
	bufsiz=BUFSIZE;
	if((buf=malloc(BUFSIZE))==NULL)return -errno;
	memset(buf,0,BUFSIZE);
	lseek(fd,0,SEEK_SET);
	r1=0;
	while((r=read(fd,buf+r1+bufsiz-BUFSIZE,BUFSIZE-r1))>0){
		r1+=r;
		ret+=r;
		if(ret==bufsiz){
			bufsiz+=BUFSIZE;
			if((p=realloc(buf,bufsiz))==NULL){
				i=errno;
				free(buf);
				return -i;
			}
			buf=p;
			memset(buf+bufsiz-BUFSIZE,0,BUFSIZE);
			r1=0;
		}
	}
	*pbuf=buf;
	return ret;
}
int ucmpgt8(const void *d,const void *s){
	return *(uint8_t *)d>*(uint8_t *)s;
}
int ucmpgt16(const void *d,const void *s){
	return *(uint16_t *)d>*(uint16_t *)s;
}
int ucmpgt32(const void *d,const void *s){
	return *(uint32_t *)d>*(uint32_t *)s;
}
int ucmpgt64(const void *d,const void *s){
	return *(uint64_t *)d>*(uint64_t *)s;
}
int ucmpge8(const void *d,const void *s){
	return *(uint8_t *)d>=*(uint8_t *)s;
}
int ucmpge16(const void *d,const void *s){
	return *(uint16_t *)d>=*(uint16_t *)s;
}
int ucmpge32(const void *d,const void *s){
	return *(uint32_t *)d>=*(uint32_t *)s;
}
int ucmpge64(const void *d,const void *s){
	return *(uint64_t *)d>=*(uint64_t *)s;
}
int ucmplt8(const void *d,const void *s){
	return *(uint8_t *)d<*(uint8_t *)s;
}
int ucmplt16(const void *d,const void *s){
	return *(uint16_t *)d<*(uint16_t *)s;
}
int ucmplt32(const void *d,const void *s){
	return *(uint32_t *)d<*(uint32_t *)s;
}
int ucmplt64(const void *d,const void *s){
	return *(uint64_t *)d<*(uint64_t *)s;
}
int ucmple8(const void *d,const void *s){
	return *(uint8_t *)d<=*(uint8_t *)s;
}
int ucmple16(const void *d,const void *s){
	return *(uint16_t *)d<=*(uint16_t *)s;
}
int ucmple32(const void *d,const void *s){
	return *(uint32_t *)d<=*(uint32_t *)s;
}
int ucmple64(const void *d,const void *s){
	return *(uint64_t *)d<=*(uint64_t *)s;
}
int ucmpne8(const void *d,const void *s){
	return *(uint8_t *)d!=*(uint8_t *)s;
}
int ucmpne16(const void *d,const void *s){
	return *(uint16_t *)d!=*(uint16_t *)s;
}
int ucmpne32(const void *d,const void *s){
	return *(uint32_t *)d!=*(uint32_t *)s;
}
int ucmpne64(const void *d,const void *s){
	return *(uint64_t *)d!=*(uint64_t *)s;
}
int ucmpeq8(const void *d,const void *s){
	return *(uint8_t *)d==*(uint8_t *)s;
}
int ucmpeq16(const void *d,const void *s){
	return *(uint16_t *)d==*(uint16_t *)s;
}
int ucmpeq32(const void *d,const void *s){
	return *(uint32_t *)d==*(uint32_t *)s;
}
int ucmpeq64(const void *d,const void *s){
	return *(uint64_t *)d==*(uint64_t *)s;
}

int cmpgt8(const void *d,const void *s){
	return *(int8_t *)d>*(int8_t *)s;
}
int cmpgt16(const void *d,const void *s){
	return *(int16_t *)d>*(int16_t *)s;
}
int cmpgt32(const void *d,const void *s){
	return *(int32_t *)d>*(int32_t *)s;
}
int cmpgt64(const void *d,const void *s){
	return *(int64_t *)d>*(int64_t *)s;
}
int cmpge8(const void *d,const void *s){
	return *(int8_t *)d>=*(int8_t *)s;
}
int cmpge16(const void *d,const void *s){
	return *(int16_t *)d>=*(int16_t *)s;
}
int cmpge32(const void *d,const void *s){
	return *(int32_t *)d>=*(int32_t *)s;
}
int cmpge64(const void *d,const void *s){
	return *(int64_t *)d>=*(int64_t *)s;
}
int cmplt8(const void *d,const void *s){
	return *(int8_t *)d<*(int8_t *)s;
}
int cmplt16(const void *d,const void *s){
	return *(int16_t *)d<*(int16_t *)s;
}
int cmplt32(const void *d,const void *s){
	return *(int32_t *)d<*(int32_t *)s;
}
int cmplt64(const void *d,const void *s){
	return *(int64_t *)d<*(int64_t *)s;
}
int cmple8(const void *d,const void *s){
	return *(int8_t *)d<=*(int8_t *)s;
}
int cmple16(const void *d,const void *s){
	return *(int16_t *)d<=*(int16_t *)s;
}
int cmple32(const void *d,const void *s){
	return *(int32_t *)d<=*(int32_t *)s;
}
int cmple64(const void *d,const void *s){
	return *(int64_t *)d<=*(int64_t *)s;
}
int cmpne8(const void *d,const void *s){
	return *(int8_t *)d!=*(int8_t *)s;
}
int cmpne16(const void *d,const void *s){
	return *(int16_t *)d!=*(int16_t *)s;
}
int cmpne32(const void *d,const void *s){
	return *(int32_t *)d!=*(int32_t *)s;
}
int cmpne64(const void *d,const void *s){
	return *(int64_t *)d!=*(int64_t *)s;
}
int cmpeq8(const void *d,const void *s){
	return *(int8_t *)d==*(int8_t *)s;
}
int cmpeq16(const void *d,const void *s){
	return *(int16_t *)d==*(int16_t *)s;
}
int cmpeq32(const void *d,const void *s){
	return *(int32_t *)d==*(int32_t *)s;
}
int cmpeq64(const void *d,const void *s){
	return *(int64_t *)d==*(int64_t *)s;
}
int cmpltf(const void *d,const void *s){
	return *(float *)d<*(float *)s;
}
int cmplef(const void *d,const void *s){
	return *(float *)d<=*(float *)s+epsilon_float;
}
int cmpgtf(const void *d,const void *s){
	return *(float *)d>*(float *)s;
}
int cmpgef(const void *d,const void *s){
	return *(float *)d>=*(float *)s-epsilon_float;
}
int cmpnef(const void *d,const void *s){
	return !cmplef(d,s)||!cmpgef(d,s);
}
int cmpeqf(const void *d,const void *s){
	return cmplef(d,s)&&cmpgef(d,s);
}
int cmpltd(const void *d,const void *s){
	return *(double *)d<*(double *)s;
}
int cmpled(const void *d,const void *s){
	return *(double *)d<=*(double *)s+epsilon_double;
}
int cmpgtd(const void *d,const void *s){
	return *(double *)d>*(double *)s;
}
int cmpged(const void *d,const void *s){
	return *(double *)d>=*(double *)s-epsilon_double;
}
int cmpned(const void *d,const void *s){
	return !cmpled(d,s)||!cmpged(d,s);
}
int cmpeqd(const void *d,const void *s){
	return cmpled(d,s)&&cmpged(d,s);
}
int cmpltld(const void *d,const void *s){
	return *(long double *)d<*(long double *)s;
}
int cmpleld(const void *d,const void *s){
	return *(long double *)d<=*(long double *)s+epsilon_ldouble;
}
int cmpgtld(const void *d,const void *s){
	return *(long double *)d>*(long double *)s;
}
int cmpgeld(const void *d,const void *s){
	return *(long double *)d>=*(long double *)s-epsilon_ldouble;
}
int cmpneld(const void *d,const void *s){
	return !cmpleld(d,s)||!cmpgeld(d,s);
}
int cmpeqld(const void *d,const void *s){
	return cmpleld(d,s)&&cmpgeld(d,s);
}
#define CMPLT 0
#define CMPLE 1
#define CMPGT 2
#define CMPGE 3
#define CMPNE 4
#define CMPEQ 5
int (*const cmp_matrix[2][7][6])(const void *,const void *)={
	{
		{cmplt8,cmple8,cmpgt8,cmpge8,cmpne8,cmpeq8},
		{cmplt16,cmple16,cmpgt16,cmpge16,cmpne16,cmpeq16},
		{cmplt32,cmple32,cmpgt32,cmpge32,cmpne32,cmpeq32},
		{cmplt64,cmple64,cmpgt64,cmpge64,cmpne64,cmpeq64},
		{cmpltf,cmplef,cmpgtf,cmpgef,cmpnef,cmpeqf},
		{cmpltd,cmpled,cmpgtd,cmpged,cmpned,cmpeqd},
		{cmpltld,cmpleld,cmpgtld,cmpgeld,cmpneld,cmpeqld}
	},{
		{ucmplt8,ucmple8,ucmpgt8,ucmpge8,ucmpne8,ucmpeq8},
		{ucmplt16,ucmple16,ucmpgt16,ucmpge16,ucmpne16,ucmpeq16},
		{ucmplt32,ucmple32,ucmpgt32,ucmpge32,ucmpne32,ucmpeq32},
		{ucmplt64,ucmple64,ucmpgt64,ucmpge64,ucmpne64,ucmpeq64},
		{NULL,NULL,NULL,NULL,NULL,NULL},
		{NULL,NULL,NULL,NULL,NULL,NULL},
		{NULL,NULL,NULL,NULL,NULL,NULL}
	}
};
int getcmpmode(const char *p1,int *restrict cmpmode){
	int eq=0,cm,ok=0;
	const char *p2;
	p2=p1+strlen(p1)-1;
	while(p2!=p1&&strchr("+-!=",*p2)){
	if(*p2=='+'){
		cm=CMPGT;
		ok=1;
	}else if(*p2=='-'){
		cm=CMPLT;
		ok=1;
	}else if(*p2=='!'){
		cm=CMPNE;
		ok=1;
	}else eq=1;
	--p2;
	}
	cm+=eq;
	if(ok)*cmpmode=cm;
	return ok;
}
int getfuzzymode(const char *p1,int *restrict cmpmode){
	int eq=0,cm,ok=0;
	while(*p1){
	if(*p1=='+'){
		cm=CMPGT;
		ok=1;
	}else if(*p1=='-'){
		cm=CMPLT;
		ok=1;
	}else if(*p1=='!'){
		cm=CMPNE;
		ok=1;
	}else if(*p1=='=')eq=1;
	else return 0;
	++p1;
	}
	cm+=eq;
	if(ok)*cmpmode=cm;
	return ok;
}
int findkeyword(const char *vn){
	char keys[BUFSIZE],*p;
	if(!keylen)return 1;
	if(!vn[0])return 0;
	memcpy(keys,keywords,keylen+1);
	p=strtok(keys," ");
	if(p)do{
		if(strstr(vn,p))return 1;
	}while((p=strtok(NULL," ")));
	return 0;
}
size_t sizeofmap(const char *pr){
	int r;
	const char *p;
	char perms[sizeof("rwxp")],vmname[(BUFSIZE+1+15)&~15],buf[(BUFSIZE+1+15)&~15];
	void *sa,*ea;
	size_t ret=0;

	while(*pr){
	p=strchr(pr,'\n');
	if(!p)return ret;
	memcpy(buf,pr,p-pr);
	buf[p-pr]=0;
	if((r=sscanf(buf,"%lx-%lx %s %*s %*s %*s %" TOCSTR(BUFSIZE) "[^\n]",(unsigned long *)&sa,(unsigned long *)&ea,perms,vmname))<3){
		pr=p+1;
		continue;
	}
	if(r<4)vmname[0]=0;
	pr=p+1;
	if(permscmp(perms,cperms)||!findkeyword(vmname))continue;
	ret+=(size_t)ea-(size_t)sa;
	continue;
	}
	return ret;
}
int researchu(enum smode search_mode,const struct addrset *restrict oldas,int fdmem,const void *restrict val,size_t len,struct addrset *restrict as,int (*compar)(const void *,const void *)){
	ssize_t i=0,n=0,ilast,s;
	char *buf=NULL;
	int r0;
	int64_t l,l1;
	uint64_t u,u1;
	buf=malloc((len+15)&~15);
	if(!buf)return errno;
	ilast=-oldas->n;
	s=oldas->n/100+!!(oldas->n%100);
	while(i<oldas->n&&freezing){
		if(pread(fdmem,buf,len,oldas->buf[i].addr)==len){
			switch(search_mode){
				case SEARCH_COMPARE:
					goto compare;
				case SEARCH_FUZZY:
					goto fuzzy;
				case SEARCH_FUZZYFIX:
					goto fuzzy_fix;
				default:
					break;
			}
		}else goto end;
		if(!memcmp(buf,val,len)){
			r0=aset_addv(as,oldas->buf[i].addr,val,len);
			if(r0<0){
				free(buf);
				return -r0;
			}
			++n;
		}
		goto end;
compare:
		if(compar(buf,val)){
			if((r0=aset_addv(as,oldas->buf[i].addr,buf,len))<0){
				free(buf);
				return -r0;
			}
			++n;
		}
		goto end;
fuzzy:
		if(compar(buf,oldas->buf[i].val)){
			if((r0=aset_addv(as,oldas->buf[i].addr,buf,len))<0){
				free(buf);
				return -r0;
			}
			++n;
		}
		goto end;
fuzzy_fix:
			l=(buf[len-1]&0x80)?-1:0;
			memcpy(&l,buf,len);
			u=0;
			memcpy(&u,buf,len);
			l1=(oldas->buf[i].val[len-1]&0x80)?-1:0;
			memcpy(&l1,oldas->buf[i].val,len);
			u1=0;
			memcpy(&u1,oldas->buf[i].val,len);
			l-=l1;
			u-=u1;
			l1=(((char *)val)[len-1]&0x80)?-1:0;
			memcpy(&l1,val,len);
			u1=0;
			memcpy(&u1,val,len);
		if(u==u1||l==l1){
			if((r0=aset_addv(as,oldas->buf[i].addr,buf,len))<0){
				free(buf);
				return -r0;
			}
			++n;
		}
		goto end;
end:
		++i;
		if((i-ilast)>=s||i==oldas->n){
		fdprintf_atomic(STDERR_FILENO,"\r[%3zu%%] hit %zu",i*100/oldas->n,n);
		ilast=i;
		}
	}
	fdprintf_atomic(STDERR_FILENO,"\n");
	free(buf);
	return 0;
}
int searchu(enum smode search_mode,int fdmap,int fdmem,void *restrict val,size_t len,struct addrset *restrict as,int (*compar)(const void *,const void *)){
	char *buf2,*rbuf,perms[sizeof("rwxp")],vmname[(BUFSIZE+1+15)&~15];
	void *sa,*ea;
	char *p,*pr;
	size_t n,size,scanned=0,pct,lline,maxlline=0;
	ssize_t sr;
	int r0,r1;
	if(len==0)return 0;
	buf2=NULL;
	sr=readall(fdmap,(void **)&rbuf);
	if(sr<0){
		return (int)-sr;
	}
	write(1,rbuf,sr);
	sr=sizeofmap(rbuf);
	pr=rbuf;
	if(quiet)fdprintf_atomic(STDERR_FILENO,"\r[%3zu%%] hit %zu",0lu,as->n);
	while(*pr&&freezing){
	n=0;
	p=strchr(pr,'\n');
	if(p){
		*p=0;
	}
	if(sscanf(pr,"%lx-%lx %s %*s %*s %*s %" TOCSTR(BUFSIZE) "[^\n]",(unsigned long *)&sa,(unsigned long *)&ea,perms,vmname)<4)vmname[0]=0;
	pr+=strlen(pr)+1;
	if(permscmp(perms,cperms)||!findkeyword(vmname))goto notfound1;
	size=(size_t)ea-(size_t)sa;
	scanned+=size;
	pct=scanned*100/sr;
	lline=0;
	if(!quiet)lline+=fdprintf_atomic(STDERR_FILENO,"[%3zu%%] %lx-%lx %s",pct,(uintptr_t)sa,(uintptr_t)ea,perms);
	p=realloc(buf2,size);
	if(!p){
		r0=errno;
		if(buf2)free(buf2);
		free(rbuf);
		return r0;
	}
	buf2=p;
	if((r0=pread(fdmem,buf2,size,(off_t)sa))==0)goto notfound;
	r1=errno;
	if(!quiet)lline+=write(STDERR_FILENO," -> ",4);
	if(r0<0){
		if(!quiet){
			lline+=fdprintf_atomic(STDERR_FILENO,"failed (%s)",strerror(r1));
			goto notfound2;
		}
		goto notfound1;
	}
	switch(search_mode){
		case SEARCH_COMPARE:
			goto compare;
		case SEARCH_FUZZY:
			goto fuzzy;
		case SEARCH_FUZZYFIX:
		default:
			break;
	}
	while((p=memmem_aligned(p,size-(size_t)(p-buf2),val,len,align))){
		++n;
		if((r0=aset_addv(as,(off_t)((uintptr_t)sa+(p-buf2)),val,len))<0){
			if(buf2)free(buf2);
			free(rbuf);
			return -r0;
		}
		if((size_t)(p-buf2)<size)
		p+=align;
	}
	goto end;
compare:
	while((size_t)(p-buf2)<=size-len){
		if(compar(p,val)){
		++n;
		if((r0=aset_addv(as,(off_t)((uintptr_t)sa+(p-buf2)),p,len))<0){
			if(buf2)free(buf2);
			free(rbuf);
			return -r0;
		}
		}
		p+=align;
	}
	goto end;
fuzzy:
	while((size_t)(p-buf2)<=size-len){
		++n;
		if((r0=aset_addv(as,(off_t)((uintptr_t)sa+(p-buf2)),p,len))<0){
			if(buf2)free(buf2);
			free(rbuf);
			return -r0;
		}
		p+=align;
	}
	goto end;
end:
notfound:
	if(!quiet){
		lline+=fdprintf_atomic(STDERR_FILENO,"%zu / %zu",n,as->n);
notfound2:
		if(vmname[0]){
		if(lline>=maxlline)maxlline=lline;
		else write(STDERR_FILENO,space,minz(maxlline-lline,sizeof(space)));
		fdprintf_atomic(STDERR_FILENO,"\t(%s)",vmname);
		}
		write(STDERR_FILENO,"\n",1);
	}
	else fdprintf_atomic(STDERR_FILENO,"\r[%3zu%%] hit %zu",pct,as->n);

notfound1:
	continue;
	}
	if(buf2)free(buf2);
	free(rbuf);
	if(quiet)fdprintf_atomic(STDERR_FILENO,"\n");
	return 0;
}
int atolodx(const char *restrict s,void *dst){
	char *format="%lu";
	if(*s=='0'&&s[1]&&!strchr("+-!=",s[1])){
		format="%lo";
		++s;
		if(*s=='x'){
			++s;
			format="%lx";
		}
	}
	return sscanf(s,format,dst);
}
int atolodxs(const char *restrict s,void *dst,int sign){
	char *format;
	format=sign?"%ld":"%lu";
	if(*s=='0'&&s[1]&&!strchr("+-!=",s[1])){
		format="%lo";
		++s;
		if(*s=='x'){
			++s;
			format="%lx";
		}
	}
	return sscanf(s,format,dst);
}
int dat2spec(const char *restrict a,struct timespec *restrict spec){
	unsigned long i,n,r0;
	i=0;n=0;
	while(*a){
		if(*a<='9'&&*a>='0'){
			i=i*10+(*a-'0');
			++a;
		}else if(*a=='.'){
			break;
		}else return 0;
	}
	if(!*a){
	spec->tv_sec=i;
	spec->tv_nsec=0;
		return 1;
	}
	r0=1000000000l/10l;
	while(*++a){
		if(*a<='9'&&*a>='0'){
			n+=(*a-'0')*r0;
			r0/=10;
		}else return 0;
	}
	spec->tv_sec=i;
	spec->tv_nsec=n;
return 2;
}
#define CMD_RECORD_MAX 16
int recd_last=0,index_last=0;
char cmd_last[CMD_RECORD_MAX][BUFSIZE];
struct termios argp_backup;
ssize_t read_input(int fd,char *buf, size_t count){
	ssize_t r,off=0;
	size_t len,blen=0;
	static char sbuf[4096+16],backup[4096];
	static char *p=sbuf,*p1;
	int il_up=0,index;
	char c;
reread:
	r=read(fd,p,1);
	if(r<=0)return r;
	if(*p==argp_backup.c_cc[VEOF]){
		return 0;
	}else if(*p==argp_backup.c_cc[VERASE]){
		if(off<0){
			p1=p+off-1;
			do{
				*p1=p1[1];
			}while(p1++!=p-2);
			write(STDERR_FILENO,"\b",1);
			r=write(STDERR_FILENO,p+off-1,-off);
			write(STDERR_FILENO," \b",2);
			while(r--)write(STDERR_FILENO,"\b",1);
		}
		if(p!=sbuf){
			if(!off)write(STDERR_FILENO,"\b \b",3);
			--p;
		}
		goto reread;
	}else if(*p==argp_backup.c_cc[VKILL]){
		while(p!=sbuf){
			--p;
			write(STDERR_FILENO,"\b \b",3);
		}
		goto reread;
	}
	switch(*p){
		case '\n':
			len=p-sbuf+1;
			memcpy(buf,sbuf,len);
			p=sbuf;
			write(STDERR_FILENO,"\n",1);
			return len;
		case '\033':
			read(fd,p+1,1);
			read(fd,p+2,1);
			if(p[1]!='[')return 0;
			switch(p[2]){
				case 'A':
				if(il_up>=recd_last)goto reread;
				if(!il_up){
					blen=p-sbuf;
					if(blen)memcpy(backup,sbuf,blen);
				}
				while(p!=sbuf){
					--p;
					write(STDERR_FILENO,"\b \b",3);
				}
				index=index_last-il_up;
				if(index<0)index+=CMD_RECORD_MAX;
				len=strlen(cmd_last[index]);
				if(len>0){
					memcpy(sbuf,cmd_last[index],len);
					p+=len;
					write(STDERR_FILENO,cmd_last[index],len);			
				}
				++il_up;
				goto reread;
				case 'B':
				while(p!=sbuf){
					--p;
					write(STDERR_FILENO,"\b \b",3);
				}
				if(il_up<1){
					if(blen){
						memcpy(sbuf,backup,blen);
						p+=blen;
						write(STDERR_FILENO,backup,blen);
					}
					goto reread;
				}
				il_up-=(il_up==recd_last)?2:1;
				index=index_last-il_up;
				if(index<0)index+=CMD_RECORD_MAX;
				len=strlen(cmd_last[index]);
				if(len>0){
					memcpy(sbuf,cmd_last[index],len);
					p+=len;
					write(STDERR_FILENO,cmd_last[index],len);			
				}
				goto reread;
				case 'D':
					if(p-sbuf<=-off)goto reread;
					--off;
					write(STDERR_FILENO,"\b",1);
					goto reread;
				case 'C':
					if(off>=0)goto reread;
					write(STDERR_FILENO,p+off,1);
					++off;
					goto reread;
				case 'H':
redoH:
					if(p-sbuf<=-off)goto reread;
					--off;
					write(STDERR_FILENO,"\b",1);
					goto redoH;
				case 'F':
redoF:
					if(off>=0)goto reread;
					write(STDERR_FILENO,p+off,1);
					++off;
					goto redoF;

				default:
				return 0;
				}
		default:
			c=*p;
			if(off){
				p1=p-1;
				do{
					p1[1]=*p1;
				}while(p1--!=p+off);
				*(p+off)=c;
				r=write(STDERR_FILENO,p+off,1-off)-1;
				while(r--)write(STDERR_FILENO,"\b",1);
			}else{
				write(STDERR_FILENO,p,1);
			}
			++p;
			if(p==sbuf+4095){
				sbuf[4095]='\n';
				memcpy(buf,sbuf,4096);
				p=sbuf;
				return 4096;
			}
			goto reread;
	}
}
void help(char *arg){
	fprintf(stdout,
	"%sList of all commands:\n\n"
	"Scanning commands:\n"
	"[i|u][8|16|32|64] x   -- scan signed/unsigned value with the specified bits equal to x\n"
	"[i|u][8|16|32|64] x ~ -- like the prev,but x is a variation\n"
	"float x               -- scan float value equal to x\n"
	"double x              -- scan double value equal to x\n"
	"ldouble x             -- scan long double value equal to x\n"
	"[i|u][8|16|32|64] x-  -- scan signed/unsigned value below to x\n"
	"[i|u][8|16|32|64] x-= -- scan signed/unsigned value below or equal to  x\n"
	"[i|u][8|16|32|64] x+  -- scan signed/unsigned value above to x\n"
	"[i|u][8|16|32|64] x+= -- scan signed/unsigned value above or equal to x\n"
	"[i|u][8|16|32|64] x!  -- scan signed/unsigned value unequal to x\n"
	"[i|u][8|16|32|64] x!= -- scan signed/unsigned value equal to x\n"
	"\tfor interger \"x!=\" is equivalent to \"x\" but maybe slower\n"
	"\tfor float \"x!=\" allows an epsilon and \"x\" not\n"
	"\tother compar operators(excluding \"~\") can also work for float\n"
	"[i|u][8|16|32|64] -   -- scan signed/unsigned decreased value\n"
	"[i|u][8|16|32|64] -=  -- scan signed/unsigned non-increased value\n"
	"[i|u][8|16|32|64] +   -- scan signed/unsigned increased value\n"
	"[i|u][8|16|32|64] +=  -- scan signed/unsigned non-decreased value\n"
	"[i|u][8|16|32|64] !   -- scan signed/unsigned modified value\n"
	"[i|u][8|16|32|64] !=  -- scan signed/unsigned non-modified value\n"
	"\tthese operators can also work for float\n"
	"\tthese will scan all value at first scanning,suggest using \"perms\" and \"key\" to limit the field to scan and \"align\" unless your machine is a quantum computer\n"
	"ascii x -- scan continuous bytes equal to x\n"
	"string x -- scan continuous bytes terminated by 0 equal to x\n"
	"\nOther commands:\n"
	"alen,al [x] -- show or set the ascii length\n"
	"align,a [x] -- show or set the aligning bytes\n"
	"autoexit,--autoexit,-e -- exit if no value hit in scanning\n"
	"autostop,--autostop,-s -- send SIGSTOP before scanning and SIGCONT after it\n"
	"cont,c -- send SIGCONT\n"
	"exit,quit,q -- exit\n"
	"echo x -- print x\n"
	"echon x -- print x without \\n\n"
	"out x -- print x to stdout\n"
	"outn x -- print x to stdout without \\n\n"
	"efloat [x] -- show or set the epsilon value for scanning float value\n"
	"edouble [x] -- show or set the epsilon value for scanning double value\n"
	"eldouble [x] -- show or set the epsilon value for scanning long double value\n"
	"\tdefault FLT_EPSILON/DBL_EPSILON/LDBL_EPSILON\n"
	"ftimer,ft x -- use x(decimal,second) as the interval in \"freeze\",default 0.125\n"
	"freeze,f x -- write x to hit addresses looply\n"
	"help,h,usage -- print this help\n"
	"key [x] -- show or set keyword to x used for first scanning,matched with vmname,separated by space\n"
	"kill,k [x] -- send signal x,default SIGKILL\n"
	"list,l,ls -- list values hit\n"
	"limit -- list limits of types\n"
	"ln -- show number of values hit\n"
	"nest,n [x|inf] -- redo the lasted command 1 or x times,or endless until SIGINT gained\n"
	"perms,p [x] -- show or set the perms filter used at first scanning to x\n"
	"\tx must be [r|-|*][w|-|*][x|-|*][s|p|*],r:read,w:write,x:execute,s:shared,p:private(copy-on-write),*:any,-:forbidden\n"
	"pid -- print pid of target process\n"
	"outpid -- print pid of target process to stdout\n"
	"quiet,--quiet,-q -- print less information at first scanning\n"
	"reset,r -- wipe values hit\n"
	"select,se x1,x2,... -- hit listed address\n"
	"sleep x -- enter the TASK_INTERRUPTIBLE state for x(decimal) seconds\n"
	"stop,s -- send SIGSTOP\n"
	"update,u -- update recorded values\n"
	"write,w x -- write x to hit addresses\n"
	"\ncommands can be appended after %s <pid> ,which will automatically do at beginning\n"
	,copyleft,arg);
	fflush(stdout);
}
struct timespec freezing_timer={
	.tv_sec=0,
	.tv_nsec=125000000
};
volatile sig_atomic_t fdmem=-1,fdmap=-1,ioret=-1;
void psig(int sig){
	switch(sig){
		case SIGINT:
			if(next_freezing){
				next_freezing=0;
			}else if(freezing){
				freezing=0;
			}else {
				if(fdmem>=0)close(fdmem);
				if(fdmap>=0)close(fdmap);
				if(ioret>=0)ioctl(STDIN_FILENO,TCSETS,&argp_backup);
				write(STDERR_FILENO,"\n",1);
				_exit(EXIT_SUCCESS);
			}
			break;
		case SIGABRT:
			break;
		case SIGALRM:
			break;
		case SIGUSR1:
			break;
		default:
			break;
	}
}

char ibuf[BUFSIZE];
char cmd[BUFSIZE];
int main(int argc,char **argv){
	int cmpmode,vtype=VT_U8,r0,ret;
	char autoexit=0,autostop=0;
	void *back=NULL;
	enum smode search_mode;
	char pid_str[BUFSIZE_PATH],*p,*p1,*format;
	pid_t pid;
	char buf[BUFSIZE_PATH];
	char vbuf[VBUFSIZE];
	char last_type[16];
	struct addrset as,as1;
	struct timespec sleepts;
	size_t len,slen=0,nnext,n2;
	long l,i;
	off_t addr;
	struct termios argp;
	last_type[0]=0;
	if(argc<2||!strcmp(argv[1],"--help")){
		fdprintf_atomic(STDERR_FILENO,"%sUsage: %s <pid>\n",copyleft,argv[0]);
		return 0;
	}else if(argc==2)fdprintf_atomic(STDERR_FILENO,"%sFor help, type \"help\".\n",copyleft);
	pid=(pid_t)atol(argv[1]);
	if(pid<=0&&!(pid=getpidbycomm(argv[1]))){
		fdprintf_atomic(STDERR_FILENO,"invaild pid %s\n",argv[1]);
		return EXIT_FAILURE;
	}
	ioret=ioctl(STDIN_FILENO,TCGETS,&argp_backup);
	if(ioret>=0){
	memcpy(&argp,&argp_backup,sizeof(struct termios));
	argp.c_lflag&=~(ICANON|ECHO);
	argp.c_cc[VMIN]=1;
	argp.c_cc[VTIME]=0;
	ioctl(STDIN_FILENO,TCSETS,&argp);
	}
	memset(cmd_last,0,CMD_RECORD_MAX*BUFSIZE);
	sprintf(pid_str,"%ld",(long)pid);
	sprintf(buf,"/proc/%s/maps",pid_str);
	fdmap=open(buf,O_RDONLY);
	if(fdmap<0){
		fdprintf_atomic(STDERR_FILENO,"%s:%s\n",buf,strerror(errno));
		goto err0;
	}
	sprintf(buf,"/proc/%s/mem",pid_str);
	fdmem=open(buf,O_RDWR);
	if(fdmem<0){
		fdprintf_atomic(STDERR_FILENO,"%s:%s\n",buf,strerror(errno));
		goto err1;
	}
	aset_init(&as);
	setvbuf(stdout,buf_stdout,_IOFBF,BUFSIZE_STDOUT);
	signal(SIGINT,psig);
	for(i=2;argv[i];++i){
		strcpy(ibuf,argv[i]);
		back=&&here;
		goto gotcmd;
here:
		back=NULL;
	}
	for(;;){
	fdprintf_atomic(STDERR_FILENO,"%s>",last_type[0]?last_type:argv[0]);
	if(read_input(STDIN_FILENO,ibuf,BUFSIZE)<=0)break;
gotcmd:
	p=memchr(ibuf,'\n',BUFSIZE);
	if(p)*p=0;
	if((len=strlen(ibuf))==0)goto nextloop;
	sscanf(ibuf,"%s",cmd);
	if(!strcmp(cmd,"next")||!strcmp(cmd,"n")){
		n2=0;
		nnext=1;
		strtok(ibuf," \t");
		p=strtok(NULL," \t");
		if(p){
			if(atolodx(p,&l)==1){
				nnext=(size_t)l;
			}
			else if(!strcmp(p,"inf")){
				nnext=0;
			}else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
				goto nextloop;
			}
		}
		if(cmd_last[index_last][0]){
		next_freezing=1;
next_again:
		strcpy(ibuf,cmd_last[index_last]);
		back=&&back_to_next;
		goto gotcmd;
back_to_next:
		++n2;
		if(nnext!=1){
			if(nnext)--nnext;
			if(next_freezing)goto next_again;
		}
		if(n2>1)fdprintf_atomic(STDERR_FILENO,"looped %zu times\n",n2);
		next_freezing=0;
		}
		back=NULL;
		goto nextloop;
	}else if(cmd[0]&&strcmp(cmd_last[index_last],ibuf)){
		if(++index_last>=CMD_RECORD_MAX)index_last=0;
		if(recd_last<CMD_RECORD_MAX)++recd_last;
		strcpy(cmd_last[index_last],ibuf);
	}
	if(!strcmp(cmd,"quit")||!strcmp(cmd,"q")||!strcmp(cmd,"exit")){
		break;
	}else if(!strcmp(cmd,"autoexit")||!strcmp(cmd,"-e")||!strcmp(cmd,"--autoexit")){
		autoexit^=1;
		if(!autoexit)fdprintf_atomic(STDERR_FILENO,"exited autoexit mode\n");
		goto nextloop;
	}else if(!strcmp(cmd,"quiet")||!strcmp(cmd,"-q")||!strcmp(cmd,"--quiet")){
		quiet^=1;
		if(!quiet)fdprintf_atomic(STDERR_FILENO,"exited quiet mode\n");
		goto nextloop;
	}else if(!strcmp(cmd,"autostop")||!strcmp(cmd,"-s")||!strcmp(cmd,"--autostop")){
		autostop^=1;
		if(!autostop)fdprintf_atomic(STDERR_FILENO,"exited autostop mode\n");
		goto nextloop;
	}else if(!strcmp(cmd,"help")||!strcmp(cmd,"h")||!strcmp(cmd,"usage")){
		help(argv[0]);
		goto nextloop;
	}else if(!strcmp(cmd,"stop")||!strcmp(cmd,"s")){
		if(kill(pid,SIGSTOP)<0)fdprintf_atomic(STDERR_FILENO,"kill failed (%s)\n",strerror(errno));
		goto nextloop;
	}else if(!strcmp(cmd,"cont")||!strcmp(cmd,"c")){
		if(kill(pid,SIGCONT)<0)fdprintf_atomic(STDERR_FILENO,"kill failed (%s)\n",strerror(errno));
		goto nextloop;
	}else if(!strcmp(cmd,"kill")||!strcmp(cmd,"k")){
		strtok(ibuf," \t");
		p=strtok(NULL," \t");
		if(p){
			if(atolodx(p,&l)==1){
				r0=(int)l;
			}
			else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
				goto nextloop;
			}
		}else {
			r0=SIGKILL;
		}
		if(kill(pid,r0)<0)fdprintf_atomic(STDERR_FILENO,"kill failed (%s)\n",strerror(errno));
		goto nextloop;
	}else if(!strcmp(cmd,"list")||!strcmp(cmd,"l")||!strcmp(cmd,"ls")){
		aset_list(&as,fdmem,vtype,slen);
		goto nextloop;
	}else if(!strcmp(cmd,"pid")){
		fdprintf_atomic(STDERR_FILENO,"%s\n",pid_str);
		goto nextloop;
	}else if(!strcmp(cmd,"outpid")){
		fprintf(stdout,"%s\n",pid_str);
		fflush(stdout);
		goto nextloop;
	}else if(!strcmp(cmd,"sleep")){
		strtok(ibuf," \t");
		if((p=strtok(NULL," \t"))&&dat2spec(p,&sleepts)>0){
			freezing=1;
			nanosleep(&sleepts,NULL);
			freezing=0;
			goto nextloop;
		}
		goto invcmd;
	}else if(!strcmp(cmd,"ftimer")||!strcmp(cmd,"ft")){
		strtok(ibuf," \t");
		if((p=strtok(NULL," \t"))&&dat2spec(p,&freezing_timer)>0){
			goto nextloop;
		}
		goto invcmd;
	}else if(!strcmp(cmd,"echo")){
		if(ibuf[4]==0){
			goto nextloop;
		}else if(ibuf[4]!=' ')goto invcmd;
		fdprintf_atomic(STDERR_FILENO,"%s\n",ibuf+5);
		goto nextloop;
	}else if(!strcmp(cmd,"echon")){
		if(ibuf[5]==0){
			goto nextloop;
		}else if(ibuf[5]!=' ')goto invcmd;
		fdprintf_atomic(STDERR_FILENO,"%s",ibuf+6);
		goto nextloop;
	}else if(!strcmp(cmd,"outn")){
		if(ibuf[4]==0){
			goto nextloop;
		}else if(ibuf[4]!=' ')goto invcmd;
		fprintf(stdout,"%s",ibuf+5);
		fflush(stdout);
		goto nextloop;
	}else if(!strcmp(cmd,"out")){
		if(ibuf[3]==0){
			goto nextloop;
		}else if(ibuf[3]!=' ')goto invcmd;
		fprintf(stdout,"%s\n",ibuf+4);
		fflush(stdout);
		goto nextloop;
	}else if(!strcmp(cmd,"key")){
		if(ibuf[3]==0){
			if(keylen){
				keywords[keylen]='\n';
				write(STDERR_FILENO,keywords,keylen+1);
				keywords[keylen]=0;
			}
			goto nextloop;
		};
		memcpy(keywords,ibuf+4,(keylen=strlen(ibuf+4))+1);
		goto nextloop;
	}else if(!strcmp(cmd,"update")||!strcmp(cmd,"u")){
		aset_wlist(&as,fdmem,vtype);
		goto nextloop;
	}else if(!strcmp(cmd,"select")||!strcmp(cmd,"se")){
		aset_wipe(&as);
		strtok(ibuf," \t");
		while((p=strtok(NULL," \t"))){
			if(sscanf(p,"%lx",&addr)==1)aset_add(&as,addr);
			else fdprintf_atomic(STDERR_FILENO,"invaild address %s\n",p);
		}
		aset_wlist(&as,fdmem,vtype);
		goto nextloop;
	}else if(!strncmp(ibuf,"w ",2)){
		p=ibuf+2;
		len-=2;
		goto from_w;
	}else if(!strncmp(ibuf,"write ",6)){
		p=ibuf+6;
		len-=6;
from_w:
		switch(vtype){
			case VT_STR:
				++len;
			case VT_ASCII:
				break;
			case VT_I8:
			case VT_U8:
				len=sizeof(int8_t);
				goto num;
			case VT_I16:
			case VT_U16:
				len=sizeof(int16_t);
				goto num;
			case VT_I32:
			case VT_U32:
				len=sizeof(int32_t);
				goto num;
			case VT_I64:
			case VT_U64:
				len=sizeof(int64_t);
				goto num;
num:
			if(atolodxs(p,vbuf,!(vtype&1))==1){
				p=vbuf;
			}
			else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
				goto nextloop;
			}
			break;
			case VT_FLOAT:
				len=sizeof(float);
				format="%f";
				goto fnum;
			case VT_DOUBLE:
				len=sizeof(double);
				format="%lf";
				goto fnum;
			case VT_LDOUBLE:
				len=sizeof(long double);
				format="%Lf";
				goto fnum;
fnum:
			if(sscanf(p,format,vbuf)==1){
				p=vbuf;
			}
			else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
				goto nextloop;
			}
			break;
			default:
				break;
		}
		if(autostop&&!freezing)kill(pid,SIGSTOP);
		aset_write(&as,fdmem,p,len);
		if(autostop&&!freezing)kill(pid,SIGCONT);
		if(freezing){
			while(freezing){
			nanosleep(&freezing_timer,NULL);
			aset_write(&as,fdmem,p,len);
			}
			goto back_to_freeze;
		}
		goto nextloop;
	}else if(!strncmp(ibuf,"freeze ",2)){
		p=ibuf+7;
		len-=7;
from_f:
		freezing=1;
		goto from_w;
back_to_freeze:
		goto nextloop;
	}else if(!strncmp(ibuf,"f ",2)){
		p=ibuf+2;
		len-=2;
		goto from_f;
	}else if(!strcmp(cmd,"reset")||!strcmp(cmd,"r")){
		last_type[0]=0;
		fdprintf_atomic(STDERR_FILENO,"wiped %zu addresses\n",as.n);
		aset_wipe(&as);
		goto nextloop;
	}else if(!strcmp(cmd,"perms")||!strcmp(cmd,"p")){
		strtok(ibuf," \t");
		p=strtok(NULL," \t");
		if(p&&strlen(p)==4){
			if(strlen(p)==4&&strchr("-r*",p[0])&&strchr("-w*",p[1])&&strchr("-x*",p[2])&&strchr("sp*",p[3])){
				strcpy(cperms,p);
			}
			else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\nuse [-r\\*][-w\\*][-x\\*][sp\\*]\n",p);
			}
		}else if(!p){
			fdprintf_atomic(STDERR_FILENO,"%4s\n",cperms);
		}else fdprintf_atomic(STDERR_FILENO,"invaild value %s\nuse [-r\\*][-w\\*][-x\\*][sp\\*]\n",p);
		goto nextloop;
	}else if(!strcmp(cmd,"ln")){
		fdprintf_atomic(STDERR_FILENO,"hit %zu in summary\n",as.n);
		goto nextloop;
	}else if(!strcmp(cmd,"limit")){
		fprintf(stdout,
				"i8:%hhd - %hhd\n"
				"u8:%hhu\n"
				"i16:%hd - %hd\n"
				"u16:%hu\n"
				"i32:%d - %d\n"
				"u32:%u\n"
				"i64:%ld - %ld\n"
				"u64:%lu\n"
				"float:%f\n"
				"double:%lf\n"
				"ldouble:%Lf\n"
				,INT8_MIN,INT8_MAX,UINT8_MAX,INT16_MIN,INT16_MAX,UINT16_MAX,INT32_MIN,INT32_MAX,UINT32_MAX,INT64_MIN,INT64_MAX,UINT64_MAX,FLT_MAX,DBL_MAX,LDBL_MAX);
		fflush(stdout);
		goto nextloop;
	}else if(!strcmp(cmd,"align")||!strcmp(cmd,"a")){
		strtok(ibuf," \t");
		p=strtok(NULL," \t");
		if(p){
			if(atolodx(p,&l)==1&&l){
				align=(size_t)l;
			}
			else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
			}
		}else {
			
			fdprintf_atomic(STDERR_FILENO,"%zu\n",align);
		}
		goto nextloop;
	}else if(!strcmp(cmd,"alen")||!strcmp(cmd,"al")){
		strtok(ibuf," \t");
		p=strtok(NULL," \t");
		if(p){
			if(atolodx(p,&l)==1&&l){
				slen=(size_t)l;
			}
			else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
			}
		}else {
			
			fdprintf_atomic(STDERR_FILENO,"%zu\n",slen);
		}
		goto nextloop;
	}else if(!strcmp(cmd,"efloat")){
		strtok(ibuf," \t");
		p=strtok(NULL," \t");
		if(p){
			if(sscanf(p,"%f",&epsilon_float)<1){
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
			}
		}else {
			r0=sprintf(fbuf,"%.128f",epsilon_float);
			fbuf[r0]='0';
			while(fbuf[--r0]=='0');
			fbuf[r0+2]='\n';
			write(STDERR_FILENO,fbuf,r0+3);
		}
		goto nextloop;
	}else if(!strcmp(cmd,"edouble")){
		strtok(ibuf," \t");
		p=strtok(NULL," \t");
		if(p){
			if(sscanf(p,"%lf",&epsilon_double)<1){
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
			}
		}else {
			r0=sprintf(fbuf,"%.128lf",epsilon_double);
			fbuf[r0]='0';
			while(fbuf[--r0]=='0');
			fbuf[r0+2]='\n';
			write(STDERR_FILENO,fbuf,r0+3);
		}
		goto nextloop;
	}else if(!strcmp(cmd,"eldouble")){
		strtok(ibuf," \t");
		p=strtok(NULL," \t");
		if(p){
			if(sscanf(p,"%Lf",&epsilon_ldouble)<1){
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
			}
		}else {
			r0=sprintf(fbuf,"%.128Lf",epsilon_ldouble);
			fbuf[r0]='0';
			while(fbuf[--r0]=='0');
			fbuf[r0+2]='\n';
			write(STDERR_FILENO,fbuf,r0+3);
		}
		goto nextloop;
	}else if(!strcmp(cmd,"ascii")){
		vtype=VT_ASCII;
		strcpy(last_type,cmd);
		if(ibuf[5]==0){
			goto nextloop;
		}else if(ibuf[5]!=' ')goto invcmd;
		p=ibuf+6;
		slen=len-=6;
		search_mode=SEARCH_NORMAL;
		goto search_start;
	}else if(!strcmp(cmd,"string")){
		vtype=VT_STR;
		strcpy(last_type,cmd);
		if(ibuf[6]==0){
			goto nextloop;
		}else if(ibuf[6]!=' ')goto invcmd;
		p=ibuf+7;
		slen=len-=7;
		++len;
		search_mode=SEARCH_NORMAL;
		goto search_start;
	}else if(!strcmp(cmd,"i8")||!strcmp(cmd,"u8")){
		vtype=cmd[0]=='i'?VT_I8:VT_U8;
		strcpy(last_type,cmd);
		strtok(ibuf," \t");
		p1=strtok(NULL," \t");
		search_mode=SEARCH_NORMAL;
		if(p1){
			len=sizeof(int8_t);
			if(atolodxs(p1,vbuf,!(vtype&1))==1){
				p=vbuf;
				if(getcmpmode(p1,&cmpmode))search_mode=SEARCH_COMPARE;
				else if((p1=strtok(NULL," \t"))&&*p1=='~')search_mode=SEARCH_FUZZYFIX;
			}
			else if(getfuzzymode(p1,&cmpmode)){
				search_mode=SEARCH_FUZZY;
			}else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
				goto nextloop;
			}
		}else goto nextloop;
		goto search_start;
	}else if(!strcmp(cmd,"i16")||!strcmp(cmd,"u16")){
		vtype=cmd[0]=='i'?VT_I16:VT_U16;
		strcpy(last_type,cmd);
		strtok(ibuf," \t");
		p1=strtok(NULL," \t");
		search_mode=SEARCH_NORMAL;
		if(p1){
			len=sizeof(int16_t);
			if(atolodxs(p1,vbuf,!(vtype&1))==1){
				p=vbuf;
				if(getcmpmode(p1,&cmpmode))search_mode=SEARCH_COMPARE;
				else if((p1=strtok(NULL," \t"))&&*p1=='~')search_mode=SEARCH_FUZZYFIX;
			}
			else if(getfuzzymode(p1,&cmpmode)){
				search_mode=SEARCH_FUZZY;
			}else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
				goto nextloop;
			}
		}else goto nextloop;
		goto search_start;
	}else if(!strcmp(cmd,"i32")||!strcmp(cmd,"u32")){
		vtype=cmd[0]=='i'?VT_I32:VT_U32;
		strcpy(last_type,cmd);
		strtok(ibuf," \t");
		p1=strtok(NULL," \t");
		search_mode=SEARCH_NORMAL;
		if(p1){
			len=sizeof(int32_t);
			if(atolodxs(p1,vbuf,!(vtype&1))==1){
				p=vbuf;
				if(getcmpmode(p1,&cmpmode))search_mode=SEARCH_COMPARE;
				else if((p1=strtok(NULL," \t"))&&*p1=='~')search_mode=SEARCH_FUZZYFIX;
			}
			else if(getfuzzymode(p1,&cmpmode)){
				search_mode=SEARCH_FUZZY;
			}else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
				goto nextloop;
			}
		}else goto nextloop;
		goto search_start;
	}else if(!strcmp(cmd,"i64")||!strcmp(cmd,"u64")){
		vtype=cmd[0]=='i'?VT_I64:VT_U64;
		strcpy(last_type,cmd);
		strtok(ibuf," \t");
		p1=strtok(NULL," \t");
		search_mode=SEARCH_NORMAL;
		if(p1){
			len=sizeof(int64_t);
			if(atolodxs(p1,vbuf,!(vtype&1))==1){
				p=vbuf;
				if(getcmpmode(p1,&cmpmode))search_mode=SEARCH_COMPARE;
				else if((p1=strtok(NULL," \t"))&&*p1=='~')search_mode=SEARCH_FUZZYFIX;
			}
			else if(getfuzzymode(p1,&cmpmode)){
				search_mode=SEARCH_FUZZY;
			}else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
				goto nextloop;
			}
		}else goto nextloop;
		goto search_start;
	}else if(!strcmp(cmd,"float")){
		vtype=VT_FLOAT;
		strcpy(last_type,cmd);
		strtok(ibuf," \t");
		p1=strtok(NULL," \t");
		search_mode=SEARCH_NORMAL;
		if(p1){
			len=sizeof(float);
			if(sscanf(p1,"%f",(float *)vbuf)==1){
				p=vbuf;
				if(getcmpmode(p1,&cmpmode))search_mode=SEARCH_COMPARE;
				else if((p1=strtok(NULL," \t"))&&*p1=='~')search_mode=SEARCH_FUZZYFIX;
			}
			else if(getfuzzymode(p1,&cmpmode)){
				search_mode=SEARCH_FUZZY;
			}else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
				goto nextloop;
			}
		}else goto nextloop;
		goto search_start;
	}else if(!strcmp(cmd,"double")){
		vtype=VT_DOUBLE;
		strcpy(last_type,cmd);
		strtok(ibuf," \t");
		p1=strtok(NULL," \t");
		search_mode=SEARCH_NORMAL;
		if(p1){
			len=sizeof(double);
			if(sscanf(p1,"%lf",(double *)vbuf)==1){
				p=vbuf;
				if(getcmpmode(p1,&cmpmode))search_mode=SEARCH_COMPARE;
			}
			else if(getfuzzymode(p1,&cmpmode)){
				search_mode=SEARCH_FUZZY;
			}else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
				goto nextloop;
			}
		}else goto nextloop;
		goto search_start;
	}else if(!strcmp(cmd,"ldouble")){
		vtype=VT_LDOUBLE;
		strcpy(last_type,cmd);
		strtok(ibuf," \t");
		p1=strtok(NULL," \t");
		search_mode=SEARCH_NORMAL;
		if(p1){
			len=sizeof(long double);
			if(sscanf(p1,"%Lf",(long double *)vbuf)==1){
				p=vbuf;
				if(getcmpmode(p1,&cmpmode))search_mode=SEARCH_COMPARE;
			}
			else if(getfuzzymode(p1,&cmpmode)){
				search_mode=SEARCH_FUZZY;
			}else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
				goto nextloop;
			}
		}else goto nextloop;
		goto search_start;
	}else {
		if(last_type[0]){
			sprintf(cmd,"%s %s",last_type,ibuf);
			strcpy(ibuf,cmd);
			goto gotcmd;
		}
invcmd:
		fdprintf_atomic(STDERR_FILENO,"invaild or incompleted command: %s\n",cmd);
		goto nextloop;
	}
search_start:
	freezing=1;
	if(autostop)kill(pid,SIGSTOP);
	if(as.n){
		aset_init(&as1);
		r0=researchu(search_mode,&as,fdmem,p,len,&as1,cmp_matrix[vtype&1][vtype/2][cmpmode]);
		if(r0){
			fdprintf_atomic(STDERR_FILENO,"Failed:%s\n",strerror(r0));
			goto err_search;
		}
		aset_free(&as);
		memcpy(&as,&as1,sizeof(struct addrset));

	}else{
		r0=searchu(search_mode,fdmap,fdmem,p,len,&as,cmp_matrix[vtype&1][vtype/2][cmpmode]);
		if(r0){
			fdprintf_atomic(STDERR_FILENO,"Failed:%s\n",strerror(r0));
			goto err_search;
		}
		fdprintf_atomic(STDERR_FILENO,"hit %zu in summary\n",as.n);
	}
		freezing=0;
		if(autostop)kill(pid,SIGCONT);
		if(!as.n){
			if(autoexit)goto err3;
		}
nextloop:
		if(back)goto *back;
		continue;
err_search:
		freezing=0;
		if(autostop)kill(pid,SIGCONT);
		goto err3;
	}
//end:
	aset_free(&as);
	if(!back)fdprintf_atomic(STDERR_FILENO,"\n");
	ret=EXIT_SUCCESS;
	goto out;
err3:
	aset_free(&as);
//err2:
err1:
err0:
	ret=EXIT_FAILURE;
	goto out;
out:
	if(fdmem>=0)close(fdmem);
	if(fdmap>=0)close(fdmap);
	if(ioret>=0)ioctl(STDIN_FILENO,TCSETS,&argp_backup);
	return ret;
}
