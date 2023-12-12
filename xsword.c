/*******************************************************************************
 *License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>*
 *This is free software: you are free to change and redistribute it.           *
 *******************************************************************************/
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <limits.h>
#define VT_I8 0
#define VT_U8 1
#define VT_I16 2
#define VT_U16 3
#define VT_I32 4
#define VT_U32 5
#define VT_I64 6
#define VT_U64 7
#define VT_ASCII 8
#define VT_STR 9
#define VT_ARRAY 16
#define BUFSIZE 1024
#define BUFSIZE_PATH 64
#define BUFSIZE_STDOUT (1024*1024)
#define SIZE_ASET (1024*1024)
#define TOCSTR(x) TOCSTR0(x)
#define TOCSTR0(x) #x
char buf_stdout[BUFSIZE_STDOUT];
char cperms[8]={"****"};
size_t align=1;
int quiet=0;
struct addrval {
	off_t addr;
	char val[sizeof(uintmax_t)];
};
struct addrset {
	struct addrval *buf;
	size_t size,n;
	int valued;
};
int vfdprintf_atomic(int fd,const char *restrict format,va_list ap){
	int r;
	char buf[PIPE_BUF];
	if((r=vsnprintf(buf,PIPE_BUF,format,ap))==EOF)return EOF;
	return write(fd,buf,r);
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
		memcpy(aset->buf[aset->n].val,val,len>=sizeof(uintmax_t)?sizeof(uintmax_t):len);
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
	memset(aset->buf[aset->n].val,0,sizeof(uintmax_t));
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
	size_t i=0;
	char *buf;
	int64_t l;
	uint64_t u;
	int toa=0;
	buf=malloc((len+15)&~15);
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
			default:
				break;
		}
	while(i<aset->n){
		pread(fdmem,buf,len,aset->buf[i].addr);
		fprintf(stdout,"%lx :",aset->buf[i].addr);
		if(toa){
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
		}else fwrite(buf,1,len,stdout);
		fputc('\n',stdout);
		++i;
	}
	fflush(stdout);
	free(buf);
}
void aset_wlist(struct addrset *restrict aset,int fdmem,int vtype){
	size_t i=0,len;
	char *buf;
	int64_t l;
	uint64_t u;
	int toa=0;
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
			default:
				return;
		}
	buf=malloc((len+15)&~15);
	while(i<aset->n){
		if(pread(fdmem,buf,len,aset->buf[i].addr)==len){
			aset->valued=1;
			memcpy(aset->buf[i].val,buf,len);
		}
		++i;
	}
	free(buf);
}
void aset_write(struct addrset *restrict aset,int fdmem,void *val,size_t len){
	size_t i=0;
	char *buf;
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
	size_t bufsiz;
	ssize_t r,ret=0;
	int i;
	bufsiz=BUFSIZE;
	if((buf=malloc(BUFSIZE))==NULL)return -errno;
	memset(buf,0,BUFSIZE);
	lseek(fd,0,SEEK_SET);
	while((r=read(fd,buf+bufsiz-BUFSIZE,BUFSIZE))>0){
		ret+=r;
		if(r==BUFSIZE){
			bufsiz+=BUFSIZE;
			if((p=realloc(buf,bufsiz))==NULL){
				i=errno;
				free(buf);
				return -i;
			}
			buf=p;
			memset(buf+bufsiz-BUFSIZE,0,BUFSIZE);
		}else break;
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
#define CMPLT 0
#define CMPLE 1
#define CMPGT 2
#define CMPGE 3
#define CMPNE 4
#define CMPEQ 5
int (*const cmp_matrix[2][4][6])(const void *,const void *)={
	{
		{cmplt8,cmple8,cmpgt8,cmpge8,cmpne8,cmpeq8},
		{cmplt16,cmple16,cmpgt16,cmpge16,cmpne16,cmpeq16},
		{cmplt32,cmple32,cmpgt32,cmpge32,cmpne32,cmpeq32},
		{cmplt64,cmple64,cmpgt64,cmpge64,cmpne64,cmpeq64}
	},{
		{ucmplt8,ucmple8,ucmpgt8,ucmpge8,ucmpne8,ucmpeq8},
		{ucmplt16,ucmple16,ucmpgt16,ucmpge16,ucmpne16,ucmpeq16},
		{ucmplt32,ucmple32,ucmpgt32,ucmpge32,ucmpne32,ucmpeq32},
		{ucmplt64,ucmple64,ucmpgt64,ucmpge64,ucmpne64,ucmpeq64}
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
size_t sizeofmap(const char *pr){
	const char *p;
	char perms[sizeof("rwxp")];
	void *sa,*ea;
	size_t ret=0;
	while(*pr){
	p=strchr(pr,'\n');
	if(!p)return ret;
	if(sscanf(pr,"%lx-%lx %s",(unsigned long *)&sa,(unsigned long *)&ea,perms)<3){
		pr=p+1;
		continue;
	}
	pr=p+1;
	if(permscmp(perms,cperms))continue;
	ret+=(size_t)ea-(size_t)sa;
	continue;
	}
	return ret;
}
int research(const struct addrset *restrict oldas,int fdmem,const void *restrict val,size_t len,struct addrset *restrict as){
	size_t i=0,n=0,pct,pct_old=0;
	char *buf;
	int r0;
	buf=malloc((len+15)&~15);
	if(!buf)return errno;
	while(i<oldas->n){
		if(pread(fdmem,buf,len,oldas->buf[i].addr)>0)
		if(!memcmp(buf,val,len)){
			r0=aset_addv(as,oldas->buf[i].addr,val,len);
			if(r0<0){
				free(buf);
				return -r0;
			}
			++n;
		}
		++i;
		pct=i*100/oldas->n;
		if(pct>pct_old){
		fdprintf_atomic(STDERR_FILENO,"\r[%3zu%%] hit %zu",pct,n);
		pct_old=pct;
		}
	}
	fdprintf_atomic(STDERR_FILENO,"\n");
	free(buf);
	return 0;
}
int research_cmp(const struct addrset *restrict oldas,int fdmem,const void *val,size_t len,struct addrset *restrict as,int (*compar)(const void *,const void *)){
	size_t i=0,n=0,pct,pct_old=0;
	char vbuf[sizeof(uintmax_t)];
	int r0;
	while(i<oldas->n){
		if(pread(fdmem,vbuf,len,oldas->buf[i].addr)==len)
		if(compar(vbuf,val)){
			if((r0=aset_addv(as,oldas->buf[i].addr,vbuf,len))<0){
				return -r0;
			}
			++n;
		}
		++i;
		pct=i*100/oldas->n;
		if(pct>pct_old){
		fdprintf_atomic(STDERR_FILENO,"\r[%3zu%%] hit %zu",pct,n);
		pct_old=pct;
		}
	}
	fdprintf_atomic(STDERR_FILENO,"\n");
	return 0;
}
int research_fuzzy(const struct addrset *restrict oldas,int fdmem,size_t len,struct addrset *restrict as,int (*compar)(const void *,const void *)){
	size_t i=0,n=0,pct,pct_old=0;
	char vbuf[sizeof(uintmax_t)];
	int r0;
	while(i<oldas->n){
		if(pread(fdmem,vbuf,len,oldas->buf[i].addr)==len)
		if(compar(vbuf,oldas->buf[i].val)){
			if((r0=aset_addv(as,oldas->buf[i].addr,vbuf,len))<0){
				return -r0;
			}
			++n;
		}
		++i;
		pct=i*100/oldas->n;
		if(pct>pct_old){
		fdprintf_atomic(STDERR_FILENO,"\r[%3zu%%] hit %zu",pct,n);
		pct_old=pct;
		}
	}
	fdprintf_atomic(STDERR_FILENO,"\n");
	return 0;
}
int search(int fdmap,int fdmem,void *val,size_t len,struct addrset *as){
	char *buf2,*rbuf,perms[sizeof("rwxp")],vmname[(BUFSIZE+1+15)&~15];
	void *sa,*ea;
	char *p,*pr;
	size_t n,size,scanned=0,pct;
	ssize_t sr;
	int r0;
	if(len==0)return 0;
	buf2=NULL;
	sr=readall(fdmap,(void **)&rbuf);
	if(sr<0){
		return (int)-sr;
	}
	sr=sizeofmap(rbuf);
	pr=rbuf;
	if(quiet)fdprintf_atomic(STDERR_FILENO,"\r[%3zu%%] hit %zu",0lu,as->n);
	while(*pr){
	n=0;
	p=strchr(pr,'\n');
	if(p){
		*p=0;
	}
	if(sscanf(pr,"%lx-%lx %s %*s %*s %*s %" TOCSTR(BUFSIZE) "[^\n]",(unsigned long *)&sa,(unsigned long *)&ea,perms,vmname)<4)vmname[0]=0;
	pr+=strlen(pr)+1;
	if(permscmp(perms,cperms))goto notfound1;
	size=(size_t)ea-(size_t)sa;
	scanned+=size;
	pct=scanned*100/sr;
	if(!quiet)fdprintf_atomic(STDERR_FILENO,"[%3zu%%] %lx-%lx %s ",pct,(uintptr_t)sa,(uintptr_t)ea,perms);
	p=realloc(buf2,size);
	if(!p){
		r0=errno;
		if(buf2)free(buf2);
		free(rbuf);
		return r0;
	}
	buf2=p;
	if((r0=pread(fdmem,buf2,size,(off_t)sa))==0)goto notfound;
	if(r0<0){
		if(!quiet)fdprintf_atomic(STDERR_FILENO,"failed (%s) %s%s%s\n",strerror(errno),vmname[0]?"(":"",vmname,vmname[0]?")":"");
		goto notfound1;
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
notfound:
	if(!quiet)fdprintf_atomic(STDERR_FILENO,"-> %zu\t%s%s%s\n",n,vmname[0]?"(":"",vmname,vmname[0]?")":"");
	else fdprintf_atomic(STDERR_FILENO,"\r[%3zu%%] hit %zu",pct,as->n);

notfound1:
	continue;
	}
	if(buf2)free(buf2);
	free(rbuf);
	if(quiet)fdprintf_atomic(STDERR_FILENO,"\n");
	return 0;
}
int search_cmp(int fdmap,int fdmem,const void *val,size_t len,struct addrset *as,int (*compar)(const void *,const void *)){
	char *buf2,*rbuf,perms[sizeof("rwxp")],vmname[(BUFSIZE+1+15)&~15];
	void *sa,*ea;
	char *p,*pr;
	size_t n,size,scanned=0,pct;
	ssize_t sr;
	int r0;
	if(len==0)return 0;
	buf2=NULL;
	sr=readall(fdmap,(void **)&rbuf);
	if(sr<0){
		return (int)-sr;
	}
	sr=sizeofmap(rbuf);
	pr=rbuf;
	if(quiet)fdprintf_atomic(STDERR_FILENO,"\r[%3zu%%] hit %zu",0lu,as->n);
	while(*pr){
	n=0;
	p=strchr(pr,'\n');
	if(p){
		*p=0;
	}
	if(sscanf(pr,"%lx-%lx %s %*s %*s %*s %" TOCSTR(BUFSIZE) "[^\n]",(unsigned long *)&sa,(unsigned long *)&ea,perms,vmname)<4)vmname[0]=0;
	pr+=strlen(pr)+1;
	if(permscmp(perms,cperms))goto notfound1;
	size=(size_t)ea-(size_t)sa;
	scanned+=size;
	pct=scanned*100/sr;
	if(!quiet)fdprintf_atomic(STDERR_FILENO,"[%3zu%%] %lx-%lx %s ",pct,(uintptr_t)sa,(uintptr_t)ea,perms);
	p=realloc(buf2,size);
	if(!p){
		r0=errno;
		if(buf2)free(buf2);
		free(rbuf);
		return r0;
	}
	buf2=p;
	if((r0=pread(fdmem,buf2,size,(off_t)sa))==0)goto notfound;
	if(r0<0){
		if(!quiet)fdprintf_atomic(STDERR_FILENO,"failed (%s) %s%s%s\n",strerror(errno),vmname[0]?"(":"",vmname,vmname[0]?")":"");
		goto notfound1;
	}
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
notfound:
	if(!quiet)fdprintf_atomic(STDERR_FILENO,"-> %zu\t%s%s%s\n",n,vmname[0]?"(":"",vmname,vmname[0]?")":"");
	else fdprintf_atomic(STDERR_FILENO,"\r[%3zu%%] hit %zu",pct,as->n);

notfound1:
	continue;
	}
	if(buf2)free(buf2);
	free(rbuf);
	if(quiet)fdprintf_atomic(STDERR_FILENO,"\n");
	return 0;
}
int search_fuzzy(int fdmap,int fdmem,size_t len,struct addrset *as){
	char *buf2,*rbuf,perms[sizeof("rwxp")],vmname[(BUFSIZE+1+15)&~15];
	void *sa,*ea;
	char *p,*pr;
	size_t n,size,scanned=0,pct;
	ssize_t sr;
	int r0;
	if(len==0)return 0;
	buf2=NULL;
	sr=readall(fdmap,(void **)&rbuf);
	if(sr<0){
		return (int)-sr;
	}
	sr=sizeofmap(rbuf);
	pr=rbuf;
	if(quiet)fdprintf_atomic(STDERR_FILENO,"\r[%3zu%%] hit %zu",0lu,as->n);
	while(*pr){
	n=0;
	p=strchr(pr,'\n');
	if(p){
		*p=0;
	}
	if(sscanf(pr,"%lx-%lx %s %*s %*s %*s %" TOCSTR(BUFSIZE) "[^\n]",(unsigned long *)&sa,(unsigned long *)&ea,perms,vmname)<4)vmname[0]=0;
	pr+=strlen(pr)+1;
	if(permscmp(perms,cperms))goto notfound1;
	size=(size_t)ea-(size_t)sa;
	scanned+=size;
	pct=scanned*100/sr;
	if(!quiet)fdprintf_atomic(STDERR_FILENO,"[%3zu%%] %lx-%lx %s ",pct,(uintptr_t)sa,(uintptr_t)ea,perms);
	p=realloc(buf2,size);
	if(!p){
		r0=errno;
		if(buf2)free(buf2);
		free(rbuf);
		return r0;
	}
	buf2=p;
	if((r0=pread(fdmem,buf2,size,(off_t)sa))==0)goto notfound;
	if(r0<0){
		if(!quiet)fdprintf_atomic(STDERR_FILENO,"failed (%s) %s%s%s\n",strerror(errno),vmname[0]?"(":"",vmname,vmname[0]?")":"");
		goto notfound1;
	}
	while((size_t)(p-buf2)<=size-len){
		++n;
		if((r0=aset_addv(as,(off_t)((uintptr_t)sa+(p-buf2)),p,len))<0){
			if(buf2)free(buf2);
			free(rbuf);
			return -r0;
		}
		p+=align;
	}
notfound:
	if(!quiet)fdprintf_atomic(STDERR_FILENO,"-> %zu\t%s%s%s\n",n,vmname[0]?"(":"",vmname,vmname[0]?")":"");
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
void help(char *arg){
	fprintf(stdout,
	"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
	"This is free software: you are free to change and redistribute it.\n"
	"List of all commands:\n\n"
	"Scanning commands:\n"
	"[i|u][8|16|32|64] x   -- scan signed/unsigned value with the specified bits equal to x\n"
	"[i|u][8|16|32|64] x-  -- scan signed/unsigned value below to x\n"
	"[i|u][8|16|32|64] x-= -- scan signed/unsigned value below or equal to  x\n"
	"[i|u][8|16|32|64] x+  -- scan signed/unsigned value above to x\n"
	"[i|u][8|16|32|64] x+= -- scan signed/unsigned value above or equal to x\n"
	"[i|u][8|16|32|64] x!  -- scan signed/unsigned value unequal to x\n"
	"[i|u][8|16|32|64] x!= -- scan signed/unsigned value equal to x\n"
	"\t\"x!=\" is equivalent to \"x\" but maybe slower\n"
	"[i|u][8|16|32|64] -   -- scan signed/unsigned decreased value\n"
	"[i|u][8|16|32|64] -=  -- scan signed/unsigned non-increased value\n"
	"[i|u][8|16|32|64] +   -- scan signed/unsigned increased value\n"
	"[i|u][8|16|32|64] +=  -- scan signed/unsigned non-decreased value\n"
	"[i|u][8|16|32|64] !   -- scan signed/unsigned modified value\n"
	"[i|u][8|16|32|64] !=  -- scan signed/unsigned non-modified value\n"
	"\tthese will scan all value at first scanning,suggest using \"perms\" to limit the field to scan and \"align\" unless your machine is a quantum computer\n"
	"ascii x -- scan continuous bytes equal to x\n"
	"string x -- scan continuous bytes terminated by 0 equal to x\n"
	"\nOther commands:\n"
	"align [x] -- show or set the aligning bytes\n"
	"autoexit,--autoexit,-e -- exit if no value hit in scanning\n"
	"autostop,--autostop,-s -- send SIGSTOP before scanning and SIGCONT after it\n"
	"exit,quit,q -- exit\n"
	"echo x -- print x\n"
	"echon x -- print x without \\n\n"
	"out x -- print x to stdout\n"
	"outn x -- print x to stdout without \\n\n"
	"ftimer,t x -- use x(decimal,second) as the interval in \"freeze\",default 0.125\n"
	"freeze,f x -- write x to hit addresses looply\n"
	"help,h,usage -- print this help\n"
	"list,l,ls -- list values hit\n"
	"nest,n [x|inf] -- redo the lasted command 1 or x times,or endless until SIGINT gained\n"
	"perms,p [x] -- show or set the perms filter used at first scanning to x\n"
	"\tx must be [r|-|*][w|-|*][x|-|*][s|p|*],r:read,w:write,x:execute,s:shared,p:private(copy-on-write),*:any,-:forbidden\n"
	"pid -- print pid of target process\n"
	"outpid -- print pid of target process to stdout\n"
	"quiet,--quiet,-q -- print less information at first scanning\n"
	"reset,r -- wipe values hit\n"
	"select x1,x2,... -- hit listed address\n"
	"sleep x -- enter the TASK_INTERRUPTIBLE state for x(decimal) seconds\n"
	"write,w x -- write x to hit addresses\n"
	"\ncommands can be appended after %s <pid> ,which will automatically do at beginning\n"
	,arg);
	fflush(stdout);
}
struct timespec freezing_timer={
	.tv_sec=0,
	.tv_nsec=125000000
};
volatile sig_atomic_t freezing=0;
volatile sig_atomic_t nnext=1;
void psig(int sig){
	switch(sig){
		case SIGINT:
			if(freezing||!nnext){
				freezing=0;
				nnext=1;
			}
			else {
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
int main(int argc,char **argv){
	int fdmem,fdmap,cmpmode,vtype=VT_U8,r0;
	char autoexit=0,autostop=0;
	void *back=NULL;
	char *pid_str,*p,*p1;
	pid_t pid;
	char buf[BUFSIZE_PATH];
	char ibuf[BUFSIZE];
	char cmd[BUFSIZE];
	char cmd_last[BUFSIZE];
	char vbuf[sizeof(uintmax_t)];
	struct addrset as,as1;
	struct timespec sleepts;
	size_t len,slen,n2;
	long l,i;
	off_t addr;
	if(argc<2||!strcmp(argv[1],"--help")){
		fdprintf_atomic(STDERR_FILENO,
	"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
	"This is free software: you are free to change and redistribute it.\n"

				"Usage: %s <pid>\n",argv[0]);
		return 0;
	}else if(argc==2)fdprintf_atomic(STDERR_FILENO,
	"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
	"This is free software: you are free to change and redistribute it.\n"
	"For help, type \"help\".\n"
			);
	pid_str=argv[1];
	pid=(pid_t)atol(pid_str);
	if(pid<=0){
		fdprintf_atomic(STDERR_FILENO,"invaild pid %s\n",pid_str);
		return EXIT_FAILURE;
	}
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
	fdprintf_atomic(STDERR_FILENO,"%s>",argv[0]);
	if(read(STDIN_FILENO,ibuf,BUFSIZE)<=0)break;
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
		if(cmd_last[0]){
next_again:
		strcpy(ibuf,cmd_last);
		back=&&back_to_next;
		goto gotcmd;
back_to_next:
		++n2;
		if(!nnext||nnext>1){
			if(nnext)--nnext;
			goto next_again;
		}
		if(n2>1)fdprintf_atomic(STDERR_FILENO,"looped %zu times\n",n2);
		}
		back=NULL;
		goto nextloop;
	}else strcpy(cmd_last,ibuf);
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
	}else if(!strcmp(cmd,"ftimer")||!strcmp(cmd,"ftimer")){
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
	}else if(!strcmp(cmd,"select")||!strcmp(cmd,"s")){
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
			if(atolodxs(p,ibuf,!(vtype&1))==1){
				p=ibuf;
			}
			else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
				goto nextloop;
			}

			default:
				break;
		}
		aset_write(&as,fdmem,p,len);
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
reset:
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
		}else {
			
			fdprintf_atomic(STDERR_FILENO,"%4s\n",cperms);
		}
		goto nextloop;
	}else if(!strcmp(cmd,"align")){
		strtok(ibuf," \t");
		p=strtok(NULL," \t");
		if(p){
			if(atolodx(p,&l)==1){
				align=(size_t)l;
			}
			else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
			}
		}else {
			
			fdprintf_atomic(STDERR_FILENO,"%zu\n",align);
		}
		goto nextloop;
	}else if(!strcmp(cmd,"ascii")){
		vtype=VT_ASCII;
		if(ibuf[5]==0){
			goto nextloop;
		}else if(ibuf[5]!=' ')goto invcmd;
		p=ibuf+6;
		slen=len-=6;
	}else if(!strcmp(cmd,"string")){
		vtype=VT_STR;
		if(ibuf[6]==0){
			goto nextloop;
		}else if(ibuf[6]!=' ')goto invcmd;
		p=ibuf+7;
		slen=len-=7;
		++len;
	}else if(!strcmp(cmd,"i8")||!strcmp(cmd,"u8")){
		vtype=cmd[0]=='i'?VT_I8:VT_U8;
		strtok(ibuf," \t");
		p1=strtok(NULL," \t");
		if(p1){
			len=sizeof(int8_t);
			if(atolodxs(p1,vbuf,!(vtype&1))==1){
				p=vbuf;
				if(getcmpmode(p1,&cmpmode))goto compare;
			}
			else if(getfuzzymode(p1,&cmpmode)){
				goto fuzzy;
			}else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
				goto nextloop;
			}
		}else goto nextloop;
	}else if(!strcmp(cmd,"i16")||!strcmp(cmd,"u16")){
		vtype=cmd[0]=='i'?VT_I16:VT_U16;
		strtok(ibuf," \t");
		p1=strtok(NULL," \t");
		if(p1){
			len=sizeof(int16_t);
			if(atolodxs(p1,vbuf,!(vtype&1))==1){
				p=vbuf;
				if(getcmpmode(p1,&cmpmode))goto compare;
			}
			else if(getfuzzymode(p1,&cmpmode)){
				goto fuzzy;
			}else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
				goto nextloop;
			}
		}else goto nextloop;
	}else if(!strcmp(cmd,"i32")||!strcmp(cmd,"u32")){
		vtype=cmd[0]=='i'?VT_I32:VT_U32;
		strtok(ibuf," \t");
		p1=strtok(NULL," \t");
		if(p1){
			len=sizeof(int32_t);
			if(atolodxs(p1,vbuf,!(vtype&1))==1){
				p=vbuf;
				if(getcmpmode(p1,&cmpmode))goto compare;
			}
			else if(getfuzzymode(p1,&cmpmode)){
				goto fuzzy;
			}else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
				goto nextloop;
			}
		}else goto nextloop;
	}else if(!strcmp(cmd,"i64")||!strcmp(cmd,"u64")){
		vtype=cmd[0]=='i'?VT_I64:VT_U64;
		strtok(ibuf," \t");
		p1=strtok(NULL," \t");
		if(p1){
			len=sizeof(int64_t);
			if(atolodxs(p1,vbuf,!(vtype&1))==1){
				p=vbuf;
				if(getcmpmode(p1,&cmpmode))goto compare;
			}
			else if(getfuzzymode(p1,&cmpmode)){
				goto fuzzy;
			}else {
				fdprintf_atomic(STDERR_FILENO,"invaild value %s\n",p);
				goto nextloop;
			}
		}else goto nextloop;
	}else {
invcmd:
		fdprintf_atomic(STDERR_FILENO,"invaild or incompleted command\n");
		goto nextloop;
	}
	if(autostop)kill(pid,SIGSTOP);
	if(as.n){
		aset_init(&as1);
		r0=research(&as,fdmem,p,len,&as1);
		if(r0){
			fdprintf_atomic(STDERR_FILENO,"Failed:%s\n",strerror(r0));
			goto err_search;
		}
		aset_free(&as);
		memcpy(&as,&as1,sizeof(struct addrset));

	}else{
		r0=search(fdmap,fdmem,p,len,&as);
		if(r0){
			fdprintf_atomic(STDERR_FILENO,"Failed:%s\n",strerror(r0));
			goto err_search;
		}
		fdprintf_atomic(STDERR_FILENO,"hit %zu in summary\n",as.n);
	}
	goto search_end;
compare:
	if(autostop)kill(pid,SIGSTOP);
	if(as.n){
		aset_init(&as1);
		r0=research_cmp(&as,fdmem,p,len,&as1,cmp_matrix[vtype&1][vtype/2][cmpmode]);
		if(r0){
			fdprintf_atomic(STDERR_FILENO,"Failed:%s\n",strerror(r0));
			goto err_search;
		}
		aset_free(&as);
		memcpy(&as,&as1,sizeof(struct addrset));

	}else{
		r0=search_cmp(fdmap,fdmem,p,len,&as,cmp_matrix[vtype&1][vtype/2][cmpmode]);
		if(r0){
			fdprintf_atomic(STDERR_FILENO,"Failed:%s\n",strerror(r0));
			goto err_search;
		}
		fdprintf_atomic(STDERR_FILENO,"hit %zu in summary\n",as.n);
	}
	goto search_end;
fuzzy:
	if(autostop)kill(pid,SIGSTOP);
	if(as.n){
		aset_init(&as1);
		r0=research_fuzzy(&as,fdmem,len,&as1,cmp_matrix[vtype&1][vtype/2][cmpmode]);
		if(r0){
			fdprintf_atomic(STDERR_FILENO,"Failed:%s\n",strerror(r0));
			goto err_search;
		}
		aset_free(&as);
		memcpy(&as,&as1,sizeof(struct addrset));

	}else{
		r0=search_fuzzy(fdmap,fdmem,len,&as);
		if(r0){
			fdprintf_atomic(STDERR_FILENO,"Failed:%s\n",strerror(r0));
			goto err_search;
		}
		fdprintf_atomic(STDERR_FILENO,"hit %zu in summary\n",as.n);
	}
	goto search_end;
search_end:
		if(autostop)kill(pid,SIGCONT);
		if(!as.n&&autoexit)goto err3;
nextloop:
		if(back)goto *back;
		continue;
err_search:
		if(autostop)kill(pid,SIGCONT);
		goto err3;
	}
end:
	aset_free(&as);
	close(fdmem);
	close(fdmap);
	if(!back)fdprintf_atomic(STDERR_FILENO,"\n");
	return EXIT_SUCCESS;
err3:
	aset_free(&as);
err2:
	close(fdmem);
err1:
	close(fdmap);
err0:
	return EXIT_FAILURE;
}
