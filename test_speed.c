#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
char buf[9999];
int main(void){
	struct timeval tv,tv1;
	time_t t,tr,i=0;
	struct timespec ts,ts1;
	char *p,*p2;
	printf("my pid %lu \n",(long)getpid());
	setvbuf(stdout,buf,_IOFBF,9999);
	while(1){
	gettimeofday(&tv,NULL);
	syscall(SYS_gettimeofday,&tv1,NULL);
	tr=time(&t);
	clock_gettime(CLOCK_REALTIME,&ts);
	syscall(SYS_clock_gettime,CLOCK_REALTIME,&ts1);
	printf("gettimeofday(libc):{%lu,%lu}\n",tv.tv_sec,tv.tv_usec);
	printf("gettimeofday(syscall):{%lu,%lu}\n",tv1.tv_sec,tv1.tv_usec);
	printf("time:{%lu,%lu} %s\n",t,tr,(p=ctime(&t),(p2=strchr(p,'\n'))&&(*p2=0),p));
	printf("clock_gettime(libc):{%lu,%lu}\n",ts.tv_sec,ts.tv_nsec);
	printf("clock_gettime(syscall):{%lu,%lu}\n",ts1.tv_sec,ts1.tv_nsec);
	printf("slept %lu times\n\n",++i);
	fflush(stdout);
	sleep(1);
	//if(!p)break;
	}
}
