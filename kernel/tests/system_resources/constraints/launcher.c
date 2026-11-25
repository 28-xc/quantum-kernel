/* Move only this short-lived test child into an already configured cgroup,
 * then drop to the invoking project user and execute the exact workload. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
int main(int argc,char **argv){
 if(argc<6)return 2;
 char path[4096];if(snprintf(path,sizeof path,"%s/cgroup.procs",argv[1])>=(int)sizeof path)return 3;
 int fd=open(path,O_WRONLY);if(fd<0)return 4;
 char pid[32];int n=snprintf(pid,sizeof pid,"%ld",(long)getpid());if(write(fd,pid,n)!=n)return 5;close(fd);
 if(setgroups(0,NULL)||setgid((gid_t)strtoul(argv[3],0,10))||setuid((uid_t)strtoul(argv[2],0,10)))return 6;
 execv(argv[4],argv+4);perror("execv");return 7;
}
