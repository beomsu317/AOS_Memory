#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <errno.h>
#include <linux/uio.h>
#include <elf.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#define MEDIUM_SIZE 1024
#define SMALL_SIZE 256

int pid;

void error(char *msg){
	perror(msg);
	exit(-1);
}

void dump(unsigned long long start,unsigned long long end){
	unsigned char data;
	char dump_name[SMALL_SIZE];
	struct user_pt_regs regs;
	struct iovec io;
	long long size = 0;
	FILE *fp;
	io.iov_base = &regs;
	io.iov_len = sizeof(regs);
	
	// // Get Register
	// if(ptrace(PTRACE_GETREGSET,pid, (void*)NT_PRSTATUS, &io) < 0){
	// 	error("ptrace() PTRACE_GETREGSET error");
	// }

	// printf("%p\n",regs.sp);
	size = end - start;
	if(size <=0 ) error("[-] size error");
	char *p = malloc(size);
	printf("[+] size: 0x%llx\n",size);
	if(ptrace(PTRACE_ATTACH,pid,0,0) < 0) error("[-] ptrace() PTRACE_ATTACH error");
	for(long long i = 0; i < size; i++,p++){
		if(i%0x1000 == 0) printf("  [+] dumping 0x%llx\n",i);
		if ((data = ptrace(PTRACE_PEEKDATA,pid,start++,0)) < 0) error("[-] ptrace() PEEKDATA error");
			*p = data;
		
	}
	if(ptrace(PTRACE_DETACH, pid, 0, 0) < 0) error("[-] ptrace() PTRACE_DETACH error");
	p = p - size;

	sprintf(dump_name,"./%d_%llx_%llx",pid,start,end);

	if((fp = fopen(dump_name,"wb")) < 0) error("[-] fopen() error");
	fwrite(p,1,size,fp);
	fclose(fp);
	free(p);

}

int ps_exists_check(int pid){
	char cmdline[MEDIUM_SIZE];
	struct dirent *entry;
	struct stat file_stat;
	int dir_pid;
	DIR *dir;
	FILE *fp;
	char *ptr;
	
	dir = opendir("/proc");
	
	while((entry = readdir(dir))!=NULL){
		
		lstat(entry->d_name,&file_stat);
		if(!S_ISDIR(file_stat.st_mode)) {
			continue;
		}
		dir_pid = atoi(entry->d_name);
		if(dir_pid == pid){		
			return 1;
		}
	}
	return -1;
}

int main(int argc,char* argv[],char* env[]) {
	
	FILE *fp;
	struct dirent *entry;
	char* ptr;
	unsigned long long start,end;
	
	if(argc != 4){
		printf("[+] Usage: %s [pid] [start] [end]\n",argv[0]);
		exit(0);
	}

	pid = atoi(argv[1]);
	start = strtoull(argv[2],NULL,16);
	end = strtoull(argv[3],NULL,16);
	
	if(ps_exists_check(pid) < 0){
		error("[-] Unknown Process\n");
	}

	printf("[+] pid:  %d\n",pid);
	printf("[+] start: %llx\n[+] end: %llx\n",start,end);
	
	dump(start,end);

	printf("[+] Done!\n");

	return 0;
}

