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
#include <fcntl.h>

#define FILE_MAX_LEN 256

int pid;
char process_name[FILE_MAX_LEN];

void error(char *msg){
	perror(msg);
	exit(-1);
}

void get_process_name(){
    char name[FILE_MAX_LEN];
    int fd;
    sprintf(name,"/proc/%d/cmdline",pid);
    fd = open(name,O_RDWR);
    read(fd,process_name,FILE_MAX_LEN);
    close(fd);
}

int process_exists_check(int pid){
    DIR *dir;
    char proc_dir[FILE_MAX_LEN];
    sprintf(proc_dir,"/proc/%d",pid);
    dir = opendir(proc_dir);
    if(dir){
        return 1;
    }else{
        return 0;
    }
}

void help(const char *name){
    printf("Usage: %s [OPTIONS]\n"
           "  -v                show version\n"
           "  -p [pid]          target pid\n"
           "  -s [start]        start memory\n"
           "  -e [end]          end memory\n"
           ,name);
    exit(0);
}

void dump(unsigned long start,unsigned long end){
	unsigned char data;
	char dump_name[FILE_MAX_LEN];
	struct user_pt_regs regs;
	struct iovec io;
	long size = 0;
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
	printf("[+] size: 0x%lx\n",size);
	if(ptrace(PTRACE_ATTACH,pid,0,0) < 0) error("[-] ptrace() PTRACE_ATTACH error");
	for(int i = 0; i < size; i++,p++){
		if(i%0x10000 == 0) printf("  [+] dumping 0x%lx\n",i);
		if ((data = ptrace(PTRACE_PEEKDATA,pid,start++,0)) < 0) error("[-] ptrace() PEEKDATA error");
			*p = data;
		
	}
	if(ptrace(PTRACE_DETACH, pid, 0, 0) < 0) error("[-] ptrace() PTRACE_DETACH error");
	p = p - size;

	sprintf(dump_name,"./%s_0x%lx_0x%lx",process_name,start,end);

	if((fp = fopen(dump_name,"wb")) < 0) error("[-] fopen() error");
	fwrite(p,1,size,fp);
	fclose(fp);
	free(p);

}

int main(int argc,char* argv[],char* env[]) {
	int opt;
	unsigned long start,end;

    if(argc == 1){
        help(argv[0]);
    }

    while((opt = getopt(argc, argv, "hvp:s:e:")) != -1) 
    {
        switch(opt) 
        { 
            case 'v':
                printf("Version: 1.0.0\n");
                break;
            case 'p':
                pid = atoi(optarg);
                break;
            case 's':
                start = strtoul(optarg,NULL,16);
                break;
            case 'e':
                end = strtoul(optarg,NULL,16);
                break;
            default:
                help(argv[0]);
                break;
        }
    } 
	
	if(process_exists_check(pid) <= 0){
		error("[-] Unknown Process\n");
	}

    get_process_name();
    printf("[+] Process name: %s\n",process_name);
	printf("[+] Memory dump: 0x%lx - 0x%lx\n",start,end);
	
	dump(start,end);

	printf("[+] Done!\n");

	return 0;
}
