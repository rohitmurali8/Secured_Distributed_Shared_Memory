#include<stdio.h>
#include<sys/syscall.h>
#include<unistd.h>
#include<stdlib.h>
#define sys_store_hash 440

int main(int argc, char * argv[]){
int ret;
char hash[32];
if(argc != 4){
printf("Help: ./a.out option page_no hash\n");
printf("options = 0 -> create\n\t1 -> read\n\t2 -> write\n");
printf("page_no = specify either number of pages to create with option 0 or\n page to read or write (with option 1 or 2)\n");
printf("hash = 32byte hash string\n");
}else{
	if(atoi(argv[1]) == 0){
		//create pages
		printf("Request for create %d pages\n",atoi(argv[2]));
		ret = syscall (sys_store_hash,0,atoi(argv[2]),NULL);
		printf("return value- %d\n",ret);
	}else if(atoi (argv[1]) == 1){
		//read request
		printf("Request to read %d page\n",atoi(argv[2]));
		ret = syscall (sys_store_hash,1,atoi(argv[2]),hash);
		printf("return value- %d\n",ret);
		printf("hash value - %0.32s\n",hash);
	}else if (atoi (argv[1]) == 2){
		printf("Request to write %d page\n",atoi(argv[2]));
		ret = syscall (sys_store_hash,2,atoi(argv[2]),argv[3]);
		printf("return value- %d\n",ret);
	}else if (atoi (argv[1]) == 3){
		printf("Clearing pages\n");
		ret = syscall (sys_store_hash,3,atoi(argv[2]),argv[3]);
		printf("return value- %d\n",ret);
	}	
}
}	
