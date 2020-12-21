#define _GNU_SOURCE
#include "tomcrypt.h"
#include <sys/types.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <poll.h>
#include <linux/userfaultfd.h> 
#include <sys/types.h>
#include <sys/ioctl.h> 
#include <sys/syscall.h> 
#include <sys/mman.h>
#include <signal.h>
#define sys_store_hash 440

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE);   \
		} while (0)
char command ;
int  page_num ;
void *  memory_allocated = NULL; 
int num_pages;
int page_siz ;
char * ash;
int network_socket;
int client_socket;
int port =  -1;
char * ip ;
int socket_filed ;
int received_page = 0;
#define KEY_SIZE 16

enum page_status {
	PAGE_INVALID,
	PAGE_SHARED,
	PAGE_MODIFIED
};

enum page_command {
	PAGE_INVALIDATE,
	PAGE_REQUEST,
	PAGE_STATUS,
	PAGE_RESPONSE,
	PAGE_SET_SHARED,
	GET_PAGE_STATUS,
	PAGE_STATUS_REP,	
	EXIT_APPLICATION
};

enum page_status * page_status;
int page_stat = 0; 
struct param_ex
{
	enum page_command cmd;
	int page_no;
	int mem_siz ;
	enum page_status status;
	void * address;
	char data[4096];
	unsigned char hash[32];
	symmetric_key key_share;
};
struct param_ex send_ex;
struct param_ex recv_sync;
symmetric_key key;

void sigintHandler(int sig_num){

	struct param_ex redv_ex;
	redv_ex.cmd = EXIT_APPLICATION;
	send(socket_filed , &redv_ex , sizeof(struct param_ex) , 0);
	if(syscall (sys_store_hash,3,0,NULL)!= 0){
		perror("Syscall failed\n");
		exit(0);
	}
	close(network_socket);
	printf("\nGracefully exiting\n");
	fflush(stdout);	
	exit(0);
}

//provide char * as result
static void key_gen( )
{
	int err;
	uint8_t rand_key[KEY_SIZE];
	for(int i = 0 ; i < KEY_SIZE ; i++)
	{
		rand_key[i] = rand() % 127 ; 
	}
	zeromem(&key, sizeof(key));
    	if ((err = rijndael_setup(rand_key , KEY_SIZE, 0, &key)) != CRYPT_OK) {
       		printf("key initialization error\n\n");
    	}
}

static int create_hash(unsigned char * input , int length ,unsigned  char * result)
{
	hash_state md;
        sha256_init(&md);
        sha256_process(&md,(unsigned char *) input,length);
        sha256_done(&md, result);
	printf("Hash calulated locally is : \n");
        for (int i = 0; i < 32 ; i++)
        {
                printf("%x ",result[i]);
        }
        printf("\n ");
}


static void * comm_loop(void * arg)
{
	long sock_fd = (long)arg ;

	uint8_t cipher[32];
	struct param_ex redv_ex;
	while(1){
		recv(socket_filed ,&redv_ex,sizeof(struct param_ex),0);
		switch(redv_ex.cmd)
		{
			case PAGE_INVALIDATE:
				page_status[redv_ex.page_no] = PAGE_INVALID ;
				madvise(send_ex.address + ((redv_ex.page_no * page_siz)),page_siz , MADV_DONTNEED);
				break;
			case PAGE_REQUEST:
				redv_ex.cmd = PAGE_RESPONSE;
				if(page_status[redv_ex.page_no] != PAGE_INVALID)
				{
					memcpy(redv_ex.data,send_ex.address + (redv_ex.page_no * page_siz) , page_siz);
					//create_hash(send_ex.address + (redv_ex.page_no * page_siz) , page_siz , redv_ex.hash);
					//read hash from kernel
					if(syscall (sys_store_hash,1,redv_ex.page_no,redv_ex.hash)!= 0){
						perror("Syscall failed\n");
						sigintHandler(0);
						exit(0);
					}
					rijndael_ecb_encrypt(redv_ex.hash,cipher, &key);
					rijndael_ecb_encrypt(redv_ex.hash + 16,cipher + 16, &key);
				/*	printf("Encrypted value is :");
					for(int i = 0 ; i < 32 ; i++)
					{
						printf("%x ",cipher[i]);
					}
				*/
					memcpy(redv_ex.hash,cipher,32);	
					printf("\n");
					redv_ex.status = page_status[redv_ex.page_no];
				}
				else
				{
					redv_ex.status = page_status[redv_ex.page_no];
				}
				send(socket_filed , &redv_ex , sizeof(struct param_ex) , 0);
				break;
			case PAGE_RESPONSE:
				page_status[redv_ex.page_no] = PAGE_SHARED;
				memcpy(&recv_sync,&redv_ex,sizeof(struct param_ex));
				received_page=1;	
				break;
			case PAGE_SET_SHARED:
				page_status[redv_ex.page_no] = PAGE_SHARED;
				break;
			case GET_PAGE_STATUS:
				redv_ex.cmd = PAGE_STATUS_REP;
				redv_ex.status = page_status[redv_ex.page_no];
				send(socket_filed , &redv_ex , sizeof(struct param_ex) , 0);
				break;
			case PAGE_STATUS_REP:
				memcpy(&recv_sync,&redv_ex,sizeof(struct param_ex));
				page_stat=1;
				break;
			case EXIT_APPLICATION:
				sigintHandler(0);
				exit(0);	
				break;
			default:
				printf("Wrong option\n");
		}
	}
}
void printstatus(enum page_status stat)
{
	switch(stat)
	{
		case PAGE_INVALID:
			printf("PAGE_INVALID\n");
			break;
		case PAGE_SHARED:
			printf("PAGE_SHARED\n");
			break;
		case PAGE_MODIFIED:
			printf("PAGE_MODIFIED\n");
			break;
		default:
			printf("ERROR in status\n");	
	}


}
static void *fault_handler_thread(void *arg)
{
	static struct uffd_msg msg;   /* Data read from userfaultfd */
	long uffd;                    /* userfaultfd file descriptor */   
	ssize_t nread;
	struct uffdio_copy uffdio_copy;
	unsigned char verify_hash[32];
	uffd = (long) arg; 
	static char *page = NULL;
	if (page == NULL) { 
		page = mmap(NULL, page_siz, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (page == MAP_FAILED)
			errExit("mmap");
	}
	for(;;)
	{
		struct pollfd pollfd;
		int nready;
		struct param_ex sen ;
		pollfd.fd = uffd;
		pollfd.events = POLLIN;
		nready = poll(&pollfd, 1, -1);
		if (nready == -1)
			errExit("poll");	
		nread = read(uffd, &msg, sizeof(msg)); 
		if (nread == 0) {
			printf("EOF on userfaultfd!\n");
			exit(EXIT_FAILURE);
		}
		if (nread == -1)
			 errExit("read");

		if (msg.event != UFFD_EVENT_PAGEFAULT) { 
			fprintf(stderr, "Unexpected event on userfaultfd\n");
			exit(EXIT_FAILURE);
		}
		memset(page,'\n',page_siz);
		sen.cmd = GET_PAGE_STATUS ;
		sen.page_no = ((char *)msg.arg.pagefault.address - (char *)send_ex.address ) / page_siz;
		page_stat=0;
		send(socket_filed , &sen , sizeof(struct param_ex) , 0);	
		
		while(!page_stat);	
				

		//uffdio_copy.src = (unsigned long) msg.arg.pagefault.address & ~(page_siz - 1);	
		if(recv_sync.status != PAGE_INVALID){
			int result;
			unsigned char plain[32];
			sen.cmd = PAGE_REQUEST ;
			sen.page_no = ((char *)msg.arg.pagefault.address - (char *)send_ex.address ) / page_siz;
			received_page=0;
			send(socket_filed , &sen , sizeof(struct param_ex) , 0);	
			
			while(!received_page);	
			create_hash(recv_sync.data , page_siz , verify_hash);			
			rijndael_ecb_decrypt(recv_sync.hash,plain, &key);
			rijndael_ecb_decrypt(recv_sync.hash + 16,plain + 16, &key);
			printf("decrypted hash\n");
			for(int i = 0 ; i < 32 ; i++)
			{
				printf("%x ",plain[i]);
			}
			printf("\n");
			result = memcmp(verify_hash,plain,32);
			if(!result)
			{
				printf("Both hash matches\n");
			}
			else{
				printf("Both hash do not match memory attacked\n");
			}
			if(recv_sync.status != PAGE_INVALID){
				uffdio_copy.src = (unsigned long) recv_sync.data; 
				recv_sync.cmd = PAGE_SET_SHARED;
				send(socket_filed,&recv_sync ,sizeof(struct param_ex) , 0);
			
			}
		}
		else
		{
			if(page_status[sen.page_no] == PAGE_INVALID){
				uffdio_copy.src = page;
				page_status[sen.page_no] = PAGE_SHARED;	
			}
		}
	//	printf("User fault done\n");
		uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
			~(page_siz - 1);
		uffdio_copy.len = page_siz;
		uffdio_copy.mode = 0;
		uffdio_copy.copy = 0;
		if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
			errExit("ioctl-UFFDIO_COPY");
	}
}

void loop_application()
{
		for(;;)
		{
			char * start_addr ;
		        char *	end_addr  ; 
			unsigned char Hash[32];
			printf("\n> Which command should I run? (r:read, w:write, v:MSI content, e:EXIT application):");
			fflush(stdout);
			scanf("%c", &command);
			getchar();
			if(command != 'v')
			{
				printf("\n> For which page? (0-%d, or -1 for all):\n",num_pages - 1);
				scanf("%d", &page_num);
			
				getchar();
				if(page_num > (num_pages - 1) )
				{
					printf("Invalid page number \n");
					continue;
				}
				else if(page_num == -1)
				{
					start_addr = (char *)send_ex.address ;
					end_addr = (char *)send_ex.address + send_ex.mem_siz - 1;
				}
				else
				{
					if(page_num < 0)
					{
						printf("Invalid page number \n");
						continue;
					}
					else
					{
						start_addr = (char *)(send_ex.address +
							( (page_num)* (page_siz)));
						end_addr =(char *) ((char*)start_addr + (page_siz - 1)) ;
					}
				}
			}
			else
			{
					start_addr = (char *)send_ex.address ;
					end_addr = (char *)send_ex.address + send_ex.mem_siz - 1;
				
			}
			
			switch(command)
			{
				case 'r':
					while (start_addr < end_addr ) 
					{
						printf("\n\nData on page %d :: \n",(start_addr - (char *)send_ex.address)/page_siz);
						for(int i = 0 ; i < page_siz ; i++)
						{	
							if(start_addr[i] == '\n') 
								break;
							printf("%c" ,start_addr[i]);
						}
						start_addr += page_siz;
					}
					break;
				case 'w': 
					printf("Enter data to write : ");
					scanf("%[^\n]",ash);
					struct param_ex sen ;
					
					while(start_addr < end_addr )
					{
						sen.cmd = PAGE_INVALIDATE;
						memcpy(start_addr,ash,strlen(ash)  );
						start_addr[strlen(ash)] = '\n' ;
						int page_writ = (   (char *) start_addr 
								- (char *)send_ex.address)/page_siz;
						page_status[page_writ] = PAGE_MODIFIED ;
						create_hash( start_addr, page_siz ,Hash );
						//write hash to kernel xarray
				                if(syscall (sys_store_hash,2,page_writ,Hash)!= 0){
			                        	perror("Syscall failed\n");
							sigintHandler(0);
							exit(0);
						}
						sen.page_no = page_writ ;
						send(socket_filed , &sen , sizeof(struct param_ex) , 0);
						start_addr += page_siz;
						memset(Hash,0,32);
					}
					getchar();
					break;
				case 'v' :
					for (int k = 0 ; k < num_pages ; k++)
					{
						printf("For page %d   :",k);
						printstatus(page_status[k]);

					}					
					break;
				case 'E' :
					recv_sync.cmd = EXIT_APPLICATION;
					
					send(socket_filed ,&recv_sync,sizeof(struct param_ex) ,0);
					close(socket_filed);
					printf("\nGracefully exiting\n");
					sigintHandler(0);
					exit(0);
					break;
				default:
					printf("\nWrong command \n");
			}
			fflush(stdout);
		}
	
}
void initialize_memory( void * start , int size )
{
	char * start_address = (char * ) start ;
	char * end_address = (char *)start + (size -1);
	for(int k = 0 ; k < num_pages ; k ++)
	{
		page_status[k] = PAGE_INVALID ;
	}
	while(start_address < end_address)
	{
//		(start_address)[0] = '\n';
		start_address += page_siz ;
	}
		
}
int main(int argc, char * argv[]){

	char server_response[256];
	int opt;
        int uffd;	
	struct sockaddr_in server_address;
	struct uffdio_register uffdio_register; 
	struct uffdio_api uffdio_api;
	int is_server = 0;
	int thread_ret;
	pthread_t thr , comm_thr;
	signal(SIGINT,sigintHandler);
	is_server = (argc == 3)? 1 : 0;
	if( (argc != 5) && (argc != 3)){
		
		printf("Usage ./app [port]  [ IP]  \n");
		sigintHandler(0);
		exit(0);
	}
	while ((opt = getopt (argc, argv, ":p:i:")) != -1)
		switch (opt)
		{
			case 'p':
				port = (int) atoi(optarg);
				break;
			case 'i':
				ip = (char *)optarg;  
				break;
			default:
				break;
		}
	/*Fill up struct*/
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(port);
	server_address.sin_addr.s_addr = INADDR_ANY;
	page_siz = getpagesize();


	if(is_server == 1)
	{
	//	printf("Port is %d and ip is %s\n",port , ip);
		network_socket = socket(AF_INET , SOCK_STREAM , 0);
		printf("Number of pages to be allocated ?\n");
		scanf("%d",&num_pages);
		key_gen();
		//create xarray pages
		if(syscall (sys_store_hash,0,num_pages,NULL)!= 0){
			perror("Syscall failed\n");
			sigintHandler(0);
			exit(0);
		}
		printf("Waiting for client\n");
		page_status = malloc(num_pages * sizeof(enum page_status));
		int conn_status = bind(network_socket,
				(struct sockaddr *)&server_address,sizeof(server_address));
		memory_allocated = mmap(NULL,num_pages * page_siz,
					PROT_READ|PROT_WRITE,MAP_ANONYMOUS | MAP_PRIVATE,-1,0);
		ash = malloc(sizeof(char) * page_siz);
		send_ex.mem_siz = num_pages * page_siz ;
		send_ex.address = memory_allocated ; 
		initialize_memory( send_ex.address , send_ex.mem_siz ) ;
		if(memory_allocated == MAP_FAILED)
		{
			perror("mmap failed");
			sigintHandler(0);
			exit(0);
		}
		if(conn_status == -1){
			perror("bind failed");
			sigintHandler(0);
			exit(0);
		}
		uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
		if (uffd == -1)
			errExit("userfaultfd");
		uffdio_api.api = UFFD_API;
		uffdio_api.features = 0;
		if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
			errExit("ioctl-UFFDIO_API");
		uffdio_register.range.start = (unsigned long) memory_allocated;
		uffdio_register.range.len = send_ex.mem_siz;
		uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
		if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
			errExit("ioctl-UFFDIO_REGISTER"); 
		thread_ret = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
		if(thread_ret != 0) {
			errExit("pthread_create");
		}
		getchar();
		
		listen(network_socket,5);
		memcpy((void *)&send_ex.key_share,(void *)&key,sizeof(symmetric_key));	
		client_socket = accept(network_socket,NULL,NULL);
		send(client_socket , &send_ex , sizeof(struct param_ex) , 0);	
		socket_filed = client_socket;
		pthread_create( &comm_thr  , NULL , comm_loop , socket_filed);
		loop_application();
	}
	else
	{
		network_socket = socket(AF_INET , SOCK_STREAM , 0);
		send_ex.mem_siz = 0;
	        send_ex.address = 0;	
		server_address.sin_addr.s_addr = inet_addr(ip);
		page_status = malloc(num_pages * sizeof(enum page_status));
		int conn_status = connect(network_socket,
				(struct sockaddr *)&server_address,sizeof(server_address));
		if(conn_status == -1){
			perror("connected failed");
			sigintHandler(0);
			exit(0);
		}
		recv(network_socket,&send_ex,sizeof(struct param_ex),0);
		num_pages = send_ex.mem_siz / page_siz ;
		ash = malloc(sizeof(char) * num_pages);
		memcpy((void *)&key,(void *)&send_ex.key_share,sizeof(symmetric_key));
		printf("The server sent %p memory address and %d\n and num pages is %d\n ",
				send_ex.address , send_ex.mem_siz , num_pages);
		mmap(send_ex.address , send_ex.mem_siz,
			PROT_READ|PROT_WRITE,MAP_ANONYMOUS | MAP_PRIVATE,-1,0);
		initialize_memory( send_ex.address , send_ex.mem_siz );
		uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
		if (uffd == -1)
			errExit("userfaultfd");
		uffdio_api.api = UFFD_API;
		uffdio_api.features = 0;
		if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
			errExit("ioctl-UFFDIO_API");
		uffdio_register.range.start = (unsigned long) send_ex.address;
		uffdio_register.range.len = send_ex.mem_siz;
		uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
		if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
			errExit("ioctl-UFFDIO_REGISTER"); 
		thread_ret = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
		if(thread_ret != 0) {
			errExit("pthread_create");
		}
		socket_filed = network_socket; 
		pthread_create( &comm_thr  , NULL , comm_loop , socket_filed );
		loop_application();
	}
	//free the xarray
	if(syscall (sys_store_hash,3,0,NULL)!= 0){
		perror("Syscall failed\n");
		sigintHandler(0);
		exit(0);
	}
	close(network_socket);
}
