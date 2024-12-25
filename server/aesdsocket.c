#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

#define IP_ADDRESS_LENGTH 40

void usage(char * prog_name);
static void signal_handler(int signal_number);
bool caught_signal = false;

int main(int argc, char ** argv)
{
    int retval = 0;
    int run_as_daemon = 0;    
    struct sigaction aesdsocket_sigaction;
    memset(&aesdsocket_sigaction, 0, sizeof(struct sigaction));
    aesdsocket_sigaction.sa_handler = signal_handler;
    if (sigaction(SIGTERM, &aesdsocket_sigaction, NULL) != 0)
    {
        perror("aesdsocket: Could not register SIGTERM handler");
    }
    if (sigaction(SIGINT, &aesdsocket_sigaction, NULL) != 0)
    {
        perror("aesdsocket: Could not register SIGINT handler");
    }    
    if (argc == 2)    
    {
        if (strcmp(argv[1],"-d") == 0)
        {
            run_as_daemon = 1;
        }
        else
        {
            printf("%s: Invalid argument\r\n", argv[0]);
            usage(argv[0]);
            exit(0);
        }
    }
    if (argc > 2)
    {
        printf("%s: Too many arguments\r\n", argv[0]);
        usage(argv[0]);
        exit(0);
    }

    if (run_as_daemon)
    {
        int pid = fork();
        if (pid == 0)
        {
             // I am the child
            setsid();
            chdir("/");
            int fd = open("/dev/null", O_RDWR);
            if (fd == -1)
            {
                perror("aesdsocket: could not open /dev/null for I/O redirection");
                exit(-1);
            }
            if (dup2(fd, STDIN_FILENO) == -1)
            {
                perror("aesdsocket: Could not redirect STDOUT to /dev/null");
            }
            if (dup2(fd, STDOUT_FILENO) == -1)
            {
                perror("aesdsocket: Could not redirect STDOUT to /dev/null");
            }
            if (dup2(fd, STDERR_FILENO) == -1)
            {
                perror("aesdsocket: Could not redirect STDERR to /dev/null");
            }
        }
        else
        {
            exit(0);
        }        
    }    

    int facility = LOG_USER;
    if (run_as_daemon)
    {
        facility = LOG_DAEMON;
    }
    openlog(NULL, 0, facility);


    struct addrinfo hints;
    struct addrinfo * res;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    retval = getaddrinfo(NULL, "9000", &hints, &res);
    if (res == NULL | retval != 0)
    {
        perror("aesdsocket: Call to getaddrinfo failed");
        exit(-1);
    }

    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0)
    {
        perror("aesdsocket: Could not get socket");
        exit(-1);        
    }
    
    int option_value = 1;
    socklen_t option_length = sizeof(option_value);
    retval = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &option_value, option_length);
    if (retval)
    {
        perror("aesdsocket: Could not set socket options");
        exit(-1);
    }
    

    retval = bind(s, res->ai_addr, res->ai_addrlen);
    if (retval)
    {
        perror("aesdsocket: Bind failed");
        exit(-1);        
    }

    freeaddrinfo(res);
    char * buf = malloc(1500 * sizeof(char));
    if (!buf)
    {
        perror("aesdsocket: Couldn't malloc buffer for incoming data");
        exit(-1);
    }    

    do
    {    
        retval = listen(s, 1);
        if (retval)
        {
            perror("aesdsocket: Listen failed");
            exit(-1);        
        }    

    //    struct sockaddr_storage connecting_addr;
        struct sockaddr connecting_addr;
        socklen_t addr_size = sizeof(connecting_addr);
        int acceptedFd = accept(s, &connecting_addr, &addr_size);
        if (acceptedFd == -1)
        {
            perror("aesdsocket: Couldn't accept incoming connection");
            exit(-1);
        }    
        struct sockaddr_in * connecting_addr_in = (struct sockaddr_in *)&connecting_addr;
        char connecting_ip_address[IP_ADDRESS_LENGTH];
        if (inet_ntop(connecting_addr_in->sin_family,
                    &(connecting_addr_in->sin_addr), 
                    (char *)(&connecting_ip_address),
                    (socklen_t)IP_ADDRESS_LENGTH) == NULL)
        {
            perror("aesdsocket: Could not get IP address string of connected client");
            exit(-1);
        };
        syslog(LOG_INFO, "Accepted connection from %s", connecting_ip_address);

    //TODO: fork or create thread at this point

        if (acceptedFd == -1)
        {
            perror("aesdsocket: Accept failed");
            exit(-1);        
        }
        
        char * bufptr = buf;
        int len = 1;
        int num_bytes_received = 0;
        int total_bytes_received = 0;
        do
        {
            num_bytes_received = recv(acceptedFd, bufptr, len, MSG_DONTWAIT);
            if (num_bytes_received == 0) //socket has been closed; break
            {
                break;
            }
            else if (num_bytes_received < 0) //non-blocking call failed; continue
            {
                continue;
            }
            else
            {   
                bufptr += num_bytes_received;
                total_bytes_received += num_bytes_received;                
                if (*(bufptr - 1) == '\0')
                {
                    printf("Received string %s, logging;\r\n", bufptr);
                }
                bufptr = buf;
            }
        } while (!caught_signal);
        
        syslog(LOG_INFO, "Closed connection from %s", connecting_ip_address);        
        printf("I got %s over my socket; total bytes = %d.\r\n",buf, total_bytes_received);    

    } while (!caught_signal);

cleanup:
    free(buf);
	return retval;
}

void usage(char * prog_name)
{
    printf("usage: %s [-d] - Socket listener and logger\r\n", prog_name);
    printf("    -d - Run as daemon\r\n");
}

static void signal_handler(int signal_number)
{
    switch(signal_number)
    {
        case SIGINT:
        case SIGTERM:
            caught_signal = true;
            syslog(LOG_INFO, "Caught signal, exiting");
            break;        
    }
}