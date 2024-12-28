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
#define MAX_PACKET_SIZE 1500
#define OUTPUT_FILENAME "/var/tmp/aesdsocketdata"

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
    if (res == NULL || retval != 0)
    {
        perror("aesdsocket: Call to getaddrinfo failed");
        retval = -1;
        goto cleanup;        
    }
    
    int output_file_desc;
    int acceptedFd;
    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0)
    {
        perror("aesdsocket: Could not get socket");
        retval = -1;
        goto cleanup;        
    }
    
    int option_value = 1;
    socklen_t option_length = sizeof(option_value);
    retval = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &option_value, option_length);
    if (retval)
    {
        perror("aesdsocket: Could not set socket options");
        retval = -1;
        goto cleanup;        
    }
    

    retval = bind(s, res->ai_addr, res->ai_addrlen);
    if (retval)
    {
        perror("aesdsocket: Bind failed");
        retval = -1;
        goto cleanup;        
    }

    freeaddrinfo(res);

    char * packet_buf = malloc(MAX_PACKET_SIZE * sizeof(char));
    if (!packet_buf)
    {
        perror("aesdsocket: Couldn't malloc buffer for incoming data");
        retval = -1;
        goto cleanup;        
    }    

    char * read_buffer = malloc(MAX_PACKET_SIZE * sizeof(char));
    if (!read_buffer)
    {
        perror("aesdsocket: Could not allocate file read buffer");
        retval = -1;
        goto cleanup;
    }    

    do
    {    
        retval = listen(s, 1);
        if (retval)
        {
            perror("aesdsocket: Listen failed");
            retval = -1;
            goto cleanup;        
        }    

        struct sockaddr connecting_addr;
        socklen_t addr_size = sizeof(connecting_addr);
        acceptedFd = accept(s, &connecting_addr, &addr_size);
        if (acceptedFd == -1)
        {
            perror("aesdsocket: Couldn't accept incoming connection");
            retval = -1;
            goto cleanup;        
        }    
        struct sockaddr_in * connecting_addr_in = (struct sockaddr_in *)&connecting_addr;
        char connecting_ip_address[IP_ADDRESS_LENGTH];
        if (inet_ntop(connecting_addr_in->sin_family,
                    &(connecting_addr_in->sin_addr), 
                    (char *)(&connecting_ip_address),
                    (socklen_t)IP_ADDRESS_LENGTH) == NULL)
        {
            perror("aesdsocket: Could not get IP address string of connected client");
            retval = -1;
            goto cleanup;        
        };
        syslog(LOG_INFO, "Accepted connection from %s", connecting_ip_address);

        if (acceptedFd == -1)
        {
            perror("aesdsocket: Accept failed");
            retval = -1;
            goto cleanup;        
        }
        
        int num_bytes_received = 0;
        int total_bytes_received = 0;
        int number_of_reallocs = 0;
        do
        {            
            num_bytes_received = recv(acceptedFd, packet_buf + total_bytes_received, MAX_PACKET_SIZE, MSG_DONTWAIT);
            if (num_bytes_received == 0) //socket has been closed; break
            {
                syslog(LOG_INFO, "Closed connection from %s", connecting_ip_address);
                break;
            }
            else if (num_bytes_received < 0) //non-blocking call failed; continue
            {
                continue;
            }
            else
            {                   
                total_bytes_received += num_bytes_received;                
                if (*(packet_buf + total_bytes_received - 1) == '\n')
                {
                    output_file_desc = open(OUTPUT_FILENAME,
                                            O_CREAT | O_RDWR | O_APPEND,
                                            S_IRGRP | S_IRUSR | S_IROTH | S_IWGRP | S_IWUSR | S_IWOTH);
                    if (output_file_desc < 0)
                    {
                        perror("aesdsocket: Could not create output file");
                        retval = -1;
                        goto cleanup;
                    }
                    
                    write(output_file_desc, packet_buf, total_bytes_received);                             
                    number_of_reallocs = 0;
                    total_bytes_received = 0;

                    // Return contents of output file
                    lseek(output_file_desc, 0, SEEK_SET);
                    size_t num_bytes_read;
                    do
                    {
                        num_bytes_read = read(output_file_desc, read_buffer, MAX_PACKET_SIZE);
                        if (send(acceptedFd, read_buffer, num_bytes_read, 0) == -1)
                        {
                            perror("aesdsocket: send failed");
                            free(read_buffer);
                            retval = -1;
                            goto cleanup;
                        }
                    } while (num_bytes_read > 0);
                    
                    free(read_buffer);
                    read_buffer = malloc(MAX_PACKET_SIZE * sizeof(char));
                    if (!read_buffer)
                    {
                        perror("aesdsocket: Could not re-create file read buffer after free");
                        retval = -1;
                        goto cleanup;
                    }

                    free(packet_buf);   
                    packet_buf = malloc(MAX_PACKET_SIZE * sizeof(char));

                    if (!packet_buf)
                    {
                        perror("aesdsocket: Could not re-create packet buffer after free");
                        retval = -1;
                        goto cleanup;
                    }

                }
                else
                {
                    // Admittedly, this could be wasteful, but assume a packet without a 
                    // '\n' is the maximum size and there is at least one more packet coming
                    // Realloc 3000b the first time and another 1500b each additional realloc
                    char * new_ptr = realloc(packet_buf, 2 * MAX_PACKET_SIZE + (number_of_reallocs * MAX_PACKET_SIZE));
                    if (!new_ptr)
                    {
                        perror("aesdsocket: Couldn't allocate additional memory for incoming data; dropping buffer");
                        total_bytes_received = 0;                        
                    }
                    else
                    {
                        packet_buf = new_ptr;                        
                        number_of_reallocs++;
                    }
                }
            }
        } while (!caught_signal);                    
    } while (!caught_signal);

cleanup:
    free(packet_buf);
    free(read_buffer);
    shutdown(acceptedFd, SHUT_RDWR);
    if (acceptedFd >= 0)
    {
        if (close(acceptedFd))
        {
            perror("aesdsocket: Could not close file descriptor for connection");
        }
    }
    if (s >= 0)
    {
        if (close(s))
        {
            perror("aesdsocket: Could not close file descriptor for socket");
        }
    }
    if (output_file_desc >= 0)
    {
        if (close(output_file_desc))
        {
            perror("aesdsocket: Could not close file descriptor for output file");
        }
    }
    if (!access(OUTPUT_FILENAME, F_OK)) // if file exists
    {
        if (remove(OUTPUT_FILENAME))
        {
            perror("aesdsocket: Could not remove output file");
        }
    }    
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
            syslog(LOG_INFO, "Caught signal %s, exiting", strsignal(signal_number));
            break;        
    }
}