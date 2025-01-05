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
#include <pthread.h>
#include <time.h>
#include <errno.h>

#define IP_ADDRESS_LENGTH 40
#define MAX_PACKET_SIZE 1500
#define OUTPUT_FILENAME "/var/tmp/aesdsocketdata"

struct connection_data_t
{
    pthread_t thread_id;
    int fd;
    char connecting_ip_address[IP_ADDRESS_LENGTH];
    pthread_mutex_t * mutex_ptr;
    int thread_done;
    int thread_return_val;
};

struct node_t
{    
    struct connection_data_t * thread_data;
    struct node_t * next;
};

void usage(char * prog_name);
static void signal_handler(int signal_number);
void * socket_thread(void * thread_data);
void cleanup_threads(struct node_t ** head);
static void timer_thread ( union sigval sigval );
static bool setup_timer( timer_t timerid, unsigned int timer_period_ms,
                         struct timespec *start_time);

//Globals
bool caught_signal = false;

int main(int argc, char ** argv)
{
    struct sigevent sev;
    timer_t timerid;    
    
    memset(&sev,0,sizeof(struct sigevent));
    /**
    * Setup a call to timer_thread passing in the td structure as the sigev_value
    * argument
    */
    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_value.sival_ptr = NULL;
    sev.sigev_notify_function = timer_thread;
    struct timespec start_time;
    if ( timer_create(CLOCK_MONOTONIC,&sev,&timerid) != 0 )
    {
        printf("Error %d (%s) creating timer!\n",errno,strerror(errno));
    }
    else
    {
        setup_timer(timerid, 10 * 1000, &start_time);
    }   
    int retval = 0;
    int run_as_daemon = 0;    
    pthread_mutex_t mutex;
    pthread_attr_t thread_attr;
    struct node_t * head = NULL;
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
    retval = pthread_mutex_init(&mutex, NULL);
    if (retval)
    {
        perror("aesdsocket: Failed to initialize mutex");
        exit(-1);
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

    int facility = (run_as_daemon) ? LOG_DAEMON : LOG_USER;
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
        int acceptedFd = accept(s, &connecting_addr, &addr_size);
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

// Spawn thread here
        struct connection_data_t * the_connection_data = malloc(sizeof (struct connection_data_t)); 
        if (!the_connection_data)
        {
            perror("aesdsocket: Couldn't allocate memory for new connection data");
            retval = -1;
            goto cleanup;
        }
        the_connection_data->fd = acceptedFd;
        the_connection_data->mutex_ptr = &mutex;
        memcpy(the_connection_data->connecting_ip_address,
                connecting_ip_address,
                sizeof(the_connection_data->connecting_ip_address));
        the_connection_data->thread_done = 0;
        pthread_attr_init(&thread_attr);
        pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE);
        int rc = pthread_create(&(the_connection_data->thread_id), &thread_attr, socket_thread, the_connection_data);
        printf("Created new thread %lu\r\n",the_connection_data->thread_id);
        if (rc)
        {
            perror("aesdsocket: Could not create thread:");
            retval = -1;
            goto cleanup;
        }
        else
        {
            struct node_t * node = malloc (sizeof(struct node_t));            
            node->thread_data = the_connection_data;
            node->next = NULL;
            // Enqueue
            struct node_t * this_node = head;
            if (this_node == NULL)
            {
                head = node;
            }
            else
            {
                while (this_node->next != NULL)
                {
                    this_node = this_node->next;
                }
                this_node->next = node;
            }
            
            cleanup_threads(&head);
        }
    } while (!caught_signal);

cleanup:

#if 0
    shutdown(acceptedFd, SHUT_RDWR);
    if (acceptedFd >= 0)
    {
        if (close(acceptedFd))
        {
            perror("aesdsocket: Could not close file descriptor for connection");
        }
    }
    if (output_file_desc >= 0)
    {
        if (close(output_file_desc))
        {
            perror("aesdsocket: Could not close file descriptor for output file");
        }
    }    
#endif    
    if (s >= 0)
    {
        if (close(s))
        {
            perror("aesdsocket: Could not close file descriptor for socket");
        }
    }

    if (!access(OUTPUT_FILENAME, F_OK)) // if file exists
    {
        if (remove(OUTPUT_FILENAME))
        {
            perror("aesdsocket: Could not remove output file");
        }
    }    
    cleanup_threads(&head);
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

void * socket_thread(void * thread_data)
{
    struct connection_data_t * data = (struct connection_data_t *)thread_data;

    char * packet_buf = malloc(MAX_PACKET_SIZE * sizeof(char));
    if (!packet_buf)
    {
        perror("aesdsocket: Couldn't malloc buffer for incoming data");
        data->thread_return_val = -1;
        data->thread_done = 1;
        return thread_data;
    }    
    
    int num_bytes_received = 0;
    int total_bytes_received = 0;
    int number_of_reallocs = 0;
    do
    {            
        num_bytes_received = recv(data->fd, packet_buf + total_bytes_received, MAX_PACKET_SIZE, MSG_DONTWAIT);
        if (num_bytes_received == 0) //socket has been closed; break
        {
            syslog(LOG_INFO, "Closed connection from %s", data->connecting_ip_address);
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
                int output_file_desc = open(OUTPUT_FILENAME,
                                        O_CREAT | O_RDWR | O_APPEND,
                                        S_IRGRP | S_IRUSR | S_IROTH | S_IWGRP | S_IWUSR | S_IWOTH);
                if (output_file_desc < 0)
                {
                    perror("aesdsocket: Could not create output file");
                    data->thread_return_val = -1;
                    free(packet_buf);                    
                    data->thread_done = 1;                    
                    return thread_data;
                }
                pthread_mutex_lock(data->mutex_ptr);
                int write_rc = write(output_file_desc, packet_buf, total_bytes_received);
                pthread_mutex_unlock(data->mutex_ptr);
                free(packet_buf);
                if (write_rc == -1)
                {
                    perror("aesdsocket: Write to output file failed");
                    data->thread_return_val = -1;
                    close(output_file_desc);                    
                    data->thread_done = 1;                    
                    return thread_data;
                }            
                
                number_of_reallocs = 0;
                total_bytes_received = 0;

                // Return contents of output file
                lseek(output_file_desc, 0, SEEK_SET);
                size_t num_bytes_read;
                char * read_buffer = malloc(MAX_PACKET_SIZE * sizeof(char));
                if (!read_buffer)
                {
                    perror("aesdsocket: Could not allocate file read buffer");
                    data->thread_return_val = -1;                    
                    data->thread_done = 1;                    
                    return thread_data;
                }                    
                do
                {
                    num_bytes_read = read(output_file_desc, read_buffer, MAX_PACKET_SIZE);
                    if (send(data->fd, read_buffer, num_bytes_read, 0) == -1)
                    {
                        perror("aesdsocket: send failed");
                        data->thread_return_val = -1;                        
                        free(read_buffer);
                        close(output_file_desc);
                        data->thread_done = 1;                        
                        return thread_data;
                    }
                } while (num_bytes_read > 0);
                
                close(output_file_desc);                
                free(read_buffer);
                
                packet_buf = malloc(MAX_PACKET_SIZE * sizeof(char));

                if (!packet_buf)
                {
                    perror("aesdsocket: Could not re-create packet buffer after free");
                    free (read_buffer);
                    data->thread_return_val = -1;
                    data->thread_done = 1;                    
                    return thread_data;
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
    
    free(packet_buf);    
    data->thread_done = 1;
    data->thread_return_val = 0;
    return thread_data;
}

void cleanup_threads(struct node_t ** head)
{
// Walk list looking for terminated threads and join
    struct node_t * this_node = *head;
    if (this_node)
    {
        int head_joined;

        do
        {
            head_joined = 0;
#if 0
            if (this_node)
            {
                printf("Checking node %lu, done: %d\r\n", this_node->thread_data->thread_id, this_node->thread_data->thread_done);
            }
#endif            
            if (this_node && this_node->thread_data->thread_done)
            {
                *head = this_node->next; // OK if NULL
                head_joined = 1;
                void ** thread_return_value = NULL;
#if 0                
                printf("Joining node %lu\r\n", this_node->thread_data->thread_id);
#endif                
                pthread_join(this_node->thread_data->thread_id, thread_return_value);     
                free(this_node->thread_data);
                free(this_node);
                this_node = *head;
            }
        } while (head_joined); // See if the new head needs to be joined

        // Start looking ahead one node at a time starting with the head
        while(this_node && this_node->next != NULL)
        {
#if 0
            printf("Checking node %lu, done: %d\r\n", this_node->next->thread_data->thread_id, this_node->next->thread_data->thread_done);
#endif            
            if (this_node->next->thread_data->thread_done)
            {                        
                struct node_t * node_to_free = this_node->next;
                this_node->next = this_node->next->next;                                                
                void ** thread_return_value = NULL;
#if 0                
                printf("Joining node %lu\r\n", node_to_free->thread_data->thread_id);
#endif                
                pthread_join(node_to_free->thread_data->thread_id, thread_return_value);
                free(node_to_free->thread_data);                        
                free(node_to_free);
            }
            this_node = this_node->next;
        }
    }            
}

static void timer_thread ( union sigval sigval )
{
//    struct thread_data *td = (struct thread_data*) sigval.sival_ptr;
    printf("************ 10 second timer fired ************\r\n");
}

static inline void timespec_add( struct timespec *result,
                        const struct timespec *ts_1, const struct timespec *ts_2)
{
    result->tv_sec = ts_1->tv_sec + ts_2->tv_sec;
    result->tv_nsec = ts_1->tv_nsec + ts_2->tv_nsec;
    if( result->tv_nsec > 1000000000L ) {
        result->tv_nsec -= 1000000000L;
        result->tv_sec ++;
    }
}


static bool setup_timer( timer_t timerid, unsigned int timer_period_ms,
                         struct timespec *start_time)
{
    bool success = false;
    if ( clock_gettime(CLOCK_MONOTONIC,start_time) != 0 )
    {
        printf("Error %d (%s) getting monotonic time\n",errno,strerror(errno));
    }
    else
    {
        struct itimerspec itimerspec;
        memset(&itimerspec, 0, sizeof(struct itimerspec));
        itimerspec.it_interval.tv_sec = timer_period_ms / 1000;
        //itimerspec.it_interval.tv_nsec = timer_period_ms * 1000000;
        timespec_add(&itimerspec.it_value,start_time,&itimerspec.it_interval);
        if( timer_settime(timerid, TIMER_ABSTIME, &itimerspec, NULL ) != 0 )
        {
            printf("Error %d (%s) setting timer\n",errno,strerror(errno));
        }
        else
        {
            success = true;
        }
    }
    return success;
}