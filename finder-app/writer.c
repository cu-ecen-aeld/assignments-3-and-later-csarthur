#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

int main(int argc, char ** argv)
{
    int ret_val = 0;

    openlog("writer", LOG_CONS | LOG_PID, LOG_USER);
    
    if (argc != 3)
    {
        printf("writer: usage:  writer <writefile> <writeval>\r\n");
        syslog(LOG_ERR, "Invoked with incorrect number of parameters");
        exit(1);
    }

    const char * writefile = argv[1];
    const char * writestr = argv[2];

    int fd = open(writefile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
    if (fd < 0)
    {
        const char * error = "writer: Could not open file for writing";
        perror(error);
        syslog(LOG_ERR, "%s", error);
        exit(1);
    }

    size_t bytes_written = write(fd, writestr, strlen(writestr));
    if (bytes_written != strlen(writestr))
    {
        const char * error = "writer: Write wrote fewer bytes than expected";
        perror(error);
        syslog(LOG_ERR, "%s", error);
        ret_val = 1;
    }
    else
    {
        syslog(LOG_DEBUG, "Writing %s to %s", argv[2], argv[1]);
    }
    close(fd);
    closelog();
    return ret_val;
}