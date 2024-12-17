#include "systemcalls.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{

/*
 *  Call the system() function with the command set in the cmd
 *   and return a boolean true if the system() call completed with success
 *   or false() if it returned a failure
*/
    int ret_val = system(cmd);    
    if (ret_val != 0)
    {
        perror("do_system: System call failed");
        return false;
    }    
    return true;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    bool was_success = true;
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    // command[count] = command[count];

/*
 *   Execute a system command by calling fork, execv(),
 *   and wait instead of system (see LSP page 161).
 *   Use the command[0] as the full path to the command to execute
 *   (first argument to execv), and use the remaining arguments
 *   as second argument to the execv() command.
 *
*/
    int my_pid = fork();
    if (my_pid == -1)
    {
        perror("do_exec: fork failed");
        was_success = false;
    }
    if (my_pid == 0)
    {
        // I am the child
        execv(command[0], command);
        // Should never get here
        perror("do_exec: execv failed in child");    
        va_end(args);
        exit(1);                    
    }
    else
    {
        // I am the parent
        int wstatus;
        int ret_val = waitpid(my_pid, &wstatus, 0);
        if (ret_val == -1)
        {
            perror("do_exec: wait failed in parent");
            was_success = false;
        }        
        else
        {
            if (WIFEXITED(wstatus))
            {
                if (WEXITSTATUS(wstatus))
                {                    
                    was_success = false;
                }
            }
            else
            {
                was_success = false;
            }
        }
    }
    va_end(args);
    return was_success;
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    bool was_success = true;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;

/*
 * TODO
 *   Call execv, but first using https://stackoverflow.com/a/13784315/1446624 as a refernce,
 *   redirect standard out to a file specified by outputfile.
 *   The rest of the behaviour is same as do_exec()
 *
*/
    int fd = open(outputfile, O_WRONLY | O_TRUNC | O_CREAT, 0664);
    if (fd < 0)
    {
        perror("do_exec_redirect: Could not open output file for redirection");
        return false;
    }

    int my_pid = fork();
    if (my_pid == 0)
    {
        // I am the child        
        int ret_val = dup2(fd, 1);
        if (ret_val != 1)
        {
            perror("do_exec_redirect: Unable to duplicate file descriptor to stdout for fork");
            return false;
        }        
        close(fd);        
        execv(command[0], command);        
        // Should never get here
        perror("do_exec_redirect: execv failed in child:");
        return false;                        
    }
    else
    {
        // I am the parent
        int wstatus;
        close(fd);
        int ret_val = waitpid(my_pid, &wstatus, 0);
        if (ret_val == -1)
        {
            perror("do_exec_redirect: wait failed in parent");
            was_success = false;
        }        
        else
        {
            if (WIFEXITED(wstatus))
            {
                if (WEXITSTATUS(wstatus))
                {                    
                    was_success = false;
                }
            }
            else
            {
                was_success = false;
            }
        }        
    }
    va_end(args);

    return was_success;
}
