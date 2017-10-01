// A tiny shell program with job control
// Sam Lerman - slerman@ur.rochester.edu

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

// Misc manifest constants
#define MAXLINE    1024   /* max line size */
#define MAXARGS     128   /* max args on a command line */
#define MAXJOBS      16   /* max jobs at any point in time */

// Job states
#define UNDEF 0 /* undefined */
#define FG 1    /* running in foreground */
#define BG 2    /* running in background */
#define ST 3    /* stopped */

// Global variables
extern char **environ;      /* defined in libc */
char prompt[] = "SamShell> ";    /* command line prompt */
int verbose = 0;            /* if true, print additional output */
int nextjid = 1;            /* next job ID to allocate */
char sbuf[MAXLINE];         /* for composing sprintf messages */

struct job_t{              /* The job struct */
    pid_t pid;              /* job PID */
    int jid;                /* job ID [1, 2, ...] */
    int state;              /* UNDEF, BG, FG, or ST */
    char cmdline[MAXLINE];  /* command line */
};
struct job_t jobs[MAXJOBS]; /* The job list */

// Function prototypes
void eval(char *cmdline);
int builtin_cmd(char **argv);
void do_bgfg(char **argv);
void waitfg(pid_t pid);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);

// Helper routines
int parseline(const char *cmdline, char **argv);
void sigquit_handler(int sig);

void clearjob(struct job_t *job);
void initjobs(struct job_t *jobs);
int maxjid(struct job_t *jobs);
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline);
int deletejob(struct job_t *jobs, pid_t pid);
pid_t fgpid(struct job_t *jobs);
struct job_t *getjobpid(struct job_t *jobs, pid_t pid);
struct job_t *getjobjid(struct job_t *jobs, int jid);
int pid2jid(pid_t pid);
void listjobs(struct job_t *jobs);

void usage(void);
void unix_error(char *msg);
void app_error(char *msg);
typedef void handler_t(int);
handler_t *Signal(int signum, handler_t *handler);

// The shell's main routine
int main(int argc, char **argv){
    char c;
    char cmdline[MAXLINE];
    int emit_prompt = 1;

    // Redirect stderr to stdout (so that driver will get all output on the pipe connected to stdout)
    dup2(1, 2);

    // Parse the command line
    while ((c = (char) getopt(argc, argv, "hvp")) != EOF){
        switch (c){
            // Print help message
            case 'h':
                usage();
                break;
                // Emit additional diagnostic info
            case 'v':
                verbose = 1;
                break;
                // Don't print a prompt
            case 'p':
                // Handy for automatic testing
                emit_prompt = 0;
                break;
            default:
                usage();
        }
    }

    // Signal handlers
    Signal(SIGINT, sigint_handler);   /* ctrl-c */
    Signal(SIGTSTP, sigtstp_handler);  /* ctrl-z */
    Signal(SIGCHLD, sigchld_handler);  /* Terminated or stopped child */

    // This one provides a clean way to kill the shell
    Signal(SIGQUIT, sigquit_handler);

    // Initialize the job list
    initjobs(jobs);

    // Execute the shell's read/eval loop
    while (1){

        // Read command line
        if (emit_prompt){
            printf("%s", prompt);
            fflush(stdout);
        }
        if ((fgets(cmdline, MAXLINE, stdin) == NULL) && ferror(stdin))
            app_error("fgets error");

        // End of file (ctrl-d)
        if (feof(stdin)){
            fflush(stdout);
            exit(0);
        }

        // Evaluate the command line
        eval(cmdline);
        fflush(stdout);
        fflush(stdout);
    }
}

// Evaluate the command line that the user has just typed in
void eval(char *cmdline){
    // Mask set to block signals in case of race conditions
    sigset_t mask;

    // Array to store parsed arguments for built-in commands
    char* argv_no_pipes[MAXARGS];

    // Parse arguments into argv_no_pipes array, and store boolean for if the command is to be run in the background
    int is_background = parseline(cmdline, argv_no_pipes);

    // Error checking
    if(argv_no_pipes[0] == NULL){
        // Print error message if the command is not known
        printf("Error: Unknown command %s\n", argv_no_pipes[0]);

        // Return
        return;
    }

    // Handle built-in command, and store boolean for if the command is a built-in command
    int is_built_in = builtin_cmd(argv_no_pipes);

    // Handle any (non built-in) command
    if(!is_built_in){
        // Create mask set of signals to block
        sigemptyset(&mask);
        sigaddset(&mask, SIGCHLD);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGTSTP);

        // Block signals
        sigprocmask(SIG_BLOCK, &mask, NULL);

        // Initialize process ID
        int pid;

        // File descriptors
        int fildes[2];

        // Read in
        int read = 0;

        // Symbol for deliminating piped commands
        const char pipe_symbol[2] = "|";

        // Set the individual command in a pipe chain
        char *pipe_cmd = strtok(cmdline, pipe_symbol);

        // Loop through piped commands
        while(pipe_cmd != NULL) {
            // Array to store parsed arguments
            char* argv[MAXARGS];

            // Parse arguments into argv array, and store boolean for if the command is to be run in the background
            is_background = parseline(pipe_cmd, argv);

            // Error checking
            if(argv[0] == NULL){
                // Print error message if the command is not known
                printf("Error: Unknown command %s\n", argv[0]);

                // Return
                return;
            }

            // Iterate to next piped command string
            pipe_cmd = strtok(NULL, pipe_symbol);

            // Create pipe
            pipe(fildes);

            // Fork a new child process
            switch (pid = fork()) {
                // If child
                case 0:
                    // Unblock signals
                    sigprocmask(SIG_UNBLOCK, &mask, NULL);

                    // Set process group
                    setpgid(0, 0);

                    // Read file descriptor
                    if (read) {
                        dup2(read, 0);
                        close(read);
                    }

                    // Output write
                    if ((pipe_cmd != NULL) && (fildes[1] != 1)) {
                        dup2(fildes[1], 1);
                        close(fildes[1]);
                    }

                    // Execute the command TODO: execute ith command
                    execvp(argv[0], argv);

                    // Print error message if the command is not known
                    printf("Error: Unknown command %s\n", argv[0]);

                    // Exit child process if command is unknown
                    exit(0);
                    // If error
                case -1:
                    // Print error message
                    printf("Error: Could not fork a new process\n");

                    // Break
                    break;
                    // Default
                default:
                    // Set process group for parent (to be safe)
                    setpgid(pid, pid);

                    // Break
                    break;
            }

            // Close pipe write
            close(fildes[1]);

            // If not final command in pipe chain
            if (pipe_cmd != NULL) {
                // Set read input
                read = fildes[0];
            }
        }

        // Add the new job to job list, and if foreground then wait for process
        if(is_background){
            // Add the new background job to the jobs list and allow to run in the background
            addjob(jobs, pid, BG, cmdline);

            // Unblock signals
            sigprocmask(SIG_UNBLOCK, &mask, NULL);
        }
        else{
            // Add the new foreground job to the jobs list
            addjob(jobs, pid, FG, cmdline);

            // Unblock signals
            sigprocmask(SIG_UNBLOCK, &mask, NULL);

            // Wait for foreground process
            waitfg(pid);
        }
    }

    // Return
    return;
}

// Parse the command line and build the argv array
int parseline(const char *cmdline, char **argv){
    static char array[MAXLINE]; /* holds local copy of command line */
    char *buf = array;          /* ptr that traverses command line */
    char *delim;                /* points to first space delimiter */
    int argc;                   /* number of args */
    int bg;                     /* background job? */

    strcpy(buf, cmdline);
    buf[strlen(buf)-1] = ' ';  /* replace trailing '\n' with space */
    while (*buf && (*buf == ' ')) /* ignore leading spaces */
        buf++;

    // Build the argv list
    argc = 0;
    if (*buf == '\''){
        buf++;
        delim = strchr(buf, '\'');
    }
    else{
        delim = strchr(buf, ' ');
    }

    while (delim){
        argv[argc++] = buf;
        *delim = '\0';
        buf = delim + 1;
        while (*buf && (*buf == ' ')) /* ignore spaces */
            buf++;

        if (*buf == '\''){
            buf++;
            delim = strchr(buf, '\'');
        }
        else{
            delim = strchr(buf, ' ');
        }
    }
    argv[argc] = NULL;

    if (argc == 0)  /* ignore blank line */
        return 1;

    // Should the job run in the background?
    if ((bg = (*argv[argc-1] == '&')) != 0){
        argv[--argc] = NULL;
    }
    return bg;
}

// Built-in commands to be executed immediately
int builtin_cmd(char **argv){
    // Check which possible built-in command the argument matches
    if(!strcmp(argv[0],"exit")){
        // Exit on "exit" built-in command
        exit(0);
    }
    else if(!strcmp(argv[0],"cd")){
        // Change directory to specified address, and return any errors
        if(chdir(argv[1]) == -1){
            // Print error message
            printf("Error: Could not change to specified directory\n");
        }

        // Built-in command
        return 1;
    }
    else if(!strcmp(argv[0],"jobs")){
        // List background jobs
        listjobs(jobs);

        // Built-in command
        return 1;
    }
    else if((!strcmp(argv[0],"bg")) || (!strcmp(argv[0],"fg"))){
        // Execute background/foreground handler
        do_bgfg(argv);

        // Built-in command
        return 1;
    }
    // Not a built-in command
    return 0;
}

// Execution of background and foreground commands
void do_bgfg(char **argv){
    // Initialize job struct
    struct job_t *job;

    // If no arguments provided
    if(argv[1] == NULL){
        // Print error
        printf("Error: No args\n");

        // Return
        return;
    }
        // Handle job ID
    else if(argv[1][0] == '%'){
        // Parse job
        int job_arg = (int) strtol(argv[1] + 1, NULL, 10);

        // If argument is not in valid form
        if(!job_arg){
            // Print error
            printf("Error: Invalid arg\n");

            // Return
            return;
        }

        // Get the job id
        job = getjobjid(jobs, job_arg);

        // If job doesn't exist
        if(job == NULL){
            // Print error
            printf("Error: Invalid job\n");

            // Return
            return;
        }
    }
        // Handle process ID
    else{
        // Parse process
        int process = (int) strtol(argv[1], NULL, 10);

        // If argument is not in valid form
        if(!process){
            // Print error
            printf("Error: Invalid arg\n");

            // Return
            return;
        }

        // Get the job for the process
        job = getjobpid(jobs, process);

        // If process doesn't exist
        if(job == NULL){
            // Print error
            printf("Error: Invalid process\n");

            // Return
            return;
        }
    }

    // Continue the execution (in case of stop)
    kill(-(job->pid), SIGCONT);

    // Foreground state change
    if(!strcmp(argv[0], "fg")){
        // Change state to foreground
        job->state = FG;

        // Wait on foreground process
        waitfg(job->pid);
    }
        // Background state change
    else{
        // Change state to background
        job->state = BG;
    }

    // Return
    return;
}

// Block until process pid is no longer the foreground process
void waitfg(pid_t pid) {
    // Initialize status variable
    int stat_loc;

    // Wait for the process
    waitpid(pid, &stat_loc, WUNTRACED);

    // Get the job for this process
    struct job_t *process_job = getjobpid(jobs, pid);

    // If the process has not terminated, but has stopped and can be restarted
    if (WIFSTOPPED(stat_loc)) {
        // Change job's state to stopped
        process_job->state = ST;
    }
        // If the process terminated due to receipt of a signal or by a call to exit(2) or exit(3)
    else if(WIFSIGNALED(stat_loc) || WIFEXITED(stat_loc)){
        // Delete the job
        deletejob(jobs, pid);
    }

    // Return
    return;
}

// Kernel sends a SIGCHLD when a child job terminates (becomes a zombie), or stops, then reaps zombie children
void sigchld_handler(int sig){
    // Process
    pid_t process;

    // Status
    int stat_loc;

    // Reap child processes
    while ((process = waitpid(-1, &stat_loc, WNOHANG)) >= 1) {
        // Job for this process
        struct job_t *process_job = getjobpid(jobs, process);

        // If the process has not terminated, but has stopped and can be restarted
        if (WIFSTOPPED(stat_loc)) {
            // Change job's state to stopped
            process_job->state = ST;
        }
            // If the process terminated due to receipt of a signal or by a call to exit(2) or exit(3)
        else if(WIFSIGNALED(stat_loc) || WIFEXITED(stat_loc)){
            // Delete the job
            deletejob(jobs, process);
        }
    }

    // Return
    return;
}

// Use ctrl-C to send an interrupt to the foreground job
void sigint_handler(int sig){
    // Foreground process
    pid_t process = fgpid(jobs);

    // Job for this process
    struct job_t *process_job = getjobpid(jobs, process);

    // If process is valid
    if(process){
        // Perform sigint on foreground process
        if(!kill(process, sig)){
            // Print notification that job has been stopped
            printf("\n%d interrupted\n", process_job->jid);
        }
    }
    else{
        // Print error
        printf("\nError: No running foreground process\n");

        // Read command line
        printf("%s", prompt);
        fflush(stdout);
    }

    // Return
    return;
}

// Use ctrl-Z to suspend the foreground job by sending it a SIGTSTP.
void sigtstp_handler(int sig){
    // Foreground process
    pid_t process = fgpid(jobs);

    // Job for this process
    struct job_t *process_job = getjobpid(jobs, process);

    // If process is valid
    if (process){
        // Perform sigstop
        if(!kill(process, sig)){
            // Print notification that job has been stopped
            printf("\n%d stopped\n", process_job->jid);
        }
    }
    else{
        // Print error
        printf("\nError: No running foreground process\n");

        // Read command line
        printf("%s", prompt);
        fflush(stdout);
    }

    // Return
    return;
}

// Clear the entries in a job struct
void clearjob(struct job_t *job){
    job->pid = 0;
    job->jid = 0;
    job->state = UNDEF;
    job->cmdline[0] = '\0';
}

// Initialize the job list
void initjobs(struct job_t *jobs){
    int i;

    for (i = 0; i < MAXJOBS; i++)
        clearjob(&jobs[i]);
}

// Returns largest allocated job ID
int maxjid(struct job_t *jobs){
    int i, max=0;

    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].jid > max)
            max = jobs[i].jid;
    return max;
}

//Add a job to the job list
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline){
    int i;

    if (pid < 1)
        return 0;

    for (i = 0; i < MAXJOBS; i++){
        if (jobs[i].pid == 0){
            jobs[i].pid = pid;
            jobs[i].state = state;
            jobs[i].jid = nextjid++;
            if (nextjid > MAXJOBS)
                nextjid = 1;
            strcpy(jobs[i].cmdline, cmdline);
            if(verbose){
                printf("Added job [%d] %d %s\n", jobs[i].jid, jobs[i].pid, jobs[i].cmdline);
            }
            return 1;
        }
    }
    printf("Tried to create too many jobs\n");
    return 0;
}

// Delete a job whose PID=pid from the job list
int deletejob(struct job_t *jobs, pid_t pid){
    int i;

    if (pid < 1)
        return 0;

    for (i = 0; i < MAXJOBS; i++){
        if (jobs[i].pid == pid){
            clearjob(&jobs[i]);
            nextjid = maxjid(jobs)+1;
            return 1;
        }
    }
    return 0;
}

// Return PID of current foreground job, 0 if no such job
pid_t fgpid(struct job_t *jobs){
    int i;

    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].state == FG)
            return jobs[i].pid;
    return 0;
}

// Find a job (by PID) on the job list
struct job_t *getjobpid(struct job_t *jobs, pid_t pid){
    int i;

    if (pid < 1)
        return NULL;
    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].pid == pid)
            return &jobs[i];
    return NULL;
}

// Find a job (by JID) on the job list
struct job_t *getjobjid(struct job_t *jobs, int jid){
    int i;

    if (jid < 1)
        return NULL;
    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].jid == jid)
            return &jobs[i];
    return NULL;
}

// Map process ID to job ID
int pid2jid(pid_t pid){
    int i;

    if (pid < 1)
        return 0;
    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].pid == pid){
            return jobs[i].jid;
        }
    return 0;
}

// Print the job list
void listjobs(struct job_t *jobs){
    // For loop iterator
    int i;

    // For all jobs
    for (i = 0; i < MAXJOBS; i++){
        // If valid background job
        if ((jobs[i].pid) && (jobs[i].state == BG)){
            // Print job id and command
            printf("%d: %s", jobs[i].jid, jobs[i].cmdline);
        }
    }

    // Return
    return;
}

// Print a help message
void usage(void){
    printf("Usage: shell [-hvp]\n");
    printf("   -h   print this message\n");
    printf("   -v   print additional diagnostic information\n");
    printf("   -p   do not emit a command prompt\n");
    exit(1);
}

// Unix-style error routine
void unix_error(char *msg){
    fprintf(stdout, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

// Application-style error routine
void app_error(char *msg){
    fprintf(stdout, "%s\n", msg);
    exit(1);
}

// Wrapper for the sigaction function
handler_t *Signal(int signum, handler_t *handler){
    struct sigaction action, old_action;

    action.sa_handler = handler;
    sigemptyset(&action.sa_mask); /* block sigs of type being handled */
    action.sa_flags = SA_RESTART; /* restart syscalls if possible */

    if (sigaction(signum, &action, &old_action) < 0)
        unix_error("Signal error");
    return (old_action.sa_handler);
}

// The driver program can gracefully terminate the child shell by sending it a SIGQUIT signal
void sigquit_handler(int sig){
    printf("Terminating after receipt of SIGQUIT signal\n");
    exit(1);
}
