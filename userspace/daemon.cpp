#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unordered_map>
 
#define global_max 1000
 
//to compile use "clang++ -std=c++11 daemon.cpp -o daemon"
 
const int MTX_OPEN = 331;
const int MTX_CLOSE = 332;
const int MTX_LOCK = 333;
const int MTX_UNLOCK = 334;
const int MTX_LIST = 335;
const int MTX_GRANT = 336;
 
std::unordered_map <int, int> id_proc;
 
int last_modify[global_max][global_max];
 
int main(int argc, char **argv) {
    pid_t process_id = 0;
    pid_t sid = 0;
 
    // Create child process
    process_id = fork();
 
    // It shows that out fork has failed
    if (process_id < 0) {
        printf("fork failed!\n");
        exit(1);
    }
 
    if (process_id > 0) {
        // PARENT PROCESS. Need to kill it.
        printf("PID of child process %d \n", process_id);
        // return success in exit status
        exit(0);
    }
 
    // unmask the file mode
    umask(0);
 
    // set new session
    sid = setsid();
 
    if (sid < 0) {
        exit(1);
    }
 
    // Change the current working directory to root.
    chdir("/");
 
    // Close stdin. stdout and stderr
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
 
    pid_t *procs = (pid_t *)malloc(global_max * sizeof(pid_t));
    int *d_mtx = (int *)malloc(global_max * sizeof(int));
    pid_t *threads = (pid_t *)malloc(global_max * sizeof(pid_t));
    memset(last_modify, 0, sizeof(last_modify));
 
    int check_step = 0;
 
    while (1) {
        // Dont block context switches, let the process sleep for some time
        sleep(0);
 
        int pair_number = syscall(MTX_LIST, procs, d_mtx, threads, global_max);
        int proc_nr = 0;
        int i;
        for(i = 1; i < pair_number; ++i){
            proc_nr++;
            id_proc[procs[i]] = proc_nr;
        }
        i = 1;
        time_t t;
        srand((unsigned) time(&t));
        while(i < pair_number){
            int index_to_swap = rand() % i;
            int aux = d_mtx[index_to_swap];
            d_mtx[index_to_swap] = d_mtx[i];
            d_mtx[i] = aux;
 
            aux = threads[index_to_swap];
            threads[index_to_swap] = threads[i];
            threads[i] = aux;
 
            aux = procs[index_to_swap];
            procs[index_to_swap] = procs[i];
            procs[i] = aux;

            i++;
        }
 
        // Updating last_modify
        check_step++;
 
        i = 0;
        while(i < pair_number){
            if(last_modify[id_proc[procs[i]]][d_mtx[i]] != check_step){
                last_modify[id_proc[procs[i]]][d_mtx[i]] = check_step;
                syscall(MTX_GRANT, procs[i], d_mtx[i], threads[i]);
            }

            i++;
        }
 
    }
    return 0;
}