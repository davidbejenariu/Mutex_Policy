#include <stdio.h> // printf
#include <pthread.h> // pthread_create, pthread_join

const int MTX_OPEN = 331;
const int MTX_CLOSE = 332;
const int MTX_LOCK = 333;
const int MTX_UNLOCK = 334;

int d, s = 0;

void* test_function(void* p){
    pid_t pid = getpid();
    
    int i;
    for (i=1; i<=15; i++){
        syscall(MTX_LOCK, d);
        s += 1;
        syscall(MTX_UNLOCK, d);

        sleep(0);
    }

    return NULL;
}

int main() {
    // Cream doua procese identice
    fork();

    d = syscall(MTX_OPEN);

    // Cream 2 threads in fiecare proces. Descriptorii trebuie sa fie per-proces.
    int num_threads = 2;
    pthread_t threads[num_threads]; 
    int i;
    for (i=0; i<num_threads; i++){
        pthread_create(&threads[i], NULL, test_function, NULL);
    }
    for (i=0; i<num_threads; i++){
        pthread_join(threads[i], NULL);
    }

    syscall(MTX_CLOSE, d);
    printf("Procesul [%d]: %d\n", getpid(), s);

    return 0;
}