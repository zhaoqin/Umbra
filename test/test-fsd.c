#include <stdio.h>
#include <pthread.h>

int sum[2];

void *
parallel_sum(void *ptr)
{
    int i, j;
    int *p = (int *)ptr;
    for (i = 0; i < 10000; i++) {
        for (j = 0; j < 10000; j++) {
            *p += j;
        }
    }
}

int main()
{
    pthread_t thread1, thread2;
    pthread_create(&thread1, NULL, parallel_sum, &sum[0]);
    pthread_create(&thread2, NULL, parallel_sum, &sum[1]);
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    printf("%d, %d\n", sum[0], sum[1]);
    return 0;
}
