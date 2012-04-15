#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

 int *p1, *p2;
//long size = 4000 * 4096;
//#define size  (100 * 4096)
long size = 100 * 4096;
//long size = 1024;

void *mem_scan(void *ptr)
{
  long i, j;
  int *p = (int *)ptr;
  volatile int trash = 0;
  
  for (j = 0; j < 500; j++) 
  {
  for (i = 0; i < size; i += 1) {
      p[i] = i;
      trash++;
      //      if (i % 1024 == 0)
      //	printf("p[%d] at %p is %d\n", i, &p[i], p[i]);
  }
  }
}


int main()
{
  pthread_t thread1, thread2;
  char *msg1 = "thread 1";
  char *msg2 = "thread 2";
  p1 = malloc(size * sizeof(int));
  p2 = malloc(size * sizeof(int));
  printf("create thread 1\n");
  pthread_create(&thread1, NULL, mem_scan, p1);
  printf("create thread 2\n");
  pthread_create(&thread2, NULL, mem_scan, p2);
  sleep(1);
  pthread_join(thread1, NULL);
  pthread_join(thread2, NULL);
  printf("exiting");
  return 0;
}
