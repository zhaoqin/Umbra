#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

int *p;
int size = 1 * 4096;

void *mem_scan(void *ptr)
{
  int i, j;
  
  for (j = 0; j < 10; j++) 
  for (i = 0; i < size; i += 1024) {
      p[i] = i;
      if (i % 1024 == 0)
	printf("%s p[%d] at %p is %d\n", (char *)ptr, i, &p[i], p[i]);
  }
}


int main()
{
  pthread_t thread1, thread2;
  char *msg1 = "thread 1";
  char *msg2 = "thread 2";
  p = malloc(size * sizeof(int));
  printf("Allocate %d ints at %p\n", size, p);
  printf("create thread 1\n");
  pthread_create(&thread1, NULL, mem_scan, msg1);
  printf("create thread 2\n");
  pthread_create(&thread2, NULL, mem_scan, msg2);
  pthread_join(thread1, NULL);
  pthread_join(thread2, NULL);
  return 0;
}
