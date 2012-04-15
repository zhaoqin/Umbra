#include <stdlib.h>
#include <stdio.h>

int main()
{
  int i;
  int size = 4 * 4096;
  int *p = malloc(size * sizeof(int));
  printf("Allocate %d ints at %p\n", size, p);
  for (i = 4096; i < size; i++) {
      p[i] = i;
      if (i % 1024 == 0)
	printf("p[%d] at %p is %d\n", i, &p[i], p[i]);
  }
  return 0;
}
