#include <sys/mman.h>  // for mprotect 
#include <signal.h>    // for signal handling 
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include <unistd.h>
#include <malloc.h>
#include <errno.h>

int pagesize;

//int    *aikido_has_inited;
void  **aikido_prot_none;
void  **aikido_prot_read;
size_t *aikido_saved_addr;

#define handle_error(msg) \
  do { perror(msg); exit(EXIT_FAILURE); } while (0)

static void
handler(int sig, siginfo_t *si, void *unused)
{
  unsigned long ret;
#ifdef VERBOSE
  printf("Got SIGSEGV at address: 0x%lx\n", (long) si->si_addr);
#endif
#ifdef AIKIDO
  if (aikido_is_aikido_fault((unsigned long)si->si_addr, 
			     &ret)) {
# ifdef VERBOSE
    printf("aikido sigsegv\n");
# endif
    aikido_unmprotect((void *)ret, pagesize);
    return;
  }
#endif
  mprotect(si->si_addr, pagesize, PROT_WRITE | PROT_READ);
}

 int *p1, *p2;
//long size = 4000 * 4096;
#define size  (100 * 4096)
//long size = 100 * 4096;
//long size = 1024;

void *mem_scan(void *ptr)
{
  long i, j;
  int *p = (int *)ptr;
  volatile int trash = 0;
 
#ifdef AIKIDO
#ifdef VERBOSE
  printf("Aikido init\n");
#endif 
  aikido_init();
  /* 
  aikido_save_tls(&aikido_has_inited, &aikido_prot_none,
		  &aikido_prot_read,  &aikido_saved_addr);
  */
#endif

  /* protect the memory */
#ifdef AIKIDO_PROTECTION
  printf("Aikido protecting memory %p, %d\n", ptr, size * sizeof(int));
  //aikido_mprotect(ptr, size * sizeof(int), PROT_NONE);
  for (i = 0; i < size; i += pagesize) {
    if (i % (2 * pagesize) == 0) {
      printf("Aikido protection %p %d\n", (void *)ptr + i, pagesize);
      aikido_mprotect((void *)ptr + i, pagesize, PROT_NONE);
    }
  }
#endif
#ifdef OS_PROTECTION
  printf("OS protection %p %d\n", ptr, size * sizeof(int));
  //  if (mprotect((void *)ptr, size * sizeof(int), PROT_NONE) == -1)
  //    handle_error("mprotect");
#if 1
  /* we protect the page alternatively to test the performance */
  for (i = 0; i < size; i += pagesize) {
    if (i % (1 * pagesize) == 0) {
      printf("OS protection %p %d\n", (void *)ptr + i, pagesize);
      if (mprotect((void *)ptr + i, pagesize, PROT_NONE) == -1)
	handle_error("mprotect");
    }
  }
#endif
#endif
  for (j = 0; j < 500; j++) {
    for (i = 0; i < size; i += 1) {
      p[i] = i;
      trash++;
    }
  }
}

int main()
{
#ifdef MULTI_THREAD
  pthread_t thread1, thread2;
  char *msg1 = "thread 1";
  char *msg2 = "thread 2";
#endif

  struct sigaction sa;

#ifdef AIKIDO
# ifdef VERBOSE
  printf("Aikido init Cleanup\n");
# endif 
  aikido_cleanup();
#endif
  pagesize = sysconf(_SC_PAGE_SIZE);
  if (pagesize == -1)
    handle_error("sysconf");

  /* register signal action */
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = handler;
  if (sigaction(SIGSEGV, &sa, NULL) == -1)
    handle_error("sigaction");

  p1 = memalign(pagesize, (size * sizeof(int)));
  p2 = memalign(pagesize, (size * sizeof(int)));

#ifdef MULTI_THREAD
  printf("create thread 1\n");
  pthread_create(&thread1, NULL, mem_scan, p1);
  printf("create thread 2\n");
  pthread_create(&thread2, NULL, mem_scan, p2);
  pthread_join(thread1, NULL);
  pthread_join(thread2, NULL);
  printf("exiting\n");
#else
  printf("calling mem_scan\n");
  mem_scan(p1);
#endif /* MULTI_THREAD */

#ifdef AIKIDO
# ifdef VERBOSE
  printf("Aikido Exit Cleanup\n");
# endif
  aikido_cleanup();
#endif
  return 0;
}
