#include<stdio.h>
#include<string.h>
#include<pthread.h>
#include<stdlib.h>
#include<unistd.h>

static pthread_t tid[2];
static pthread_mutex_t lock;
static int counter;

void *do_nothing_loop(void *arg)
{
	unsigned long i = 0;

	printf("\n Job %d started\n", counter);

	for (i = 0; i < 10; i++) {
		pthread_mutex_lock(&lock);
		counter += 1;
		pthread_mutex_unlock(&lock);
	}

	printf("\n Job %d finished\n", counter);
	return NULL;
}

int main(void)
{
	int i = 0;
	int err;

	if (pthread_mutex_init(&lock, NULL) != 0) {
		printf("\n mutex init failed\n");
		return 1;
	}

	while (i < 2) {
		err = pthread_create(&(tid[i]), NULL, &do_nothing_loop, NULL);
		if (err != 0)
			printf("\ncan't create thread :[%s]", strerror(err));
		i++;
	}

	pthread_join(tid[0], NULL);
	pthread_join(tid[1], NULL);

	return 0;
}
