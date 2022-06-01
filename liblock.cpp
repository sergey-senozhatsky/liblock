#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>

#ifndef UNW_LOCAL_ONLY
#define UNW_LOCAL_ONLY
#endif
#include <libunwind.h>

#include <cstdlib>
#include <cstdio>
#include <string>
#include <iostream>
#include <vector>
#include <unordered_map>

using namespace std;

static volatile int __init_done;
static volatile __thread int __tracing_depth;

static int (*libc_pthread_mutex_lock)(pthread_mutex_t *)		= pthread_mutex_lock;
static int (*libc_pthread_mutex_trylock)(pthread_mutex_t *)		= pthread_mutex_trylock;
static int (*libc_pthread_mutex_timedlock)(pthread_mutex_t *,
					   const struct timespec *)	= pthread_mutex_timedlock;
static int (*libc_pthread_mutex_unlock)(pthread_mutex_t *)		= pthread_mutex_unlock;
static char *(*libc_getenv)(const char *)				= getenv;
static int (*libc_dlclose)(void *)					= dlclose;

struct trace {
	pthread_mutex_t		*lock;
	struct timeval		event_tv;
	string			event_trace;
};

#define FN_NAME_SZ		128

struct symbol {
	unsigned long		start_ip;
	unsigned long		end_ip;
	char			fn_name[FN_NAME_SZ];
};

static unordered_map<unw_word_t, struct symbol *>		__symbols;
/*
 * TID is the key, then we have resizable array of locks that this
 * particular TID touched. It should not be that big, so liner scan
 * is OK. And since traces are per-TID then we should be races free,
 * only __locks hash table needs to be protected.
 */
static unordered_map<unsigned int, vector<struct trace *>>	__locks;
static pthread_mutex_t						__locks_lock = PTHREAD_MUTEX_INITIALIZER;

#define UNRESOLVED_SYM_NAME "<unknown>"
static volatile __thread int unwind_recursion;

static void __enter_tracing(void)
{
	__tracing_depth++;
}

static void __exit_tracing(void)
{
	__tracing_depth--;
}

static int __can_trace(void)
{
	if (!__init_done)
		return 0;

	return __tracing_depth < 2;
}

static void __lock(void)
{
	pthread_mutex_lock(&__locks_lock);
}

static void __unlock(void)
{
	pthread_mutex_unlock(&__locks_lock);
}


static void record_lock_trace_entry(struct trace *trace,
				    unw_word_t ip,
				    struct symbol *symbol)
{
	char buf[256] = {0, };

	snprintf(buf, sizeof(buf), "#[<0x%lx>] %s\n", ip, symbol->fn_name);
	trace->event_trace += buf;
}

static void store_resolved_symbol(unw_word_t ip, const char *fn_name)
{
	struct symbol *sym = new struct symbol;

	memset(sym, 0x00, sizeof(*sym));

	__lock();
	if (__symbols.find(ip) == __symbols.end()) {
		strcpy(sym->fn_name, fn_name);
		__symbols[ip] = sym;
	} else {
		delete sym;
	}
	__unlock();
}

static bool lookup_resolved_symbol(unw_word_t ip, struct symbol *sym)
{
	bool ret = false;
	memset(sym, 0x00, sizeof(*sym));

	__lock();
	if (__symbols.find(ip) != __symbols.end()) {
		memcpy(sym, __symbols[ip], sizeof(*sym));
		ret = true;
	}
	__unlock();

	return ret;
}

static void unwind(struct trace *trace)
{
	unw_cursor_t cursor;
	unw_context_t uc;
	int skip_frames = 2;
	int depth = 16;

	if (unwind_recursion) {
		return;
	}
	unwind_recursion++;

	if (unw_getcontext(&uc) != 0) {
		unwind_recursion--;
		return;
	}

	if (unw_init_local(&cursor, &uc) != 0) {
		unwind_recursion--;
		return;
	}

	while (depth) {
		unw_word_t ip;
		unsigned long offset;
		int should_break = 0;
		// unw_proc_info_t pip;
		struct symbol symbol;

		int rc = unw_get_reg(&cursor, UNW_REG_IP, &ip);
		if (rc != 0)
			break;

		/* first two frames are us */
		if (skip_frames-- > 0)
			goto cont;

		if (lookup_resolved_symbol(ip, &symbol)) {
			record_lock_trace_entry(trace, ip, &symbol);
			goto cont;
		}

		rc = unw_get_proc_name(&cursor,
				       symbol.fn_name,
				       FN_NAME_SZ,
				       (unw_word_t *)&offset);
		if (rc == 0) {
			//if (unw_get_proc_info(&cursor, &pip) != 0)
			//	break;

			store_resolved_symbol(ip, symbol.fn_name);
		} else {
			strcpy(symbol.fn_name, UNRESOLVED_SYM_NAME);
			store_resolved_symbol(ip, UNRESOLVED_SYM_NAME);
			should_break = true;
		}


		record_lock_trace_entry(trace, ip, &symbol);
cont:
		if (should_break)
			break;
		if (unw_step(&cursor) <= 0)
			break;
		depth--;
	}

	unwind_recursion--;
}

static trace *get_trace(pthread_mutex_t *lock, unsigned int pid)
{
	struct trace *trace = NULL;

	__lock();
	if (__locks.find(pid) == __locks.end())
		__locks[pid].reserve(7);
	auto &traces = __locks[pid];
	__unlock();

	for (auto t : traces) {
		if (t->lock == lock) {
			trace = t;
			break;
		}
	}

	if (!trace) {
		trace = new struct trace;

		trace->lock = lock;
		traces.push_back(trace);
	}

	gettimeofday(&trace->event_tv, NULL);
	return trace;
}

static void trace_header(struct trace *trace,
			 unsigned int pid,
			 const char *func)
{
	char buf[512] = {0, };

	snprintf(buf, sizeof(buf), "pid:%d event:%s lock:0x%lx ts:%lu.%06d\n",
		 pid,
		 func,
		 (unsigned long)trace->lock,
		 (unsigned long)trace->event_tv.tv_sec,
		 (int)trace->event_tv.tv_usec);

	trace->event_trace = buf;
}

static void show_trace(struct trace *trace)
{
	printf("%s\n", trace->event_trace.c_str());
	trace->event_trace.erase();
}

static void trace_pthread_enter(const char *func, pthread_mutex_t *lock)
{
	if (!__can_trace())
		return;

	unsigned int pid = gettid();
	struct trace *trace;

	trace = get_trace(lock, pid);
	trace_header(trace, pid, func);
	unwind(trace);
	show_trace(trace);
}

static void trace_pthread_exit(const char *func, pthread_mutex_t *lock, int ret)
{
	if (!__can_trace())
		return;

	unsigned int pid = gettid();
	struct trace *trace;

	trace = get_trace(lock, pid);
	trace_header(trace, pid, func);
	unwind(trace);
	show_trace(trace);
}

int pthread_mutex_lock(pthread_mutex_t *lock)
{
	int ret;

	__enter_tracing();
	trace_pthread_enter(__func__, lock);

	ret = libc_pthread_mutex_lock(lock);

	trace_pthread_exit(__func__, lock, ret);
	__exit_tracing();
	return ret;
}

int pthread_mutex_trylock(pthread_mutex_t *lock)
{
	int ret;

	__enter_tracing();
	trace_pthread_enter(__func__, lock);

	ret = libc_pthread_mutex_trylock(lock);

	trace_pthread_exit(__func__, lock, ret);
	__exit_tracing();
	return ret;
}

int pthread_mutex_timedlock(pthread_mutex_t *lock,
			    const struct timespec *ts)
{
	int ret;

	__enter_tracing();
	trace_pthread_enter(__func__, lock);

	ret = libc_pthread_mutex_timedlock(lock, ts);

	trace_pthread_exit(__func__, lock, ret);
	__exit_tracing();
	return ret;
}

int pthread_mutex_unlock(pthread_mutex_t *lock)
{
	int ret;

	__enter_tracing();

	ret = libc_pthread_mutex_unlock(lock);

	trace_pthread_exit(__func__, lock, ret);
	__exit_tracing();
	return ret;
}

char *getenv(const char *name)
{
	return libc_getenv(name);
}

int dlclose(void *handle)
{
	int ret;

	ret = libc_dlclose(handle);

	// our clean up code
	return ret;
}

__attribute__((constructor)) static void __init_liblock(void)
{
	if (__init_done == 1)
		return;

	libc_pthread_mutex_lock	=
		(int (*)(pthread_mutex_t*))dlsym(RTLD_NEXT, "pthread_mutex_lock");
	libc_pthread_mutex_trylock	=
		(int (*)(pthread_mutex_t*))dlsym(RTLD_NEXT, "pthread_mutex_trylock");
	libc_pthread_mutex_unlock	=
		(int (*)(pthread_mutex_t*))dlsym(RTLD_NEXT, "pthread_mutex_unlock");
	libc_pthread_mutex_timedlock	=
		(int (*)(pthread_mutex_t*, const timespec*))dlsym(RTLD_NEXT, "pthread_mutex_timedlock");
	libc_getenv			=
		(char* (*)(const char*))dlsym(RTLD_NEXT, "getenv");
	libc_dlclose			=
		(int (*)(void*))dlsym(RTLD_NEXT, "dlclose");

	if (getenv("LIBLOCK_LOG_DIR")) {
		//const char *base_path = getenv("LIBLOCK_LOG_DIR");
		//init_output_file(base_path);
	}

	__init_done = 1;
}
