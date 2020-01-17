#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include "perf_buffer.h"
#include "bpf_syscall_helpers.h"
#include "uid.h"

// linux/tools/lib/bpf/libbpf.c:
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#define STRERR_BUFSIZE  128

#define ERR_PTR(error) ((void*)(unsigned long)error)
#define IS_ERR(x) ((unsigned long)(void*)(x)>=(unsigned long)-4096)
#define PTR_ERR(ptr) ((long)ptr)

int libbpf_num_possible_cpus(void);

enum bpf_perf_event_ret {
                         LIBBPF_PERF_EVENT_DONE	= 0,
                         LIBBPF_PERF_EVENT_ERROR	= -1,
                         LIBBPF_PERF_EVENT_CONT	= -2,
};

typedef enum bpf_perf_event_ret
(*perf_buffer_event_fn)(void *ctx, int cpu, struct perf_event_header *event);

/* raw perf buffer options, giving most power and control */
struct perf_buffer_raw_opts {
  /* perf event attrs passed directly into perf_event_open() */
  struct perf_event_attr *attr;
  /* raw event callback */
  perf_buffer_event_fn event_cb;
  /* ctx is provided to event_cb */
  void *ctx;
  /* if cpu_cnt == 0, open all on all possible CPUs (up to the number of
   * max_entries of given PERF_EVENT_ARRAY map)
   */
  int cpu_cnt;
  /* if cpu_cnt > 0, cpus is an array of CPUs to open ring buffers on */
  int *cpus;
  /* if cpu_cnt > 0, map_keys specify map keys to set per-CPU FDs for */
  int *map_keys;
};

typedef enum bpf_perf_event_ret
(*bpf_perf_event_print_t)(struct perf_event_header *hdr,
                          void *private_data);

char *libbpf_strerror_r(int err, char *dst, int len)
{
  return strerror_r(err < 0 ? -err : err, dst, len);
}

enum bpf_perf_event_ret
bpf_perf_event_read_simple(void *mmap_mem, size_t mmap_size, size_t page_size,
			   void **copy_mem, size_t *copy_size,
			   bpf_perf_event_print_t fn, void *private_data)
{
  struct perf_event_mmap_page *header = mmap_mem;
  __u64 data_head = header->data_head;
  __asm__ volatile("" ::: "memory");
  __u64 data_tail = header->data_tail;
  void *base = ((__u8 *)header) + page_size;
  int ret = LIBBPF_PERF_EVENT_CONT;
  struct perf_event_header *ehdr;
  size_t ehdr_size;

  while (data_head != data_tail) {
    ehdr = base + (data_tail & (mmap_size - 1));
    ehdr_size = ehdr->size;

    if (((void *)ehdr) + ehdr_size > base + mmap_size) {
      void *copy_start = ehdr;
      size_t len_first = base + mmap_size - copy_start;
      size_t len_secnd = ehdr_size - len_first;

      if (*copy_size < ehdr_size) {
        free(*copy_mem);
        *copy_mem = malloc(ehdr_size);
        if (!*copy_mem) {
          *copy_size = 0;
          ret = LIBBPF_PERF_EVENT_ERROR;
          break;
        }
        *copy_size = ehdr_size;
      }

      memcpy(*copy_mem, copy_start, len_first);
      memcpy(*copy_mem + len_first, base, len_secnd);
      ehdr = *copy_mem;
    }

    ret = fn(ehdr, private_data);
    data_tail += ehdr_size;
    if (ret != LIBBPF_PERF_EVENT_CONT)
      break;
  }

  __asm__ volatile("" ::: "memory");
  header->data_tail = data_tail;
  return ret;
}

typedef enum bpf_perf_event_ret
(*perf_buffer_event_fn)(void *ctx, int cpu, struct perf_event_header *event);

struct perf_buffer_params {
  struct perf_event_attr *attr;
  /* if event_cb is specified, it takes precendence */
  perf_buffer_event_fn event_cb;
  /* sample_cb and lost_cb are higher-level common-case callbacks */
  perf_buffer_sample_fn sample_cb;
  perf_buffer_lost_fn lost_cb;
  void *ctx;
  int cpu_cnt;
  int *cpus;
  int *map_keys;
};

struct perf_cpu_buf {
  struct perf_buffer *pb;
  void *base; /* mmap()'ed memory */
  void *buf; /* for reconstructing segmented data */
  size_t buf_size;
  int fd;
  int cpu;
  int map_key;
};

struct perf_buffer {
  perf_buffer_event_fn event_cb;
  perf_buffer_sample_fn sample_cb;
  perf_buffer_lost_fn lost_cb;
  void *ctx; /* passed into callbacks */

  size_t page_size;
  size_t mmap_size;
  struct perf_cpu_buf **cpu_bufs;
  struct epoll_event *events;
  int cpu_cnt;
  int epoll_fd; /* perf event FD */
  int map_fd; /* BPF_MAP_TYPE_PERF_EVENT_ARRAY BPF map FD */
};

static void perf_buffer__free_cpu_buf(struct perf_buffer *pb,
				      struct perf_cpu_buf *cpu_buf)
{
  if (!cpu_buf)
    return;
  if (cpu_buf->base &&
      munmap(cpu_buf->base, pb->mmap_size + pb->page_size))
    fprintf(stderr,"failed to munmap cpu_buf #%d\n", cpu_buf->cpu);
  if (cpu_buf->fd >= 0) {
    ioctl(cpu_buf->fd, PERF_EVENT_IOC_DISABLE, 0);
    close(cpu_buf->fd);
  }
  free(cpu_buf->buf);
  free(cpu_buf);
}

void perf_buffer_free(struct perf_buffer *pb)
{
  int i;

  if (!pb)
    return;
  if (pb->cpu_bufs) {
    for (i = 0; i < pb->cpu_cnt && pb->cpu_bufs[i]; i++) {
      struct perf_cpu_buf *cpu_buf = pb->cpu_bufs[i];

      bpf_map_delete_elem(pb->map_fd, &cpu_buf->map_key);
      perf_buffer__free_cpu_buf(pb, cpu_buf);
    }
    free(pb->cpu_bufs);
  }
  if (pb->epoll_fd >= 0)
    close(pb->epoll_fd);
  free(pb->events);
  free(pb);
}

// CR rcummings: doesn't work on offline CPUs
static struct perf_cpu_buf *
perf_buffer__open_cpu_buf(struct perf_buffer *pb, struct perf_event_attr *attr,
			  int cpu, int map_key)
{
  struct perf_cpu_buf *cpu_buf;
  char msg[STRERR_BUFSIZE];
  int err;

  cpu_buf = calloc(1, sizeof(*cpu_buf));
  if (!cpu_buf)
    return ERR_PTR(-ENOMEM);

  cpu_buf->pb = pb;
  cpu_buf->cpu = cpu;
  cpu_buf->map_key = map_key;

  uid_up ();
  cpu_buf->fd = syscall(__NR_perf_event_open, attr, -1 /* pid */, cpu,
                        -1, PERF_FLAG_FD_CLOEXEC);
  uid_down ();
  if (cpu_buf->fd < 0) {
    err = -errno;
    fprintf(stderr,"failed to open perf buffer event on cpu #%d: %s\n",
            cpu, libbpf_strerror_r(err, msg, sizeof(msg)));
    goto error;
  }

  cpu_buf->base = mmap(NULL, pb->mmap_size + pb->page_size,
                       PROT_READ | PROT_WRITE, MAP_SHARED,
                       cpu_buf->fd, 0);
  if (cpu_buf->base == MAP_FAILED) {
    cpu_buf->base = NULL;
    err = -errno;
    fprintf(stderr,"failed to mmap perf buffer on cpu #%d: %s\n",
            cpu, libbpf_strerror_r(err, msg, sizeof(msg)));
    goto error;
  }

  if (ioctl(cpu_buf->fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    err = -errno;
    fprintf(stderr,"failed to enable perf buffer event on cpu #%d: %s\n",
            cpu, libbpf_strerror_r(err, msg, sizeof(msg)));
    goto error;
  }

  return cpu_buf;

 error:
  perf_buffer__free_cpu_buf(pb, cpu_buf);
  return (struct perf_cpu_buf *)ERR_PTR(err);
}

static struct perf_buffer *__perf_buffer__new(int map_fd, size_t page_cnt,
					      struct perf_buffer_params *p);

struct perf_buffer *perf_buffer_create(int map_fd, size_t page_cnt,
                                       const struct perf_buffer_opts *opts)
{
  struct perf_buffer_params p = {};
  struct perf_event_attr attr = { 0, };

  attr.config = PERF_COUNT_SW_BPF_OUTPUT,
    attr.type = PERF_TYPE_SOFTWARE;
  attr.sample_type = PERF_SAMPLE_RAW;
  attr.sample_period = 1;
  attr.wakeup_events = 1;

  p.attr = &attr;
  p.sample_cb = opts ? opts->sample_cb : NULL;
  p.lost_cb = opts ? opts->lost_cb : NULL;
  p.ctx = opts ? opts->ctx : NULL;

  struct perf_buffer *result = __perf_buffer__new(map_fd, page_cnt, &p);
  if(IS_ERR(result)) return NULL;
  return result;
}

struct perf_buffer *
perf_buffer__new_raw(int map_fd, size_t page_cnt,
		     const struct perf_buffer_raw_opts *opts)
{
  struct perf_buffer_params p = {};

  p.attr = opts->attr;
  p.event_cb = opts->event_cb;
  p.ctx = opts->ctx;
  p.cpu_cnt = opts->cpu_cnt;
  p.cpus = opts->cpus;
  p.map_keys = opts->map_keys;

  return __perf_buffer__new(map_fd, page_cnt, &p);
}

static struct perf_buffer *__perf_buffer__new(int map_fd, size_t page_cnt,
					      struct perf_buffer_params *p)
{
  struct bpf_map_info map = {};
  char msg[STRERR_BUFSIZE];
  struct perf_buffer *pb;
  __u32 map_info_len;
  int err, i;

  if (page_cnt & (page_cnt - 1)) {
    fprintf(stderr,"page count should be power of two, but is %zu\n",
            page_cnt);
    return ERR_PTR(-EINVAL);
  }

  map_info_len = sizeof(map);
  err = bpf_obj_get_info_by_fd(map_fd, &map, &map_info_len);
  if (err) {
    err = -errno;
    fprintf(stderr,"failed to get map info for map FD %d: %s\n",
            map_fd, libbpf_strerror_r(err, msg, sizeof(msg)));
    return ERR_PTR(err);
  }

  if (map.type != BPF_MAP_TYPE_PERF_EVENT_ARRAY) {
    fprintf(stderr,"map '%s' should be BPF_MAP_TYPE_PERF_EVENT_ARRAY\n",
            map.name);
    return ERR_PTR(-EINVAL);
  }

  pb = calloc(1, sizeof(*pb));
  if (!pb)
    return ERR_PTR(-ENOMEM);

  pb->event_cb = p->event_cb;
  pb->sample_cb = p->sample_cb;
  pb->lost_cb = p->lost_cb;
  pb->ctx = p->ctx;

  pb->page_size = getpagesize();
  pb->mmap_size = pb->page_size * page_cnt;
  pb->map_fd = map_fd;

  pb->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (pb->epoll_fd < 0) {
    err = -errno;
    fprintf(stderr,"failed to create epoll instance: %s\n",
            libbpf_strerror_r(err, msg, sizeof(msg)));
    goto error;
  }

  if (p->cpu_cnt > 0) {
    pb->cpu_cnt = p->cpu_cnt;
  } else {
    pb->cpu_cnt = libbpf_num_possible_cpus();
    if (pb->cpu_cnt < 0) {
      err = pb->cpu_cnt;
      goto error;
    }
    if (map.max_entries < pb->cpu_cnt)
      pb->cpu_cnt = map.max_entries;
  }

  pb->events = calloc(pb->cpu_cnt, sizeof(*pb->events));
  if (!pb->events) {
    err = -ENOMEM;
    fprintf(stderr,"failed to allocate events: out of memory\n");
    goto error;
  }
  pb->cpu_bufs = calloc(pb->cpu_cnt, sizeof(*pb->cpu_bufs));
  if (!pb->cpu_bufs) {
    err = -ENOMEM;
    fprintf(stderr,"failed to allocate buffers: out of memory\n");
    goto error;
  }

  for (i = 0; i < pb->cpu_cnt; i++) {
    struct perf_cpu_buf *cpu_buf;
    int cpu, map_key;

    cpu = p->cpu_cnt > 0 ? p->cpus[i] : i;
    map_key = p->cpu_cnt > 0 ? p->map_keys[i] : i;

    cpu_buf = perf_buffer__open_cpu_buf(pb, p->attr, cpu, map_key);
    if (IS_ERR(cpu_buf)) {
      err = PTR_ERR(cpu_buf);
      goto error;
    }

    pb->cpu_bufs[i] = cpu_buf;

    err = bpf_map_update_elem(pb->map_fd, &map_key,
                              &cpu_buf->fd, 0);
    if (err) {
      err = -errno;
      fprintf(stderr,"failed to set cpu #%d, key %d -> perf FD %d: %s\n",
              cpu, map_key, cpu_buf->fd,
              libbpf_strerror_r(err, msg, sizeof(msg)));
      goto error;
    }

    pb->events[i].events = EPOLLIN;
    pb->events[i].data.ptr = cpu_buf;
    if (epoll_ctl(pb->epoll_fd, EPOLL_CTL_ADD, cpu_buf->fd,
                  &pb->events[i]) < 0) {
      err = -errno;
      fprintf(stderr,"failed to epoll_ctl cpu #%d perf FD %d: %s\n",
              cpu, cpu_buf->fd,
              libbpf_strerror_r(err, msg, sizeof(msg)));
      goto error;
    }
  }

  return pb;

 error:
  if (pb)
    perf_buffer_free(pb);
  return ERR_PTR(err);
}

struct perf_sample_raw {
  struct perf_event_header header;
  uint32_t size;
  char data[0];
};

struct perf_sample_lost {
  struct perf_event_header header;
  uint64_t id;
  uint64_t lost;
  uint64_t sample_id;
};

static enum bpf_perf_event_ret
perf_buffer__process_record(struct perf_event_header *e, void *ctx)
{
  struct perf_cpu_buf *cpu_buf = ctx;
  struct perf_buffer *pb = cpu_buf->pb;
  void *data = e;

  /* user wants full control over parsing perf event */
  if (pb->event_cb)
    return pb->event_cb(pb->ctx, cpu_buf->cpu, e);

  switch (e->type) {
  case PERF_RECORD_SAMPLE: {
    struct perf_sample_raw *s = data;

    if (pb->sample_cb)
      pb->sample_cb(pb->ctx, cpu_buf->cpu, s->data, s->size);
    break;
  }
  case PERF_RECORD_LOST: {
    struct perf_sample_lost *s = data;

    if (pb->lost_cb)
      pb->lost_cb(pb->ctx, cpu_buf->cpu, s->lost);
    break;
  }
  default:
    fprintf(stderr,"unknown perf sample type %d\n", e->type);
    return LIBBPF_PERF_EVENT_ERROR;
  }
  return LIBBPF_PERF_EVENT_CONT;
}

static int perf_buffer__process_records(struct perf_buffer *pb,
					struct perf_cpu_buf *cpu_buf)
{
  enum bpf_perf_event_ret ret;

  ret = bpf_perf_event_read_simple(cpu_buf->base, pb->mmap_size,
                                   pb->page_size, &cpu_buf->buf,
                                   &cpu_buf->buf_size,
                                   perf_buffer__process_record, cpu_buf);
  if (ret != LIBBPF_PERF_EVENT_CONT)
    return ret;
  return 0;
}

int perf_buffer_poll(struct perf_buffer *pb, int timeout_ms)
{
  int i, cnt, err;

  cnt = epoll_wait(pb->epoll_fd, pb->events, pb->cpu_cnt, timeout_ms);
  for (i = 0; i < cnt; i++) {
    struct perf_cpu_buf *cpu_buf = pb->events[i].data.ptr;

    err = perf_buffer__process_records(pb, cpu_buf);
    if (err) {
      fprintf(stderr,"error while processing records: %d\n", err);
      return err;
    }
  }
  return cnt < 0 ? -errno : cnt;
}

int libbpf_num_possible_cpus(void)
{
  return 1; // because of offline CPU issue above
  static const char *fcpu = "/sys/devices/system/cpu/possible";
  int len = 0, n = 0, il = 0, ir = 0;
  unsigned int start = 0, end = 0;
  int tmp_cpus = 0;
  static int cpus;
  char buf[128];
  int error = 0;
  int fd = -1;

  tmp_cpus = cpus;// READ_ONCE
  if (tmp_cpus > 0)
    return tmp_cpus;

  fd = open(fcpu, O_RDONLY);
  if (fd < 0) {
    error = errno;
    fprintf(stderr,"Failed to open file %s: %s\n", fcpu, strerror(error));
    return -error;
  }
  len = read(fd, buf, sizeof(buf));
  close(fd);
  if (len <= 0) {
    error = len ? errno : EINVAL;
    fprintf(stderr,"Failed to read # of possible cpus from %s: %s\n",
            fcpu, strerror(error));
    return -error;
  }
  if (len == sizeof(buf)) {
    fprintf(stderr,"File %s size overflow\n", fcpu);
    return -EOVERFLOW;
  }
  buf[len] = '\0';

  for (ir = 0, tmp_cpus = 0; ir <= len; ir++) {
    /* Each sub string separated by ',' has format \d+-\d+ or \d+ */
    if (buf[ir] == ',' || buf[ir] == '\0') {
      buf[ir] = '\0';
      n = sscanf(&buf[il], "%u-%u", &start, &end);
      if (n <= 0) {
        fprintf(stderr,"Failed to get # CPUs from %s\n",
                &buf[il]);
        return -EINVAL;
      } else if (n == 1) {
        end = start;
      }
      tmp_cpus += end - start + 1;
      il = ir + 1;
    }
  }
  if (tmp_cpus <= 0) {
    fprintf(stderr,"Invalid #CPUs %d from %s\n", tmp_cpus, fcpu);
    return -EINVAL;
  }

  cpus = tmp_cpus; //WRITE_ONCE
  return tmp_cpus;
}
