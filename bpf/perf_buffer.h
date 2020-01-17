struct perf_buffer;

typedef void (*perf_buffer_sample_fn)(void *ctx, int cpu,
                                      void *data, __u32 size);

typedef void (*perf_buffer_lost_fn)(void *ctx, int cpu, __u64 cnt);

struct perf_buffer_opts {
  /* if specified, sample_cb is called for each sample */
  perf_buffer_sample_fn sample_cb;
  /* if specified, lost_cb is called for each batch of lost samples */
  perf_buffer_lost_fn lost_cb;
  /* ctx is provided to sample_cb and lost_cb */
  void *ctx;
};

struct perf_buffer *perf_buffer_create(int map_fd, size_t page_cnt,
                                       const struct perf_buffer_opts *opts);

int perf_buffer_poll(struct perf_buffer *pb, int timeout_ms);


void perf_buffer_free(struct perf_buffer *pb);
