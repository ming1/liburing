/*
 * Description: run various timeout tests
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/time.h>

#include "liburing.h"

#define TIMEOUT_MSEC	1000
static int not_supported;

static unsigned long long mtime_since(const struct timeval *s,
				      const struct timeval *e)
{
	long long sec, usec;

	sec = e->tv_sec - s->tv_sec;
	usec = (e->tv_usec - s->tv_usec);
	if (sec > 0 && usec < 0) {
		sec--;
		usec += 1000000;
	}

	sec *= 1000;
	usec /= 1000;
	return sec + usec;
}

static unsigned long long mtime_since_now(struct timeval *tv)
{
	struct timeval end;

	gettimeofday(&end, NULL);
	return mtime_since(tv, &end);
}

/*
 * Test that we return to userspace if a timeout triggers, even if we
 * don't satisfy the number of events asked for.
 */
static int test_single_timeout_many(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	unsigned long long exp;
	struct __kernel_timespec ts;
	struct timeval tv;
	int ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "%s: get sqe failed\n", __FUNCTION__);
		goto err;
	}

	ts.tv_sec = TIMEOUT_MSEC / 1000;
	ts.tv_nsec = 0;
	io_uring_prep_timeout(sqe, &ts, 0, 0);

	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "%s: sqe submit failed: %d\n", __FUNCTION__, ret);
		goto err;
	}

	gettimeofday(&tv, NULL);
	ret = io_uring_enter(ring->ring_fd, 0, 4, IORING_ENTER_GETEVENTS, NULL);
	if (ret < 0) {
		fprintf(stderr, "%s: io_uring_enter %d\n", __FUNCTION__, ret);
		goto err;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "%s: wait completion %d\n", __FUNCTION__, ret);
		goto err;
	}
	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	if (ret == -EINVAL) {
		fprintf(stdout, "Timeout not supported, ignored\n");
		not_supported = 1;
		return 0;
	} else if (ret != -ETIME) {
		fprintf(stderr, "Timeout: %s\n", strerror(-ret));
		goto err;
	}

	exp = mtime_since_now(&tv);
	if (exp >= TIMEOUT_MSEC / 2 && exp <= (TIMEOUT_MSEC * 3) / 2)
		return 0;
	fprintf(stderr, "%s: Timeout seems wonky (got %llu)\n", __FUNCTION__, exp);
err:
	return 1;
}

/*
 * Test numbered trigger of timeout
 */
static int test_single_timeout_nr(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct __kernel_timespec ts;
	int i, ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "%s: get sqe failed\n", __FUNCTION__);
		goto err;
	}

	ts.tv_sec = TIMEOUT_MSEC / 1000;
	ts.tv_nsec = 0;
	io_uring_prep_timeout(sqe, &ts, 2, 0);

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_nop(sqe);
	io_uring_sqe_set_data(sqe, (void *) 1);
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_nop(sqe);
	io_uring_sqe_set_data(sqe, (void *) 1);

	ret = io_uring_submit_and_wait(ring, 4);
	if (ret <= 0) {
		fprintf(stderr, "%s: sqe submit failed: %d\n", __FUNCTION__, ret);
		goto err;
	}

	i = 0;
	while (i < 3) {
		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "%s: wait completion %d\n", __FUNCTION__, ret);
			goto err;
		}

		/*
		 * NOP commands have user_data as 1. Check that we get the
		 * two NOPs first, then the successfully removed timout as
		 * the last one.
		 */
		switch (i) {
		case 0:
		case 1:
			if (io_uring_cqe_get_data(cqe) != (void *) 1) {
				fprintf(stderr, "%s: nop not seen as 1 or 2\n", __FUNCTION__);
				goto err;
			}
			break;
		case 2:
			if (io_uring_cqe_get_data(cqe) != NULL) {
				fprintf(stderr, "%s: timeout not last\n", __FUNCTION__);
				goto err;
			}
			break;
		}

		ret = cqe->res;
		io_uring_cqe_seen(ring, cqe);
		if (ret < 0) {
			fprintf(stderr, "Timeout: %s\n", strerror(-ret));
			goto err;
		} else if (ret) {
			fprintf(stderr, "res: %d\n", ret);
			goto err;
		}
		i++;
	};

	return 0;
err:
	return 1;
}

static int test_single_timeout_wait(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct __kernel_timespec ts;
	int i, ret;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_nop(sqe);
	io_uring_sqe_set_data(sqe, (void *) 1);

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_nop(sqe);
	io_uring_sqe_set_data(sqe, (void *) 1);

	ts.tv_sec = 1;
	ts.tv_nsec = 0;

	i = 0;
	do {
		ret = io_uring_wait_cqes(ring, &cqe, 2, &ts, NULL);
		if (ret == -ETIME)
			break;
		if (ret < 0) {
			fprintf(stderr, "%s: wait timeout failed: %d\n", __FUNCTION__, ret);
			goto err;
		}

		ret = cqe->res;
		io_uring_cqe_seen(ring, cqe);
		if (ret < 0) {
			fprintf(stderr, "res: %d\n", ret);
			goto err;
		}
		i++;
	} while (1);

	if (i != 2) {
		fprintf(stderr, "got %d completions\n", i);
		goto err;
	}
	return 0;
err:
	return 1;
}

/*
 * Test single timeout waking us up
 */
static int test_single_timeout(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	unsigned long long exp;
	struct __kernel_timespec ts;
	struct timeval tv;
	int ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "%s: get sqe failed\n", __FUNCTION__);
		goto err;
	}

	ts.tv_sec = TIMEOUT_MSEC / 1000;
	ts.tv_nsec = 0;
	io_uring_prep_timeout(sqe, &ts, 0, 0);

	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "%s: sqe submit failed: %d\n", __FUNCTION__, ret);
		goto err;
	}

	gettimeofday(&tv, NULL);
	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "%s: wait completion %d\n", __FUNCTION__, ret);
		goto err;
	}
	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	if (ret == -EINVAL) {
		fprintf(stdout, "%s: Timeout not supported, ignored\n", __FUNCTION__);
		not_supported = 1;
		return 0;
	} else if (ret != -ETIME) {
		fprintf(stderr, "%s: Timeout: %s\n", __FUNCTION__, strerror(-ret));
		goto err;
	}

	exp = mtime_since_now(&tv);
	if (exp >= TIMEOUT_MSEC / 2 && exp <= (TIMEOUT_MSEC * 3) / 2)
		return 0;
	fprintf(stderr, "%s: Timeout seems wonky (got %llu)\n", __FUNCTION__, exp);
err:
	return 1;
}

/*
 * Test single absolute timeout waking us up
 */
static int test_single_timeout_abs(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	unsigned long long exp;
	struct __kernel_timespec ts;
	struct timespec abs_ts;
	struct timeval tv;
	int ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "%s: get sqe failed\n", __FUNCTION__);
		goto err;
	}

	clock_gettime(CLOCK_MONOTONIC, &abs_ts);
	ts.tv_sec = abs_ts.tv_sec + 1;
	ts.tv_nsec = abs_ts.tv_nsec;
	io_uring_prep_timeout(sqe, &ts, 0, IORING_TIMEOUT_ABS);

	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "%s: sqe submit failed: %d\n", __FUNCTION__, ret);
		goto err;
	}

	gettimeofday(&tv, NULL);
	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "%s: wait completion %d\n", __FUNCTION__, ret);
		goto err;
	}
	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	if (ret == -EINVAL) {
		fprintf(stdout, "Absolute timeouts not supported, ignored\n");
		return 0;
	} else if (ret != -ETIME) {
		fprintf(stderr, "Timeout: %s\n", strerror(-ret));
		goto err;
	}

	exp = mtime_since_now(&tv);
	if (exp >= TIMEOUT_MSEC / 2 && exp <= (TIMEOUT_MSEC * 3) / 2)
		return 0;
	fprintf(stderr, "%s: Timeout seems wonky (got %llu)\n", __FUNCTION__, exp);
err:
	return 1;
}

/*
 * Test that timeout is canceled on exit
 */
static int test_single_timeout_exit(struct io_uring *ring)
{
	struct io_uring_sqe *sqe;
	struct __kernel_timespec ts;
	int ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "%s: get sqe failed\n", __FUNCTION__);
		goto err;
	}

	ts.tv_sec = 30;
	ts.tv_nsec = 0;
	io_uring_prep_timeout(sqe, &ts, 0, 0);

	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "%s: sqe submit failed: %d\n", __FUNCTION__, ret);
		goto err;
	}

	io_uring_queue_exit(ring);
	return 0;
err:
	io_uring_queue_exit(ring);
	return 1;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	int ret;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed\n");
		return 1;
	}

	ret = test_single_timeout(&ring);
	if (ret) {
		fprintf(stderr, "test_single_timeout failed\n");
		return ret;
	}
	if (not_supported)
		return 0;

	ret = test_single_timeout_abs(&ring);
	if (ret) {
		fprintf(stderr, "test_single_timeout_abs failed\n");
		return ret;
	}

	ret = test_single_timeout_many(&ring);
	if (ret) {
		fprintf(stderr, "test_single_timeout_many failed\n");
		return ret;
	}

	ret = test_single_timeout_nr(&ring);
	if (ret) {
		fprintf(stderr, "test_single_timeout_nr failed\n");
		return ret;
	}

	ret = test_single_timeout_wait(&ring);
	if (ret) {
		fprintf(stderr, "test_single_timeout_wait failed\n");
		return ret;
	}

	/*
	 * this test must go last, it kills the ring
	 */
	ret = test_single_timeout_exit(&ring);
	if (ret) {
		fprintf(stderr, "test_single_timeout_nr failed\n");
		return ret;
	}

	return 0;
}
