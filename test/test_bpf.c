/* SPDX-License-Identifier: LGPL-2.0-or-later */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>

#include "liburing.h"
#include "helpers.h"

static void io_uring_bpf_set_op_flags(struct io_uring_sqe *sqe,
		unsigned char op, unsigned flags)
{
	assert(!(flags & (0xff << IORING_BPF_OP_SHIFT)));

	sqe->rw_flags = IORING_BPF_OP_FLAGS(op, IORING_BPF_BUF_TYPE_NONE,
			IORING_BPF_BUF_TYPE_NONE, flags);
}

static void io_uring_bpf_set_buf_op_flags(struct io_uring_sqe *sqe,
		unsigned char op, unsigned char buf1_type, unsigned char buf2_type,
		void *buf1_addr, unsigned buf1_len,
		void *buf2_addr, unsigned buf2_len, unsigned flags)
{
	assert(!(flags & (0xff << IORING_BPF_OP_SHIFT)));

	sqe->rw_flags = IORING_BPF_OP_FLAGS(op, buf1_type, buf2_type, flags);
	sqe->addr = (unsigned long)buf1_addr;
	sqe->len = buf1_len;
	sqe->addr3 = (unsigned long)buf2_addr;
	sqe->optlen = buf2_len;
}

static int io_bpf_simple(struct io_uring *ring, unsigned char op, bool ok)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret = -ENOMEM;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "get sqe failed\n");
		goto err;
	}
	io_uring_prep_rw(IORING_OP_BPF, sqe, 0, NULL, 0, 0);
	io_uring_bpf_set_op_flags(sqe, op, 0);
	sqe->user_data = op;
	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		goto err;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait completion %d\n", ret);
		goto err;
	}
	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);

	if (ok)
		return ret == 0 ? T_EXIT_PASS : T_EXIT_FAIL;
	else
		return ret < 0 ? T_EXIT_PASS : T_EXIT_FAIL;
err:
	return ret;
}

static int io_bpf_memcpy(struct io_uring *ring, unsigned char op,
			 unsigned char buf1_type, unsigned char buf2_type,
			 void *buf1, void *buf2, unsigned buf_len, bool async)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret = -ENOMEM;
	int i;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "get sqe failed\n");
		goto err;
	}
	io_uring_prep_rw(IORING_OP_BPF, sqe, 0, NULL, 0, 0);
	io_uring_bpf_set_buf_op_flags(sqe, op, buf1_type, buf2_type,
			buf1, buf_len, buf2, buf_len, 0);

	/* For fixed buffer, set buf_index */
	if (buf1_type == IORING_BPF_BUF_TYPE_FIXED)
		sqe->buf_index = 0;  /* Use first registered buffer */

	/* Set IOSQE_ASYNC flag for async mode */
	if (async)
		sqe->flags |= IOSQE_ASYNC;

	sqe->user_data = op;
	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		goto err;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait completion %d\n", ret);
		goto err;
	}
	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);

	/* Check if the operation succeeded */
	if (ret < 0) {
		fprintf(stderr, "bpf memcpy failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	/* Verify that buffer 2 has the same content as buffer 1 */
	for (i = 0; i < buf_len; i++) {
		if (((unsigned char *)buf2)[i] != ((unsigned char *)buf1)[i]) {
			fprintf(stderr, "memcpy verification failed at offset %d: expected 0x%02x, got 0x%02x\n",
				i, ((unsigned char *)buf1)[i], ((unsigned char *)buf2)[i]);
			return T_EXIT_FAIL;
		}
	}

	return T_EXIT_PASS;
err:
	return ret;
}

static int test_memcpy(struct io_uring *ring, bool async)
{
	unsigned char buf1[2048], buf2[2048];
	struct iovec iov;
	int ret;

	/* Register fixed buffer */
	memset(buf1, 0xaa, sizeof(buf1));
	iov.iov_base = buf1;
	iov.iov_len = sizeof(buf1);
	ret = io_uring_register_buffers(ring, &iov, 1);
	if (ret) {
		fprintf(stderr, "buffer registration failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	/* Test plain-to-plain memcpy operation (op 5) */
	memset(buf1, 0xaa, sizeof(buf1));
	memset(buf2, 0, sizeof(buf2));
	ret = io_bpf_memcpy(ring, 5, IORING_BPF_BUF_TYPE_PLAIN,
			    IORING_BPF_BUF_TYPE_PLAIN, buf1, buf2, sizeof(buf1), async);
	if (ret != T_EXIT_PASS) {
		fprintf(stderr, "bpf plain-to-plain memcpy test failed ret %d\n", ret);
		ret = T_EXIT_FAIL;
		goto cleanup;
	}

	/* Test fixed-to-plain memcpy operation (op 5) */
	memset(buf1, 0xaa, sizeof(buf1));
	memset(buf2, 0, sizeof(buf2));
	ret = io_bpf_memcpy(ring, 5, IORING_BPF_BUF_TYPE_FIXED,
			    IORING_BPF_BUF_TYPE_PLAIN, buf1, buf2, sizeof(buf1), async);
	if (ret != T_EXIT_PASS) {
		fprintf(stderr, "bpf fixed-to-plain memcpy test failed ret %d\n", ret);
		ret = T_EXIT_FAIL;
		goto cleanup;
	}

	/* Test plain-to-fixed memcpy operation (op 6)
	 * Op 6 copies from buffer 2 to buffer 1
	 */
	memset(buf1, 0, sizeof(buf1));
	memset(buf2, 0xaa, sizeof(buf2));
	ret = io_bpf_memcpy(ring, 6, IORING_BPF_BUF_TYPE_FIXED,
			    IORING_BPF_BUF_TYPE_PLAIN, buf1, buf2, sizeof(buf1), async);
	if (ret != T_EXIT_PASS) {
		fprintf(stderr, "bpf plain-to-fixed memcpy test failed ret %d\n", ret);
		ret = T_EXIT_FAIL;
		goto cleanup;
	}

	ret = T_EXIT_PASS;

cleanup:
	/* Unregister buffers so test_memcpy can be called multiple times */
	io_uring_unregister_buffers(ring);
	return ret;
}

int main(int argc, char *argv[])
{
	struct io_uring_params p;
	struct io_uring ring;
	int ret, i;
	bool exp_ok[] = {
		true,
		false,
		true,
		true,
		true,
	};

	if (argc > 1)
		return 0;

	memset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_BPF;
	ret = io_uring_queue_init_params(8, &ring, &p);
	if (ret) {
		fprintf(stderr, "ring setup failed ret %d\n", ret);
		goto exit;
	}

	if (!(p.features & IORING_FEAT_BPF))
		return T_EXIT_SKIP;

	for (i = 0; i < sizeof(exp_ok) / sizeof(exp_ok[0]); i++) {
		ret = io_bpf_simple(&ring, i, exp_ok[i]);
		if (ret == T_EXIT_FAIL) {
			fprintf(stderr, "bpf test %d failed ret %d\n", i, ret);
			goto exit;
		}
	}

	/* Test memcpy in sync mode */
	ret = test_memcpy(&ring, false);
	if (ret != T_EXIT_PASS) {
		fprintf(stderr, "bpf memcpy tests (sync) failed\n");
		goto exit;
	}

	/* Test memcpy in async mode */
	ret = test_memcpy(&ring, true);
	if (ret != T_EXIT_PASS) {
		fprintf(stderr, "bpf memcpy tests (async) failed\n");
		goto exit;
	}

exit:
	return ret;
}
