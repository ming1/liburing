/* SPDX-License-Identifier: LGPL-2.0-or-later */
/*
 * Description: test that pathname resolution works from async context when
 * using /proc/self/ which should be the original submitting task, not the
 * async worker.
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>

#include "liburing.h"
#include "helpers.h"

#ifndef IORING_FEAT_BPF
#define IORING_FEAT_BPF			(1U << 16)
#endif

#ifndef IORING_SETUP_BPF
#define IORING_SETUP_BPF		(1U << 17)
#endif

#ifndef IORING_BPF_OP_SHIFT
#define IORING_BPF_OP_SHIFT		24
#endif

const unsigned char uring_bpf_op = IORING_OP_LISTEN + 1;

static void io_uring_bpf_set_op_flags(struct io_uring_sqe *sqe,
		unsigned char op, unsigned flags)
{
	assert(!(flags & (0xff << IORING_BPF_OP_SHIFT)));

	sqe->rw_flags = (op << IORING_BPF_OP_SHIFT) | flags;
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
	io_uring_prep_rw(uring_bpf_op, sqe, 0, NULL, 0, 0);
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
	};

	if (argc > 1)
		return 0;

	memset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_BPF;
	ret = io_uring_queue_init_params(8, &ring, &p);
	if (ret) {
		fprintf(stderr, "ring setup failed ret %d\n", ret);
		return 1;
	}

	if (!(p.features & IORING_FEAT_BPF))
		return T_EXIT_SKIP;

	for (i = 0; i < sizeof(exp_ok) / sizeof(exp_ok[0]); i++) {
		ret = io_bpf_simple(&ring, i, exp_ok[i]);
		if (ret == T_EXIT_FAIL)
			goto exit;
	}

exit:
	return ret;
}
