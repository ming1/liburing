// SPDX-License-Identifier: LGPL-2.0-or-later

#include "vmlinux.h"
#include <linux/const.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

//#define DEBUG
#include "uring_bpf.h"

/* libbpf v1.4.5+ is required for struct_ops to work */

struct my_data {
	int a, b, c;
};

SEC("struct_ops/io_bpf_prep_io")
int BPF_PROG(uring_bpf_nop_prep, struct uring_bpf_data *data, const struct io_uring_sqe *sqe)
{
	return 0;
}

SEC("struct_ops/io_bpf_issue_io")
int BPF_PROG(uring_bpf_nop_issue, struct uring_bpf_data *data)
{
	return 0;
}

SEC(".struct_ops.link")
struct uring_bpf_ops nop_bpf_ops_0 = {
	.id = 0,
	.prep_fn = (void *)uring_bpf_nop_prep,
	.issue_fn = (void *)uring_bpf_nop_issue,
};

SEC("struct_ops/io_bpf_prep_io")
int BPF_PROG(uring_bpf_fail_prep, struct uring_bpf_data *data, const struct io_uring_sqe *sqe)
{
	return -EINVAL;
}

SEC(".struct_ops.link")
struct uring_bpf_ops fail_bpf_ops_1 = {
	.id = 1,
	.prep_fn = (void *)uring_bpf_fail_prep,
};


SEC("struct_ops/io_bpf_prep_io")
int BPF_PROG(uring_bpf_data_write_prep, struct uring_bpf_data *data, const struct io_uring_sqe *sqe)
{
	struct my_data *m = (struct my_data *)data->pdu;

	BPF_DBG("%s: op 0\n", __func__);

	m->a = 1;
	m->b = 2;
	m->c = 3;
	return 0;
}

SEC("struct_ops/io_bpf_issue_io")
int BPF_PROG(uring_bpf_data_write_issue, struct uring_bpf_data *data)
{
	const struct my_data *m = (struct my_data *)data->pdu;
	int ret = 0;

	if (m->a != 1 || m->b != 2 || m->c != 3)
		ret = -EIO;

	BPF_DBG("%s: op 0 return %d\n", __func__, ret);
	uring_bpf_set_result(data, ret);
	return 0;
}

SEC(".struct_ops.link")
struct uring_bpf_ops data_write_bpf_ops_2 = {
	.id = 2,
	.prep_fn = (void *)uring_bpf_data_write_prep,
	.issue_fn = (void *)uring_bpf_data_write_issue,
};

SEC("struct_ops/io_bpf_prep_io")
int BPF_PROG(uring_bpf_req_read_prep, struct uring_bpf_data *data, const struct io_uring_sqe *sqe)
{
	BPF_DBG("%s\n", __func__);
	return 0;
}

SEC("struct_ops/io_bpf_issue_io")
int BPF_PROG(uring_bpf_req_read_issue, struct uring_bpf_data *data)
{
	const struct my_data *m = (struct my_data *)data->pdu;
	const struct io_kiocb *req = uring_bpf_data_to_req(data);
	int ret = 0;

	/* bpf op is passed via user_data */
	if (req->cqe.user_data != 3)
		ret = -EIO;

	BPF_DBG("%s: return %d\n", __func__, ret);
	uring_bpf_set_result(data, ret);

	return 0;
}

SEC(".struct_ops.link")
struct uring_bpf_ops req_read_bpf_ops_3 = {
	.id = 3,
	.prep_fn = (void *)uring_bpf_req_read_prep,
	.issue_fn = (void *)uring_bpf_req_read_issue,
};

char LICENSE[] SEC("license") = "GPL";
