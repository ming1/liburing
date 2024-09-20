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

/* Buffer for memory allocation */
struct alloc_buffer {
	int magic;
	int value;
	char data[64];
};

/* BPF map to store allocated buffers */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, struct alloc_buffer);
} memory_map SEC(".maps");

SEC("struct_ops/io_bpf_prep_io")
int BPF_PROG(uring_bpf_memory_alloc_prep, struct uring_bpf_data *data, const struct io_uring_sqe *sqe)
{
	struct io_kiocb *req = uring_bpf_data_to_req(data);
	struct alloc_buffer buf = {};
	__u64 key;
	int ret;

	BPF_DBG("%s: allocating memory\n", __func__);

	/* Use request address as key */
	key = (__u64)req;

	/* Initialize the buffer */
	buf.magic = 0xdeadbeef;
	buf.value = 42;
	__builtin_memset(buf.data, 'A', sizeof(buf.data));

	/* Store buffer in hash map */
	ret = bpf_map_update_elem(&memory_map, &key, &buf, BPF_ANY);
	if (ret < 0) {
		BPF_DBG("%s: failed to store buffer in map: %d\n", __func__, ret);
		return ret;
	}

	BPF_DBG("%s: memory allocated and stored\n", __func__);
	return 0;
}

SEC("struct_ops/io_bpf_issue_io")
int BPF_PROG(uring_bpf_memory_alloc_issue, struct uring_bpf_data *data)
{
	struct io_kiocb *req = uring_bpf_data_to_req(data);
	struct alloc_buffer *buf;
	__u64 key;
	int ret = 0;

	BPF_DBG("%s: retrieving memory from map\n", __func__);

	/* Use request address as key */
	key = (__u64)req;

	/* Retrieve buffer from hash map */
	buf = bpf_map_lookup_elem(&memory_map, &key);
	if (!buf) {
		BPF_DBG("%s: failed to retrieve buffer from map\n", __func__);
		ret = -ENOENT;
		goto out;
	}

	/* Verify the buffer contents */
	if (buf->magic != 0xdeadbeef || buf->value != 42) {
		BPF_DBG("%s: buffer validation failed (magic: 0x%x, value: %d)\n",
			__func__, buf->magic, buf->value);
		ret = -EIO;
		goto cleanup;
	}

	BPF_DBG("%s: buffer validated successfully\n", __func__);

cleanup:
	/* Clean up: remove entry from map */
	bpf_map_delete_elem(&memory_map, &key);

out:
	uring_bpf_set_result(data, ret);
	return 0;
}

SEC(".struct_ops.link")
struct uring_bpf_ops memory_alloc_bpf_ops_4 = {
	.id = 4,
	.prep_fn = (void *)uring_bpf_memory_alloc_prep,
	.issue_fn = (void *)uring_bpf_memory_alloc_issue,
};

char LICENSE[] SEC("license") = "GPL";
