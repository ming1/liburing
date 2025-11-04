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

/* Helper to perform a single memcpy with specified offset and length */
__always_inline static int __do_memcpy(struct uring_bpf_data *data,
					__u8 src_buf_id, __u8 dst_buf_id,
					unsigned offset, unsigned len)
{
	struct bpf_req_mem_desc src_desc = {};
	struct bpf_req_mem_desc dst_desc = {};
	int ret;

	/* Initialize buffer descriptors */
	src_desc.buf_id = src_buf_id;
	src_desc.offset = offset;
	dst_desc.buf_id = dst_buf_id;
	dst_desc.offset = offset;

	BPF_DBG("memcpy src_buf_id=%u dst_buf_id=%u offset=%u len=%u\n",
		src_desc.buf_id, dst_desc.buf_id, offset, len);

	/* Call the kfunc to perform the memcpy */
	ret = io_uring_bpf_req_memcpy(data, &dst_desc, &src_desc, len);

	BPF_DBG("memcpy returned %d\n", ret);

	return ret;
}

/* Common helper for memcpy operations - tests partial copies */
__always_inline static int do_memcpy(struct uring_bpf_data *data,
				     __u8 src_buf_id, __u8 dst_buf_id)
{
	unsigned total_len, first_len, remainder;
	int ret, total_ret = 0;

	/* Use the minimum of buf1_len and buf2_len */
	total_len = data->buf1_len;
	if (total_len > data->buf2_len)
		total_len = data->buf2_len;

	/* First copy: min(total_len, 512) bytes */
	first_len = total_len;
	if (first_len > 512)
		first_len = 512;

	/* Perform first copy */
	ret = __do_memcpy(data, src_buf_id, dst_buf_id, 0, first_len);
	if (ret < 0)
		return ret;

	total_ret = ret;

	/* Second copy: remainder if there is any */
	if (total_len > total_ret) {
		remainder = total_len - total_ret;

		/* Perform second copy with adjusted offset */
		ret = __do_memcpy(data, src_buf_id, dst_buf_id, total_ret, remainder);
		if (ret < 0)
			return ret;

		total_ret += ret;
	}

	BPF_DBG("memcpy total returned %d\n", total_ret);

	return total_ret;
}

SEC("struct_ops/io_bpf_prep_io")
int BPF_PROG(uring_bpf_memcpy_prep, struct uring_bpf_data *data, const struct io_uring_sqe *sqe)
{
	BPF_DBG("%s\n", __func__);
	return 0;
}

SEC("struct_ops/io_bpf_issue_io")
int BPF_PROG(uring_bpf_memcpy_issue, struct uring_bpf_data *data)
{
	int ret;

	/* Copy from buffer 1 to buffer 2 */
	ret = do_memcpy(data, 1, 2);
	uring_bpf_set_result(data, ret);
	return 0;
}

SEC(".struct_ops.link")
struct uring_bpf_ops memcpy_bpf_ops_5 = {
	.id = 5,
	.prep_fn = (void *)uring_bpf_memcpy_prep,
	.issue_fn = (void *)uring_bpf_memcpy_issue,
};

SEC("struct_ops/io_bpf_prep_io")
int BPF_PROG(uring_bpf_memcpy_reverse_prep, struct uring_bpf_data *data, const struct io_uring_sqe *sqe)
{
	BPF_DBG("%s\n", __func__);
	return 0;
}

SEC("struct_ops/io_bpf_issue_io")
int BPF_PROG(uring_bpf_memcpy_reverse_issue, struct uring_bpf_data *data)
{
	int ret;

	/* Copy from buffer 2 to buffer 1 */
	ret = do_memcpy(data, 2, 1);
	uring_bpf_set_result(data, ret);
	return 0;
}

SEC(".struct_ops.link")
struct uring_bpf_ops memcpy_reverse_bpf_ops_6 = {
	.id = 6,
	.prep_fn = (void *)uring_bpf_memcpy_reverse_prep,
	.issue_fn = (void *)uring_bpf_memcpy_reverse_issue,
};

char LICENSE[] SEC("license") = "GPL";
