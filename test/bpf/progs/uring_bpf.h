// SPDX-License-Identifier: LGPL-2.0-or-later

#ifndef UBLK_BPF_GEN_H
#define UBLK_BPF_GEN_H

#ifdef DEBUG
#define BPF_DBG(...) bpf_printk(__VA_ARGS__)
#else
#define BPF_DBG(...)
#endif

extern void uring_bpf_set_result(struct uring_bpf_data *data, int res) __ksym;
extern struct io_kiocb *uring_bpf_data_to_req(struct uring_bpf_data *data) __ksym;
extern int io_uring_bpf_req_memcpy(struct uring_bpf_data *data,
				   struct bpf_req_mem_desc *dest,
				   struct bpf_req_mem_desc *src,
				   unsigned int len) __ksym;

#endif
