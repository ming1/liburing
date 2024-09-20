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

#endif
