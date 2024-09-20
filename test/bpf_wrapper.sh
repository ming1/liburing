#!/bin/bash

if ! which bpftool > /dev/null 2>&1; then
	exit 77
fi

CURDIR=$(cd "$(dirname "$0")";pwd)
PROG_PINF="__uring_ops_"$RANDOM
bpftool struct_ops register ${CURDIR}/bpf/simple.bpf.o /sys/fs/bpf/${PROG_PINF} > /dev/null 2>&1

${CURDIR}/bpf.t
RET=$?

#unpin & unregister
rm -fr /sys/fs/bpf/${PROG_PINF}

exit $RET
