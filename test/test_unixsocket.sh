#!/bin/bash -ex

prefix=$(realpath $(dirname "$0"))

source "${prefix}/assert.sh"

enable -f "${prefix}/../os_basic" enable_all
enable_all

create_unixsocketpair stream fd1 fd2

fdputs $fd1 'hello'
read -u $fd2 -n 5
assert '[ "$REPLY" = "hello" ]'

sendfds $fd1 $fd1 $fd2
recvfds $fd2 2 fds

fdputs ${fds[0]} 'hello'
read -u ${fds[1]} -n 5
assert '[ "$REPLY" = "hello" ]'
