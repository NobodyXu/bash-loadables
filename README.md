# bash-loadables

An extension to bash's builtin, providing more functionalities and potentially better performance.

## How to build this project

```
git clone --recurse-submodules https://github.com/NobodyXu/bash-loadables
cd bash-loadabes/

# Make sure you have clang installed before running make
make all -j $(nproc)
```

## How to load builtin from a loadable

```bash
#!/bin/bash

# To load builtins
enable -f /path/to/loadable builtin_name ...

# Load all builtins from a loadable
enable -f /path/to/loadable loadable_name
loadable_name
```

## Get usage/help of builtin

After a builtin is enabled, type `help builtin` to get detailed help.

## builtins provided by loadables

### `os_basic`

 - `create_memfd: usage: create_memfd [-C] VAR`
 - `create_tmpfile: usage: create_tmpfile [-CE] VAR /path/to/dir rw/w [mode]`
 - `lseek: usage: lseek <int> fd <off64_t> offset SEEK_SET/SEEK_CUR/SEEK_END`
 - `fexecve: usage: fexecve <int> fd program_name [args...]`
 - `flink: usage: flink <int> fd path`
 - `fchmod: usage: flink <int> fd mode`
 - `fchown: usage: fchown <int> fd uid/username:gid/groupname`
 - `getresuid: usage: getresuid var1 var2 var3`
 - `getresgid: usage: getresgid var1 var2 var3`
 - `setresuid: usage: setresuid var1 var2 var3`
 - `setresgid: usage: getresgid var1 var2 var3`
 - `has_supplementary_group_member: usage: has_supplementary_group_member group/gid`
 - `get_supplementary_groups: usage: get_supplementary_groups varname`
 - `set_supplementary_groups: set_supplementary_groups [gid/group ...]`
 - `create_unixsocketpair: usage: create_unixsocketpair stream/dgram var1 var2`
 - `fdputs: usage: fdputs <int> fd msg`
 - `fdecho: usage: fdecho <int> fd msgs ...`
 - `sendfds: usage: sendfds [-N] <int> fd_of_unix_socket fd1 [fds...]`
 - `recvfds: usage: recvfds [-C] <int> fd_of_unix_socket nfd var`
 - `pause`
 - `sleep: usage: sleep [-R] seconds nanoseconds`
 - `create_socket: usage: create_socket [-NC] domain type <int> protocol var`
 - `bind: usage: bind <int> socketfd domain socketaddr`
 - `listen: usage: listen <int> socketfd <int> backlog`
 - `accept: usage: accept [-NC] <int> socketfd var`
 - `connect: usage: bind <int> socketfd domain socketaddr`
 - `clone: clone [-FPVS] [var]`
 - `unshare: unshare [-FS]`
 - `os_basic`

### `sandboxing`

 - `enable_no_new_privs_strict: enable_no_new_privs_strict`
 - `clone_ns: clone_ns [-VCINMPuU] [var]`
 - `unshare_ns: unshare_ns [-CINMPuU]`
 - `chroot: chroot path`
 - `setns: setns [-CINMPuU] <int> fd`

### `common_commands`

 - `realpath: realpath path [var]`
 - `common_commands`
