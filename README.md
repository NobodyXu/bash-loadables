# bash-loadables

An extension to bash's builtin, providing more functionalities and potentially better performance.

## How to build this project

### Requirements
 - Clang: `sudo apt install clang`
 - LLD: `sudo apt install lld`
 - cap-ng.h: `sudo apt install libcap-ng-dev`
 - seccomp.h: `sudo apt install libseccomp-dev`

```
# Clone this repo
git clone --recurse-submodules https://github.com/NobodyXu/bash-loadables
cd bash-loadables

# Build the bash submodule
cd bash
./configure
make

# Build this project
cd ..
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

 - `create_memfd [-C] VAR`
 - `create_tmpfile [-CE] VAR /path/to/dir rw/w [mode]`
 - `lseek <int> fd <off64_t> offset SEEK_SET/SEEK_CUR/SEEK_END`
 - `fexecve <int> fd program_name [args...]`
 - `flink <int> fd path`
 - `flink <int> fd mode`
 - `fchown <int> fd uid/username:gid/groupname`
 - `getresuid var1 var2 var3`
 - `getresgid var1 var2 var3`
 - `setresuid var1 var2 var3`
 - `getresgid var1 var2 var3`
 - `has_supplementary_group_member group/gid`
 - `get_supplementary_groups varname`
 - `set_supplementary_groups [gid/group ...]`
 - `create_unixsocketpair stream/dgram var1 var2`
 - `fdputs <int> fd msg`
 - `fdecho <int> fd msgs ...`
 - `sendfds [-N] <int> fd_of_unix_socket fd1 [fds...]`
 - `recvfds [-C] <int> fd_of_unix_socket nfd var`
 - `pause`
 - `sleep [-R] seconds nanoseconds`
 - `create_socket [-NC] domain type <int> protocol var`
 - `bind <int> socketfd domain socketaddr`
 - `listen <int> socketfd <int> backlog`
 - `accept [-NC] <int> socketfd var`
 - `bind <int> socketfd domain socketaddr`
 - `clone [-FPVS] [var]`
 - `unshare [-FS]`
 - `os_basic`

### `sandboxing`

 - `enable_no_new_privs_strict`
 - `clone_ns [-VCINMPuU] [var]`
 - `unshare_ns [-CINMPuU]`
 - `chroot path`
 - `setns [-CINMPuU] <int> fd`
 - `sandboxing`

### `common_commands`

 - `realpath path [var]`
 - `mkdir path [mode]`
 - `common_commands`
