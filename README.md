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
enable -f /path/to/loadable enable_all
enable_all
```

## builtins provided by loadables

### `os_basic`

 - `create_memfd`
 - `create_tmpfile`
 - `lseek`
 - `fexecve`
 - `flink`
 - `fchmod`
 - `fchown`
 - `getresuid`
 - `getresgid`
 - `setresuid`
 - `setresgid`
 - `create_unixsocketpair`
 - `fdputs`
 - `sendfds`
 - `recvfds`
 - `enable_all`

