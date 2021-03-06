/* sandboxing - loadable builtin that helps user sandbox applications */

#define _BSD_SOURCE
#define _DEFAULT_SOURCE
#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L

#include "utilities.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>

#include <stdint.h>
#include <inttypes.h>
#include <setjmp.h>

#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include <linux/securebits.h>

#include <sched.h>

#include <errno.h>

#include <dlfcn.h>

#include <cap-ng.h>
#include <seccomp.h>

#if defined(__hppa__) || defined(__ia64__)
# define STACK_GROWS_DOWN 0
#else
# define STACK_GROWS_DOWN 1
#endif

#define STACK(addr, len) ((addr) + (len) * STACK_GROWS_DOWN)

static void *libcapng_handle;
static void *libseccomp_handle;

static scmp_filter_ctx seccomp_ctx;

void unload_dynlib_impl(void *handle, const char *handle_name)
{
    if (handle != NULL) {
        if (dlclose(handle) != 0)
            warnx("dlclose %s failed: %s", handle_name, dlerror());
    }
}
#define unload_dynlib(handle) unload_dynlib_impl((handle), # handle)

void* load_dynlib(const char *filename)
{
    void *handle = dlopen(filename, RTLD_LAZY | RTLD_LOCAL);
    if (handle == NULL)
        warnx("failed to load %s: %s", filename, dlerror());
    return handle;
}
void* load_sym_impl(void *handle, const char *symbol, const char *dyn_name)
{
    void *sym_addr = dlsym(handle, symbol);
    if (sym_addr == NULL)
        warnx("failed to load %s from %s: %s", symbol, dyn_name, dlerror());
    return sym_addr;
}
void* load_sym(void **handle, const char *dyn_name, const char *symbol)
{
    if (*handle == NULL) {
        if ((*handle = load_dynlib(dyn_name)) == NULL)
            return NULL;
    }
    return load_sym_impl(*handle, symbol, dyn_name);
}

/**
 * Called when `sandboxing' is enabled and loaded from the shared object.
 *
 * If this function returns 0, the load fails.
 */
PUBLIC int sandboxing_builtin_load(char *name)
{
    libcapng_handle = NULL;
    libseccomp_handle = NULL;
    seccomp_ctx = NULL;
    return (1);
}

int call_seccomp_release(scmp_filter_ctx ctx);
/**
 * Called when `template' is disabled.
 */
PUBLIC void sandboxing_builtin_unload(char *name)
{
    unload_dynlib(libcapng_handle);
    if (seccomp_ctx != NULL) {
        if (libseccomp_handle != NULL)
            call_seccomp_release(seccomp_ctx);
        else
            warnx("sandboxing_builtin_unload: seccomp_ctx != NULL but %s == NULL", "libseccomp_handle");
    }
    unload_dynlib(libseccomp_handle);
}

int enable_no_new_privs_strict_builtin(WORD_LIST *list)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    if (list != NULL) {
        builtin_usage();
        return (EX_USAGE);
    }

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin enable_no_new_privs_strict_struct = {
    "enable_no_new_privs_strict",             /* builtin name */
    enable_no_new_privs_strict_builtin,       /* function implementing the builtin */
    BUILTIN_ENABLED,        /* initial flags for builtin */
    (char*[]){
        "After this function call, no new privileges is allowed for this process and its child process.",
        "It is also preserved accross execve and cannot be unset.",
        (char *)NULL
    },                      /* array of long documentation strings. */
    "enable_no_new_privs_strict",             /* usage synopsis; becomes short_doc */
    0                       /* reserved for internal use */
};

int set_securebits_builtin(WORD_LIST *list)
{
    int locked = PARSE_FLAG(&list, "L", -1);

    unsigned long flags = 0;
    for (int i = 1; list != NULL; list = list->next, ++i) {
        if (strcasecmp(list->word->word, "KEEP_CAPS") == 0)
            flags |= SECBIT_KEEP_CAPS | (locked & SECBIT_KEEP_CAPS_LOCKED);
        else if (strcasecmp(list->word->word, "NO_SETUID_FIXUP") == 0)
            flags |= SECBIT_NO_SETUID_FIXUP | (locked & SECBIT_NO_SETUID_FIXUP_LOCKED);
        else if (strcasecmp(list->word->word, "NOROOT") == 0)
            flags |= SECBIT_NOROOT | (locked & SECBIT_NOROOT_LOCKED);
        else if (strcasecmp(list->word->word, "NO_CAP_AMBIENT_RAISE") == 0)
            flags |= SECBIT_NO_CAP_AMBIENT_RAISE | (locked & SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED);
        else {
            warnx("Invalid argv[%d]", i);
            return (EX_USAGE);
        }
    }

    if (prctl(PR_SET_SECUREBITS, flags, 0, 0, 0) == -1) {
        warn("set_securebits: prctl failed");
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin set_securebits_struct = {
    "set_securebits",             /* builtin name */
    set_securebits_builtin,       /* function implementing the builtin */
    BUILTIN_ENABLED,        /* initial flags for builtin */
    (char*[]){
        "set_securebits set secure bits specified as arguments (which is case insensitive).",
        "",
        "If '-L' is passed, then the specified secure bits are also locked.",
        "",
        "Example usage: set_securebits -L KEEP_CAPS NO_SETUID_FIXUP NOROOT NO_CAP_AMBIENT_RAISE",
        "",
        "For more detail on secure bits, check man capabilities(7).",
        (char *)NULL
    },                      /* array of long documentation strings. */
    "set_securebits [-L] [KEEP_CAPS/NO_SETUID_FIXUP/NOROOT/NO_CAP_AMBIENT_RAISE]...",
    0                       /* reserved for internal use */
};

int clone_ns_fn(void *arg)
{
    longjmp(*((jmp_buf*) arg), 1);
}
int clone_ns_builtin(WORD_LIST *list)
{
    int flags = PARSE_FLAG(&list, "VPCINMpuU", CLONE_VFORK, CLONE_PARENT, CLONE_NEWCGROUP, CLONE_NEWIPC, \
                                               CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, \
                                               CLONE_NEWUTS);

    const char *varname = NULL;
    if (to_argv_opt(list, 0, 1, &varname) == -1)
        return (EX_USAGE);

    int pid;
    jmp_buf env;
    if (setjmp(env) == 0) {
        {
            // Since stack is grown from higher to low, this wouldn't cause undetected stack overflow
            // that overwrites heap.
            char stack[8064];
            pid = clone(clone_ns_fn, STACK(stack, sizeof(stack)), flags | SIGCHLD, &env);
        }

        if (pid == -1) {
            warn("clone failed");
            return (EXECUTION_FAILURE);
        }
    } else
        pid = 0;

    if (varname)
        bind_var_to_int((char*) varname, pid);

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin clone_ns_struct = {
    "clone_ns",       /* builtin name */
    clone_ns_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "clone_ns creates a new process possibly in a new namespace",
        "",
        "If var is present, then the pid is writen to it in parent process, and",
        "0 is writen to it in the child process.",
        "",
        "If '-V' is passed, this process is suspended until the child process calls execve or _exit.",
        "If '-P' is passed, the child process shares the same parent as this process.",
        "    NOTE that the init process in the PID namespace cannot use this funtionality.",
        "If '-C' is passed, child process is put in a new cgroup.",
        "If '-I' is passed, child process is put in a new IPC namespace.",
        "If '-N' is passed, child process is put in a new network namespace.",
        "If '-M' is passed, child process is put in a new mount namespace.",
        "If '-p' is passed, child process is put in a new PID namespace.",
        "If '-u' is passed, child process is put in a new user namespace.",
        "If '-U' is passed, child process is put in a new UTS namespace.",
        "",
        "All namespaces except for user namespace requires CAP_SYSADMIN in the current user namespace.",
        "",
        "To create namespaces without privilege, you need to create user namespace along with the",
        "actual namespace you want.",
        "",
        "NOTE that in order to create a user namespace, the euid and egid of the process",
        "must be mapped in the parent user namespace AND the process mustn't in chroot env.",
        "",
        "After user namespace is created, you would need to set uid_map, setgroups and gid_map.",
        "",
        "To make certain path rdonly/noexec/nosuid/nodev, use bind_mount",
        "To make certain path inaccessible, use make_inaccessible",
        "",
        "It is suggested that you remount /boot, /efi, /etc, /usr, /bin, /sbin, /lib, /lib64, /var, ",
        "/home, /root, /sys, /dev to be read-only or (partially) inaccessible and remount /dev/pts, ",
        "/proc (if you have created a new PID namespace), /sys/fs/cgroup/ (if created new cgroup namespace).",
        "",
        "It is also suggested that you remount /tmp, /dev/shm, /run, /var/tmp to ensure these path won't be ",
        "tempered with from outside of the namespace.",
        "",
        "Check manpage clone(2), namespace(7) and user_namespace(7) for more information.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "clone_ns [-VPCINMpuU] [var]",        /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

int unshare_ns(int flags, const char *self_name)
{
    if (unshare(flags) == -1) {
        warn("%s: unshare failed", self_name);
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
int unshare_ns_builtin(WORD_LIST *list)
{
    int flags = PARSE_FLAG(&list, "CINMpuU", CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, \
                                             CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS);

    if (list != NULL) {
        builtin_usage();
        return (EX_USAGE);
    }

    return unshare_ns(flags, "unshare_ns");
}
PUBLIC struct builtin unshare_ns_struct = {
    "unshare_ns",       /* builtin name */
    unshare_ns_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "unshare_ns puts the process in a new namespace",
        "",
        "If you specified '-p' to create a new PID namespace, then the next child you created will becomes",
        "PID 1 of the new PID namespace and this process won't be able to fork again.",
        "",
        "Check 'help clone_ns' for more information on how to use this function.",
        "Check manpage for unshare(2) for behavior of this function.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "unshare_ns [-CINMpuU]",        /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

int setns_builtin(WORD_LIST *list)
{
    int flags = PARSE_FLAG(&list, "CINMpuU", CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, \
                                             CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS);

    const char *argv[1];
    if (to_argv(list, 1, argv) == -1)
        return (EX_USAGE);

    int fd;
    if (str2fd(argv[0], &fd) == -1)
        return (EX_USAGE);

    if (setns(fd, flags) == -1) {
        warn("setns failed");
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin setns_struct = {
    "setns",       /* builtin name */
    setns_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "setns puts the process into namespace referred by fd.",
        "fd may be opened read-only.",
        "",
        "Flags are optional. They can be used to check the type of namespace before enter into it.",
        "",
        "If you specified '-p' to create a new PID namespace, then the next child you created will becomes",
        "PID 1 of the new PID namespace and this process won't be able to fork again.",
        "",
        "Check 'help clone_ns' for more information on how to use the flags.",
        "Check manpage for setns(2) for behavior of this function.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "setns [-CINMpuU] <int> fd",        /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

int chroot_builtin(WORD_LIST *list)
{
    const char *path;
    if (to_argv(list, 1, &path) == -1)
        return (EX_USAGE);

    if (chroot(path) == -1) {
        warn("chroot failed");
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin chroot_struct = {
    "chroot",       /* builtin name */
    chroot_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "chroot requires the process to have CAP_SYS_CHROOT capability in its user namespace.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "chroot path",        /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

int remount(const char *dest, unsigned long flags, const char *data, const char *fname)
{
    if (mount(NULL, dest, NULL, flags | MS_REMOUNT, data) == -1) {
        warn("%s: %s: failed to apply options %lu, and data %s to %s", 
             fname, "remount", flags, data, dest);
        return (EXECUTION_FAILURE);
    }
    return (EXECUTION_SUCCESS);
}
/**
 * @flags should contain flags other than MS_REMOUNT, MS_BIND and MS_REC.
 */
int bind_mount(const char *src, const char *dest, unsigned long flags, unsigned long recursive, 
               const char *fname)
{
    const char *self_name = "bind_mount";

    const unsigned long bind_mount_flag = MS_BIND | (recursive & MS_REC);
    if (mount(src, dest, NULL, bind_mount_flag, NULL) == -1) {
        warn("%s: %s: 1st mount (bind mount only) of src = %s, dest = %s failed", 
             fname, self_name, src, dest);
        return (EXECUTION_FAILURE);
    }

    int ret;

    if (flags != 0)
        ret = remount(dest, flags | bind_mount_flag, NULL, fname);
    else
        ret = (EXECUTION_SUCCESS);

    return ret;
}
int parse_mount_options(const char *options, unsigned long *flags, const char *fname)
{
    for (size_t i = 0; options[0] != '\0'; ++i) {
        const char *opt_end = strchrnul(options, ',');

        size_t opt_len = opt_end - options;
        if (strncasecmp(options, "RDONLY", opt_len) == 0)
            *flags |= MS_RDONLY;
        else if (strncasecmp(options, "NOEXEC", opt_len) == 0)
            *flags |= MS_NOEXEC;
        else if (strncasecmp(options, "NOSUID", opt_len) == 0)
            *flags |= MS_NOSUID;
        else if (strncasecmp(options, "NODEV", opt_len) == 0)
            *flags |= MS_NODEV;
        else {
            warnx("%s: Invalid option[%zu] provided", fname, i);
            return -1;
        }

        if (opt_end[0] == '\0')
            break;
        else
            options = opt_end + 1;
    }

    return 0;
}
int bind_mount_parseopt(int opt, unsigned long *flags, unsigned long *recursive, const char *fname)
{
    switch (opt) {
    case 'o':
        if (parse_mount_options(list_optarg, flags, fname) == -1)
            return (EX_USAGE);
        break;

    case 'R':
        *recursive = -1;
        break;

    CASE_HELPOPT;

    default:
        builtin_usage();
        return (EX_USAGE);
    }

    return (EXECUTION_SUCCESS);
}
int bind_mount_getopt(WORD_LIST **list, unsigned long *flags, unsigned long *recursive, const char *fname)
{
    reset_internal_getopt();
    for (int opt; (opt = internal_getopt(*list, "o:R")) != -1; ) {
        int result = bind_mount_parseopt(opt, flags, recursive, fname);
        if (result != EXECUTION_SUCCESS)
            return result;
    }
    *list = loptend;

    return (EXECUTION_SUCCESS);
}
int bind_mount_builtin(WORD_LIST *list)
{
    unsigned long flags = 0;
    unsigned long recursive = 0;

    int result = bind_mount_getopt(&list, &flags, &recursive, "bind_mount");
    if (result != EXECUTION_SUCCESS)
        return result;

    const char *paths[2];
    if (to_argv(list, 2, paths) == -1)
        return (EX_USAGE);

    return bind_mount(paths[0], paths[1], flags, recursive, "bind_mount");
}
PUBLIC struct builtin bind_mount_struct = {
    "bind_mount",       /* builtin name */
    bind_mount_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "bind_mount binds src to dest, which can be configured as combination of rdonly, noexec or nosuid",
        "by '-o ...' flag.",
        "",
        "If '-R' is specified and src is a dir, then bind mount is performed recursively:",
        "    all submounts under src is also bind mounted.",
        "",
        "src and dest can be the same path.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "bind_mount [-R] [-o rdonly,noexec,nosuid,nodev] src dest",        /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

/**
 * @param *flags, *recursive must be initialized to 0.
 * @param *data must be initialized to NULL.
 */
int mount_getopt(WORD_LIST **list, unsigned long *flags, unsigned long *recursive, const char **data,
                 const char *fname)
{
    reset_internal_getopt();
    for (int opt; (opt = internal_getopt(*list, "o:O:R")) != -1; ) {
        if (opt == 'O') {
            if (*data != NULL) {
                warnx("%s: '-O' option is specified at least twice", fname);
                return (EX_USAGE);
            } else
                *data = list_optarg;
        } else {
            int result = bind_mount_parseopt(opt, flags, recursive, fname);
            if (result != EXECUTION_SUCCESS)
                return result;
        }
    }
    *list = loptend;

    return (EXECUTION_SUCCESS);
}
int remount_builtin(WORD_LIST *list)
{
    const char *self_name = "remount";

    const char *data = NULL;
    unsigned long flags = 0;
    unsigned long recursive = 0;

    int result = mount_getopt(&list, &flags, &recursive, &data, self_name);
    if (result != (EXECUTION_SUCCESS))
        return result;

    const char *paths[1];
    if (to_argv(list, 1, paths) == -1)
        return (EX_USAGE);

    return remount(paths[0], flags | (recursive & MS_REC), data, self_name);
}
PUBLIC struct builtin remount_struct = {
    "remount",       /* builtin name */
    remount_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "remount remounts dest according to options given.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "remount [-R] [-o rdonly,noexec,nosuid,nodev] [-O options,...] dest",        
    0                             /* reserved for internal use */
};

int make_inaccessible_builtin_impl(WORD_LIST *list, const char *tmp_path)
{
    const unsigned long flags = MS_RDONLY | MS_NOEXEC | MS_NOSUID | MS_NODEV;
    for (; list != NULL; list = list->next) {
        if (bind_mount(tmp_path, list->word->word, flags, 0, "make_inaccessible") != EXECUTION_SUCCESS)
            return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
int make_inaccessible_builtin(WORD_LIST *list)
{
    const char *self_name = "make_inaccessible";

    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    char tmp_path[] = "/tmp/sandboxing_make_inaccessible_builtinXXXXXX";
    if (mkdtemp(tmp_path) == NULL) {
        warn("%s: mkdtemp failed", self_name);
        return (EXECUTION_FAILURE);
    }

    int result = make_inaccessible_builtin_impl(list, tmp_path);

    if (rmdir(tmp_path) == -1) {
        warn("%s: rmdir failed", self_name);
        return (EXECUTION_FAILURE);
    }

    return result;
}
PUBLIC struct builtin make_inaccessible_struct = {
    "make_inaccessible",       /* builtin name */
    make_inaccessible_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "make_inaccessible make paths... inaccessible.",
        "",
        "It should be invoked after a private tmp is mounted and before any new processes",
        "is created in this mount namespace, since it creates a tmp dir internally.",
        "OTHERWISE it is hard to ensure nobody else is TEMPERING with the tmp dir.",
        "",
        "make_inaccessible is implemented using bind mount.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "make_inaccessible paths...",        /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

/**
 * @param tmp_path should be null-terminated string and allocated on heap.
 * @param tmp_len include the trailing null byte.
 */
int bind_to_dir(WORD_LIST *list, char **tmp_path, const size_t tmp_len, unsigned long recursive)
{
    const char *self_name = "make_accessible_under";

    struct stat statbuf;

    size_t buf_len = tmp_len;

    for (size_t i = 1; list != NULL; list = list->next, ++i) {
        if (strcmp(list->word->word, "/") == 0) {
            warnx("%s: the %zu path points to %s", self_name, i, "/");
            return (EX_USAGE);
        }
        char *bind_name = basename(list->word->word);
        if (strcmp(bind_name, ".") == 0) {
            warnx("%s: the %zu path points to %s", self_name, i, ".");
            return (EX_USAGE);
        } else if (strcmp(bind_name, "..") == 0) {
            warnx("%s: the %zu path points to %s", self_name, i, "..");
            return (EX_USAGE);
        }
        size_t bind_len = strlen(bind_name);
        if (bind_len == 0) {
            warnx("%s: the %zu path points to %s", self_name, i, "a path with empty basename");
            return (EX_USAGE);
        }

        if (stat(list->word->word, &statbuf) == -1) {
            warn("%s: failed to stat the %zu path", self_name, i);
            return (EXECUTION_FAILURE);
        }

        if (buf_len < tmp_len + 1 + bind_len) {
            void *p = realloc(*tmp_path, tmp_len + 1 + bind_len);
            if (p == NULL) {
                warn("%s: realloc failed", self_name);
                return (EXECUTION_FAILURE);
            }
            buf_len = tmp_len + 1 + bind_len;
            *tmp_path = p;
        }
        (*tmp_path)[tmp_len - 1] = '/';
        strncpy(*tmp_path + tmp_len, bind_name, bind_len + 1);
        (*tmp_path + tmp_len)[bind_len] = '\0';

        if (S_ISDIR(statbuf.st_mode)) {
            if (mkdir(*tmp_path, S_IRWXU) == -1) {
                if (errno == EEXIST)
                    warn("%s: either the %zu path is the same as one of the previous path, or "
                         "somebody has tempered with %s", self_name, i, *tmp_path);
                else
                    warn("%s: mkdir %s failed", self_name, *tmp_path);
                return (EXECUTION_FAILURE);
            }
        } else {
            int fd;
            do {
                fd = open(*tmp_path, O_WRONLY | O_CREAT | O_EXCL, S_IRWXU);
            } while (fd == -1 && errno == EINTR);
            if (fd == -1) {
                if (errno == EEXIST)
                    warn("%s: either the %zu path is the same as one of the previous path, or "
                         "somebody has tempered with %s", self_name, i, *tmp_path);
                else
                    warn("%s: open %s failed", self_name, *tmp_path);
                return (EXECUTION_FAILURE);
            }
            if (close(fd) == -1 && errno != EINTR) {
                warn("%s: close %s failed", self_name, *tmp_path);
                return (EXECUTION_FAILURE);
            }
        }

        if (bind_mount(list->word->word, *tmp_path, 0, recursive, self_name) != EXECUTION_SUCCESS)
            return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
int make_accessible_under_builtin(WORD_LIST *list)
{
    const char *self_name = "make_accessible_under";

    const char *data = NULL;
    unsigned long flags = 0;
    unsigned long recursive = 0;

    {
        int result = mount_getopt(&list, &flags, &recursive, &data, self_name);
        if (result != (EXECUTION_SUCCESS))
            return result;
    }

    const char *dest;
    if (readin_args(&list, 1, &dest) != 1 || list == NULL) {
        builtin_usage();
        return (EX_USAGE);
    }

    const char template_path[] = "/tmp/sandboxing_make_accessible_under_builtinXXXXXX";
    char *tmp_path = (strdup)(template_path);
    if (tmp_path == NULL) {
        warn("%s: strdup failed", self_name);
        return (EXECUTION_FAILURE);
    }

    int ret;
    if (mkdtemp(tmp_path) == NULL) {
        warn("%s: mkdtemp failed", self_name);
        ret = (EXECUTION_FAILURE);
        goto freeup;
    }

    if (mount("tmpfs", tmp_path, "tmpfs", 0, data) == -1) {
        warn("%s: mount tmpfs at %s failed", self_name, tmp_path);
        ret = (EXECUTION_FAILURE);
        goto rm_tmpdir;
    }

    ret = bind_to_dir(list, &tmp_path, sizeof(template_path), recursive);
    tmp_path[sizeof(template_path) - 1] = '\0';

    if (ret == EXECUTION_SUCCESS) {
        if (flags != 0)
            ret = remount(tmp_path, flags, data, self_name);
    }

    if (ret == EXECUTION_SUCCESS) {
        if (mount(tmp_path, dest, NULL, MS_MOVE, NULL) == -1) {
            warn("%s: move mount from %s to %s failed", self_name, tmp_path, dest);
            ret = (EXECUTION_FAILURE);
        }
    }

    if (ret != EXECUTION_SUCCESS) {
        if (umount(tmp_path) == -1) {
            warn("%s: umount %s failed", self_name, tmp_path);
            ret = EXECUTION_FAILURE;
        }

rm_tmpdir:
        if (rmdir(tmp_path) == -1) {
            warn("%s: rmdir tmp_path %s failed", self_name, tmp_path);
            ret = (EXECUTION_FAILURE);
        }
    }

freeup:
    (free)(tmp_path);

    return ret;
}
PUBLIC struct builtin make_accessible_under_struct = {
    "make_accessible_under",       /* builtin name */
    make_accessible_under_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "make_accessible_under make paths... accessible in dest (which must be a dir other than /tmp)",
        "",
        "-o' options only affect tmpfs mounted at dest dir and '-R' only affects the bind mounting of paths...",
        "-O options will be passed to mount tmpfs.",
        "",
        "paths... can be subdir or files in dest.",
        "paths... must not be '/', '.' or '..'",
        "If paths is a symlink, it will be dereferenced.",
        "There musn't be repeated path in paths...",
        "",
        "The resulting dest dir itself will be read-only.",
        "",
        "It should be invoked after a private tmp is mounted and before any new processes",
        "is created in this mount namespace, since it creates a tmp dir internally.",
        "OTHERWISE it is hard to ensure nobody else is TEMPERING with the tmp dir.",
        "",
        "make_accessible_under is implemented using bind mount.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "make_accessible_under [-R] [-o rdonly,noexec,nosuid,nodev] [-O options,...] dest paths ...",
    0                             /* reserved for internal use */
};

int mount_pseudo_builtin(WORD_LIST *list)
{
    const char *self_name = "mount_pseudo";

    const char *data = NULL;
    unsigned long flags = 0;

    reset_internal_getopt();
    for (int opt; (opt = internal_getopt(list, "O:o:t:")) != -1; ) {
        switch (opt) {
        case 'O':
            if (data != NULL) {
                warnx("%s: '-O' option is specified at least twice", self_name);
                return (EX_USAGE);
            } else
                data = list_optarg;
            break;

        case 'o':
            if (parse_mount_options(list_optarg, &flags, self_name) == -1)
                return (EX_USAGE);
            break;

        CASE_HELPOPT;

        default:
            builtin_usage();
            return (EX_USAGE);
        }
    }
    list = loptend;

    const char *argv[2];
    if (to_argv(list, 2, argv) == -1)
        return (EX_USAGE);

    if (mount(argv[0], argv[1], argv[0], flags, data) == -1) {
        warn("%s: mount failed", self_name);
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin mount_pseudo_struct = {
    "mount_pseudo",       /* builtin name */
    mount_pseudo_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "mount_tmpfs mount tmpfs to path.",
        "",
        "If you want to place block or character file in tmpfs, you must provide '-O mode=0755'.",
        "",
        "For possible options to be passed in via '-O', check manpage of the persudo_filesystem_type.",
        "",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "mount_pseudo [-o rdonly,noexec,nosuid,nodev] [-O options,...] persudo_filesystem_type path",
    0                             /* reserved for internal use */
};

static const char *libcapng_lib_name = "libcap-ng.so";
#define load_libcapng_sym(sym)                     \
    ({                                              \
        void *ret = load_sym(&libcapng_handle, libcapng_lib_name, (sym)); \
        if (ret == NULL)                            \
            return (EXECUTION_FAILURE);             \
        ret;                                        \
     })

int parse_capng_select(const char *arg, size_t i, capng_select_t *set, const char *fname)
{
    if (strcasecmp(arg, "BOUNDS") == 0)
        *set = CAPNG_SELECT_BOUNDS;
    else if (strcasecmp(arg, "CAPS") == 0)
        *set = CAPNG_SELECT_CAPS;
    else if (strcasecmp(arg, "BOTH") == 0)
        *set = CAPNG_SELECT_BOTH;
    else {
        warnx("%s: argv[%zu] is invalid", fname, i + 1);
        return -1;
    }
    return 0;
}
int readin_capng_select_only_impl(WORD_LIST *list, capng_select_t *set, const char *self_name)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    const char* argv[1];
    if (to_argv(list, 1, argv) == -1)
        return (EX_USAGE);

    if (parse_capng_select(argv[0], 0, set, self_name) == -1)
        return (EX_USAGE);

    return (EXECUTION_SUCCESS);
}
#define readin_capng_select_only(list)      \
    ({                                   \
        capng_select_t set;              \
        int result = readin_capng_select_only_impl((list), &set, self_name); \
        if (result != EXECUTION_SUCCESS) \
            return result;               \
        set;                             \
     })

int capng_clear_builtin(WORD_LIST *list)
{
    const char *self_name = "capng_clear";

    capng_select_t set = readin_capng_select_only(list);

    typedef void (*capng_clear_t)(capng_select_t);
    capng_clear_t capng_clear_p = load_libcapng_sym(self_name);
    capng_clear_p(set);

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin capng_clear_struct = {
    "capng_clear",       /* builtin name */
    capng_clear_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "CAPS standss for tranditional capabilities.",
        "BOUNDS stands for the bounding set.",
        "BOTH means both CAPS and BOUNDS.",
        "",
        "Check manpage for capabilities(7) for more info.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "capng_clear [CAPS/BOUNDS/BOTH]",
    0                             /* reserved for internal use */
};

int capng_fill_builtin(WORD_LIST *list)
{
    const char *self_name = "capng_fill";

    capng_select_t set = readin_capng_select_only(list);

    typedef void (*capng_fill_t)(capng_select_t);
    capng_fill_t capng_fill_p = load_libcapng_sym(self_name);
    capng_fill_p(set);

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin capng_fill_struct = {
    "capng_fill",       /* builtin name */
    capng_fill_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "CAPS standss for tranditional capabilities.",
        "BOUNDS stands for the bounding set.",
        "BOTH means both CAPS and BOUNDS.",
        "",
        "Check manpage for capabilities(7) for more info.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "capng_fill [CAPS/BOUNDS/BOTH]",
    0                             /* reserved for internal use */
};

int capng_apply_builtin(WORD_LIST *list)
{
    const char *self_name = "capng_apply";

    capng_select_t set = readin_capng_select_only(list);

    typedef int (*capng_apply_t)(capng_select_t);
    capng_apply_t capng_apply_p = load_libcapng_sym(self_name);
    if (capng_apply_p(set) == -1) {
        warnx("%s failed", self_name);
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin capng_apply_struct = {
    "capng_apply",       /* builtin name */
    capng_apply_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "CAPS standss for tranditional capabilities.",
        "BOUNDS stands for the bounding set.",
        "BOTH means both CAPS and BOUNDS.",
        "",
        "This function would only set the capability of the current thread.",
        "",
        "Check manpage for capabilities(7) for more info.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "capng_apply [CAPS/BOUNDS/BOTH]",
    0                             /* reserved for internal use */
};

int capng_update_builtin(WORD_LIST *list)
{
    const char *self_name = "capng_update";

    typedef int (*capng_update_t)(capng_act_t, capng_type_t, unsigned);
    typedef int (*capng_name_to_cap_t)(const char*);

    capng_type_t type = PARSE_FLAG(&list, "EPIB", 
                                   CAPNG_EFFECTIVE, CAPNG_PERMITTED, CAPNG_INHERITABLE, CAPNG_BOUNDING_SET);

    const char* argv[2];
    if (to_argv(list, 2, argv) == -1)
        return (EX_USAGE);

    capng_act_t action;
    if (strcasecmp(argv[0], "ADD") == 0)
        action = CAPNG_ADD;
    else if (strcasecmp(argv[0], "DROP") == 0)
        action = CAPNG_DROP;
    else {
        warnx("%s: Invalid first non-option arg", self_name);
        return (EX_USAGE);
    }

    capng_name_to_cap_t capng_name_to_cap_p = load_libcapng_sym("capng_name_to_capability");

    const int cap = capng_name_to_cap_p(argv[1]);
    if (cap < 0) {
        warnx("%s: Invalid capability", self_name);
        return (EX_USAGE);
    }

    capng_update_t capng_update_p = load_libcapng_sym(self_name);

    if (capng_update_p(action, type, cap) == -1) {
        warnx("%s failed", self_name);
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin capng_update_struct = {
    "capng_update",       /* builtin name */
    capng_update_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "Pass '-E' to set effective set.",
        "Pass '-P' to set permitted set.",
        "Pass '-I' to set inheritable set.",
        "Pass '-B' to set bounding set.",
        "",
        "Options '-EPIB' are not exclusive to each other.",
        "",
        "capname should be the same name as defined in linux/capability.h with CAP_ prefix removed.",
        "The string case of capname doesn't matter.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "capng_update [-EPIB] ADD/DROP capname",
    0                             /* reserved for internal use */
};

int capng_have_capability_builtin(WORD_LIST *list)
{
    const char *self_name = "capng_have_capability";

    typedef int (*capng_have_cap_t)(capng_type_t, unsigned);
    typedef int (*capng_name_to_cap_t)(const char*);

    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    const char* argv[2];
    if (to_argv(list, 1, argv) == -1)
        return (EX_USAGE);

    capng_type_t type;

    if (strcasecmp(argv[0], "EFFECTIVE") == 0)
        type = CAPNG_EFFECTIVE;
    else if (strcasecmp(argv[0], "PERMITTED") == 0)
        type = CAPNG_PERMITTED;
    else if (strcasecmp(argv[0], "INHERITABLE") == 0)
        type = CAPNG_INHERITABLE;
    else if (strcasecmp(argv[0], "BOUNDING_SET") == 0)
        type = CAPNG_BOUNDING_SET;
    else {
        warnx("%s: Unknown argv[1]", self_name);
        return (EX_USAGE);
    }

    capng_name_to_cap_t capng_name_to_cap_p = load_libcapng_sym("capng_name_to_capability");

    const int cap = capng_name_to_cap_p(argv[1]);
    if (cap < 0) {
        warnx("%s: Invalid capability", self_name);
        return (EX_USAGE);
    }

    capng_have_cap_t capng_have_cap_p = load_libcapng_sym(self_name);

    return !capng_have_cap_p(type, cap);
}
PUBLIC struct builtin capng_have_capability_struct = {
    "capng_have_capability",       /* builtin name */
    capng_have_capability_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "capname should be the same name as defined in linux/capability.h with CAP_ prefix removed.",
        "The string case of capname doesn't matter.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "capng_have_capability EFFECTIVE/PERMITTED/INHERITABLE/BOUNDING_SET ADD/DROP capname",
    0                             /* reserved for internal use */
};

int capng_have_capabilities_builtin(WORD_LIST *list)
{
    const char *self_name = "capng_have_capabilities";

    typedef int (*capng_have_caps_t)(capng_select_t);

    capng_select_t set = readin_capng_select_only(list);

    capng_have_caps_t capng_have_caps_p = load_libcapng_sym(self_name);

    switch (capng_have_caps_p(set)) {
        case CAPNG_FAIL:
            warnx("%s failed", self_name);
            return (EXECUTION_FAILURE);

        case CAPNG_NONE:
            return 4;

        case CAPNG_PARTIAL:
            return 3;

        case CAPNG_FULL:
            return 0;

        default:
            warnx("%s: %s from %s %s", self_name, self_name, libcapng_lib_name, "returns unknown return value");
            return (EXECUTION_FAILURE);
    }
}
PUBLIC struct builtin capng_have_capabilities_struct = {
    "capng_have_capabilities",       /* builtin name */
    capng_have_capabilities_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "CAPS standss for tranditional capabilities.",
        "BOUNDS stands for the bounding set.",
        "BOTH means both CAPS and BOUNDS.",
        "",
        "Returns 0 on full capabilities.",
        "Returns 3 on partial capabilities.",
        "Returns 4 on no capabilities.",
        "Returns 1 on failure.",
        "Returns 2 on wrong usage.",
        "",
        "Check manpage for capabilities(7) for more info.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "capng_have_capabilities [CAPS/BOUNDS/BOTH]",
    0                             /* reserved for internal use */
};

static const char *libseccomp_lib_name = "libseccomp.so";
#define load_libseccomp_sym(sym)                    \
    ({                                              \
        void *ret = load_sym(&libseccomp_handle, libseccomp_lib_name, (sym)); \
        if (ret == NULL)                            \
            return (EXECUTION_FAILURE);             \
        ret;                                        \
     })

int call_seccomp_release(scmp_filter_ctx ctx)
{
    typedef void (*seccoomp_rel_t)(scmp_filter_ctx);
    seccoomp_rel_t seccoomp_rel_p = load_libseccomp_sym("seccomp_release");
    seccoomp_rel_p(ctx);
    return (EXECUTION_SUCCESS);
}

#define CHECK_SECCOMP_CTX_NOT_NULL() \
    if (seccomp_ctx == NULL) {       \
        warnx("%s isn't initialized yet!\nCall %s to initialize it.", libseccomp_lib_name, "seccomp_init"); \
        return (EXECUTION_FAILURE);  \
    }

int parse_action(const char *arg, uint32_t *action, const char *fname, size_t i)
{
    if (strcasecmp(arg, "KILL") == 0)
        *action = SCMP_ACT_KILL;
    else if (strcasecmp(arg, "KILL_PROCESS") == 0)
        *action = SCMP_ACT_KILL_PROCESS;
    else if (strcasecmp(arg, "TRAP") == 0)
        *action = SCMP_ACT_TRAP;
    else if (strncasecmp(arg, "ERRNO:", 6) == 0) {
        int errno_v = parse_errno(arg + 6, i + 1, fname);
        if (errno_v == -1) {
            builtin_usage();
            return -1;
        }
        *action = SCMP_ACT_ERRNO(errno_v);
    } else if (strcasecmp(arg, "LOG") == 0)
        *action = SCMP_ACT_LOG;
    else if (strcasecmp(arg, "ALLOW") == 0)
        *action = SCMP_ACT_ALLOW;
    else {
        warnx("%s: parse_action: Invalid %zu arg", fname, i + 1);
        builtin_usage();
        return -1;
    }
    return 0;
}
int seccomp_init_builtin(WORD_LIST *list)
{
    const char *self_name = "seccomp_init";

    typedef scmp_filter_ctx (*seccomp_init_t)(uint32_t);
    typedef int             (*seccomp_reset_t)(scmp_filter_ctx, uint32_t);

    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    const char* argv[1];
    if (to_argv(list, 1, argv) == -1)
        return (EX_USAGE);

    uint32_t def_actions;
    if (parse_action(argv[0], &def_actions, self_name, 0) == -1)
        return (EX_USAGE);

    int ret = (EXECUTION_SUCCESS);

    if (seccomp_ctx) {
        seccomp_reset_t seccomp_reset_p = load_libseccomp_sym("seccomp_reset");
        if (seccomp_reset_p(seccomp_ctx, def_actions) != 0) {
            warnx("%s: %s failed", self_name, "seccomp_reset");
            ret = (EXECUTION_FAILURE);
        }
    } else {
        seccomp_init_t seccomp_init_p = load_libseccomp_sym("seccomp_init");
        seccomp_ctx = seccomp_init_p(def_actions);
        if (seccomp_ctx == NULL) {
            warnx("%s: %s failed", self_name, "seccomp_init");
            ret = (EXECUTION_FAILURE);
        }
    }

    return ret;
}
PUBLIC struct builtin seccomp_init_struct = {
    "seccomp_init",       /* builtin name */
    seccomp_init_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "Valid default_action values for syscalls where there isn't a rule for:",
        " - \"KILL\": terminate the thread with SIGSYS when a syscall is made against filter rule.",
        " - \"KILL_PROCESS\": terminate the process with SIGSYS when a syscall is made against filter rule.",
        " - \"TRAP\": send SIGSYS to the thread when a syscall is made against filter rule.",
        " - \"ERRNO:errno\": The syscall will return errno.",
        " - \"LOG\": The syscall made against filter rule will be logged.",
        " - \"ALLOW\": have no effect on the thread which made a syscall against seccomp filter",
        "",
        "seccomp_init must be called before any other seccomp_* is called.",
        "",
        "If seccomp_init is called again, then it will releases the existing filter and",
        "reinitialize it with the given def_action.",
        "",
        "Example:",
        "",
        "seccomp_init ERRNO:ENOSYS",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "seccomp_init default_action",
    0                             /* reserved for internal use */
};

int seccomp_release_builtin(WORD_LIST *list)
{
    const char *self_name = "seccomp_release";

    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    if (list != NULL) {
        builtin_usage();
        return (EX_USAGE);
    }

    if (seccomp_ctx != NULL)
        return call_seccomp_release(seccomp_ctx);
    else
        return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin seccomp_release_struct = {
    "seccomp_release",       /* builtin name */
    seccomp_init_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "Release all resources occupied by libseccomp.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "seccomp_release",
    0                             /* reserved for internal use */
};

int resolve_arch(const char *arg, uint32_t *arch, const char *fname)
{
    typedef uint32_t (*seccomp_arch_resolve_name_t)(const char*);
    typedef uint32_t (*seccomp_arch_native_t)();

    if (strcasecmp(arg, "native") != 0) {
        const char *sym = "seccomp_arch_resolve_name";
        seccomp_arch_resolve_name_t seccomp_arch_resolve_name_p = load_libseccomp_sym(sym);

        *arch = seccomp_arch_resolve_name_p(arg);
        if (*arch == 0) {
            warnx("%s: get_arch: Args provided in option '-a' isn't an architecture", fname);
            return (EX_USAGE);
        }
    } else {
        seccomp_arch_native_t seccomp_arch_native_p = load_libseccomp_sym("seccomp_arch_native");
        *arch = seccomp_arch_native_p();
    }

    return (EXECUTION_SUCCESS);
}
int get_arch(WORD_LIST **list, uint32_t *arch, const char *fname)
{
    typedef uint32_t (*seccomp_arch_native_t)();
    typedef uint32_t (*seccomp_arch_resolve_name_t)(const char*);

    int has_set_arch = 0;

    reset_internal_getopt();
    for (int opt; (opt = internal_getopt(*list, "a:")) != -1; ) {
        switch (opt) {
            case 'a':
            if (!has_set_arch) {
                int result = resolve_arch(list_optarg, arch, fname);
                if (result != (EXECUTION_SUCCESS))
                    return result;

                has_set_arch = 1;
            } else {
                warnx("%s: Switch -a is specified twice", fname);
                return (EX_USAGE);
            }
            break;

            CASE_HELPOPT;

            default:
                builtin_usage();
                return (EX_USAGE);
        }
    }

    int ret = (EXECUTION_SUCCESS);

    if (!has_set_arch)
        ret = resolve_arch("native", arch, fname);

    *list = loptend;

    return ret;
}
int seccomp_resolve_syscall(uint32_t arch, const char *arg, int *syscall_num, size_t i, const char *fname)
{
    typedef int (*resolver_t)(uint32_t, const char*);
    resolver_t seccomp_syscall_resolver_p = load_libseccomp_sym("seccomp_syscall_resolve_name_arch");

    *syscall_num = seccomp_syscall_resolver_p(arch, arg);
    if (*syscall_num == __NR_SCMP_ERROR) {
        warnx("%s: Invalid syscall in %zu arg", fname, i + 1);
        return (EX_USAGE);
    }

    return (EXECUTION_SUCCESS);
}
int seccomp_rule_add_builtin(WORD_LIST *list)
{
    const char *self_name = "seccomp_rule_add";

    uint32_t arch;
    {
        int result = get_arch(&list, &arch, self_name);
        if (result != (EXECUTION_SUCCESS))
            return result;
    }

    const char* argv[2];
    if (readin_args(&list, 2, argv) != 2) {
        builtin_usage();
        return (EX_USAGE);
    }

    uint32_t action;
    if (parse_action(argv[0], &action, self_name, 0) == -1)
        return (EX_USAGE);

    int syscall_num;
    {
        int result = seccomp_resolve_syscall(arch, argv[1], &syscall_num, 1, self_name);
        if (result != (EXECUTION_SUCCESS))
            return result;
    }

    CHECK_SECCOMP_CTX_NOT_NULL();

    typedef int (*seccomp_rule_addv_t)(scmp_filter_ctx, uint32_t, int, unsigned, const struct scmp_arg_cmp*);
    const char *loaded_fname = "seccomp_rule_add_array";
    seccomp_rule_addv_t seccomp_rule_addv_p = load_libseccomp_sym(loaded_fname);

    int argc = list_length(list);

    struct scmp_arg_cmp *arg_cmp;
    START_VLA(struct scmp_arg_cmp, argc, arg_cmp);

    int ret = (EXECUTION_SUCCESS);

    for (int i = 0; i != argc; ++i, list = list->next) {
        const char *arg = list->word->word;

        uint64_t narg;
        uint64_t bit;

        char op[3];
        uint64_t arg1;
        uint64_t arg2;

        int n;
        int result = sscanf(arg, "A%" PRIu64 "_%" PRIu64 " %2s %" PRIu64 " %n", &narg, &bit, op, &arg1, &n);

        if (result == EOF) {
            warn("%s: sscanf on %d arg failed", self_name, i + 3);
            ret = (EXECUTION_FAILURE);
            goto cleanup;
        } else if (result != 4 || narg > 5 || (bit != 32 && bit != 64)) {
            const char *err_msg = "Invalid format";
            if (narg > 5)
                err_msg = "narg too large";
            else if (bit != 32 && bit != 64)
                err_msg = "bit is neither 32 nor 64";
            warnx("%s: Invalid %d arg: %s", self_name, i + 3, err_msg);
            ret = (EX_USAGE);
            goto cleanup;
        }

        enum scmp_compare op_enum;
        switch (((int) op[0] << 8) | (int) op[1]) {
            default:
                warnx("%s: Invalid %d arg: %s", self_name, i + 3, "Invalid operator");
                ret = (EX_USAGE);
                goto cleanup;

            case ((int) '<' << 8) | (int) '\0':
                op_enum = SCMP_CMP_LT;
                break;

            case ((int) '<' << 8) | (int) '=':
                op_enum = SCMP_CMP_LE;
                break;

            case ((int) '>' << 8) | (int) '\0':
                op_enum = SCMP_CMP_GT;
                break;

            case ((int) '>' << 8) | (int) '=':
                op_enum = SCMP_CMP_GE;
                break;

            case ((int) '=' << 8) | (int) '=':
                op_enum = SCMP_CMP_EQ;
                break;

            case ((int) '!' << 8) | (int) '=':
                op_enum = SCMP_CMP_NE;
                break;

            case ((int) '&' << 8) | (int) '\0':
                op_enum = SCMP_CMP_MASKED_EQ;
                arg += n;
                result = sscanf(arg, "== %" PRIu64 " %n", &arg2, &n);
                if (result == EOF) {
                    warn("%s: sscanf on %d arg failed", self_name, i + 3);
                    ret = (EXECUTION_FAILURE);
                    goto cleanup;
                } else if (result != 1) {
                    warnx("%s: Invalid %d arg: %s", self_name, i + 3, "Invalid format");
                    ret = (EX_USAGE);
                    goto cleanup;
                }
                break;
        }

        if (arg[n] != '\0') {
             warnx("%s: Invalid %d arg: %s", self_name, i + 3, "Too many parameters");
             ret = (EX_USAGE);
             goto cleanup;
        }

        if (bit == 32) {
            if (op_enum != SCMP_CMP_MASKED_EQ)
                arg_cmp[i] = SCMP_CMP32(narg, op_enum, arg1);
            else
                arg_cmp[i] = SCMP_CMP32(narg, op_enum, arg1, arg2);
        } else {
            if (op_enum != SCMP_CMP_MASKED_EQ)
                arg_cmp[i] = SCMP_CMP64(narg, op_enum, arg1);
            else
                arg_cmp[i] = SCMP_CMP64(narg, op_enum, arg1, arg2);
        }
    }

    if (seccomp_rule_addv_p(seccomp_ctx, action, syscall_num, argc, arg_cmp) != 0) {
        warnx("%s: %s from %s %s", self_name, loaded_fname, libseccomp_lib_name, "failed");
        ret = (EXECUTION_FAILURE);
    }

cleanup:
    END_VLA(arg_cmp);

    return ret;
}
PUBLIC struct builtin seccomp_rule_add_struct = {
    "seccomp_rule_add",       /* builtin name */
    seccomp_rule_add_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "Valid action values for syscall_name:",
        " - \"KILL\": terminate the thread with SIGSYS when a syscall is made against filter rule.",
        " - \"KILL_PROCESS\": terminate the process with SIGSYS when a syscall is made against filter rule.",
        " - \"TRAP\": send SIGSYS to the thread when a syscall is made against filter rule.",
        " - \"ERRNO:errno\": The syscall will return errno.",
        " - \"LOG\": The syscall made against filter rule will be logged.",
        " - \"ALLOW\": have no effect on the thread which made a syscall against seccomp filter",
        "",
        "syscall_arg_requirements should be a list of arguments in the format of",
        "\"A{arg}_{bits} op val\", where op can be </<=/>/>=/==/!=/&.",
        "",
        "If op == '&', then the argument should be \"A{arg}_{bits} op bitmask == val\"",
        "",
        "If you want to add a syscall for architecture other than your native arch, you can use switch -a:",
        "-a native/x86/x86-64/...",
        "",
        "Example:",
        " - seccomp_rule_add KILL read 'A0_32 == 1': If the 1st argument to read equals to 0, kill the thread",
        " - seccomp_rule_add KILL write: If the thread calls write, it is killed.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "seccomp_rule_add [-a arch] action syscall_name [syscall_arg_requirements]",
    0                             /* reserved for internal use */
};

int seccomp_arch_template_builtin(WORD_LIST *list, const char *fname, int is_seccomp_arch_exist)
{
    typedef int (*fp)(scmp_filter_ctx, uint32_t);

    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    uint32_t arch;
    {
        const char* argv[1];
        if (to_argv(list, 1, argv) == -1)
            return (EX_USAGE);

        int result = resolve_arch(argv[0], &arch, fname);
        if (result != (EXECUTION_SUCCESS))
            return result;
    }
 
    CHECK_SECCOMP_CTX_NOT_NULL();

    fp f = load_libseccomp_sym(fname);
    int result = f(seccomp_ctx, arch);

    if (is_seccomp_arch_exist && result == -EEXIST)
        return 3;

    if (result != 0) {
        errno = -result;
        warn("%s failed", fname);
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
int seccomp_arch_add_builtin(WORD_LIST *list)
{
    return seccomp_arch_template_builtin(list, "seccomp_arch_add", 0);
}
PUBLIC struct builtin seccomp_arch_add_struct = {
    "seccomp_arch_add",       /* builtin name */
    seccomp_arch_add_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "Add arch to seccomp filter.",
        "arch can be native/x86/x86-64/...\n",
        "NOTE that after seccomp_init, native architecture is automatically added.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "seccomp_arch_add arch",
    0                             /* reserved for internal use */
};

int seccomp_arch_remove_builtin(WORD_LIST *list)
{
    return seccomp_arch_template_builtin(list, "seccomp_arch_remove", 0);
}
PUBLIC struct builtin seccomp_arch_remove_struct = {
    "seccomp_arch_remove",       /* builtin name */
    seccomp_arch_remove_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "Add arch to seccomp filter.",
        "arch can be native/x86/x86-64/...\n",
        "NOTE that if all of architecture is removed, then other seccomp* will most likely fail.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "seccomp_arch_remove arch",
    0                             /* reserved for internal use */
};

int seccomp_arch_exist_builtin(WORD_LIST *list)
{
    return seccomp_arch_template_builtin(list, "seccomp_arch_exist", 1);
}
PUBLIC struct builtin seccomp_arch_exist_struct = {
    "seccomp_arch_exist",       /* builtin name */
    seccomp_arch_exist_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "Add arch to seccomp filter.",
        "arch can be native/x86/x86-64/...\n",
        "Returns 3 if the architecture is not added, 1 if failed, 2 if wrong usage.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "seccomp_arch_exist arch",
    0                             /* reserved for internal use */
};

int seccomp_attr_set_builtin(WORD_LIST *list)
{
    const char *self_name = "seccomp_attr_set";
    typedef int (*seccomp_attr_set_t)(scmp_filter_ctx, enum scmp_filter_attr, uint32_t);

    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    const char* argv[2];
    if (to_argv(list, 2, argv) == -1)
        return (EX_USAGE);

    enum scmp_filter_attr attr;
    if (strcasecmp(argv[0], "CTL_NO_NEW_PRIVS") == 0)
        attr = SCMP_FLTATR_CTL_NNP;
    else if (strcasecmp(argv[0], "CTL_TSYNC") == 0)
        attr = SCMP_FLTATR_CTL_TSYNC;
    else if (strcasecmp(argv[0], "CTL_LOG") == 0)
        attr = SCMP_FLTATR_CTL_LOG;
    else {
        warnx("%s: Unknown attr", self_name);
        return (EX_USAGE);
    }

    uint32_t val;
    if (strcmp(argv[1], "1") == 0)
        val = 1;
    else if (strcmp(argv[1], "0") == 0)
        val = 0;
    else {
        warnx("%s: Unknown val", self_name);
        return (EX_USAGE);
    }

    CHECK_SECCOMP_CTX_NOT_NULL();

    seccomp_attr_set_t seccomp_attr_set_p = load_libseccomp_sym(self_name);
    int result = seccomp_attr_set_p(seccomp_ctx, attr, val);
    if (result != 0) {
        errno = -result;
        warn("%s failed", self_name);
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin seccomp_attr_set_struct = {
    "seccomp_attr_set",       /* builtin name */
    seccomp_attr_set_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "seccomp_attr_set set value of attr to val.\n",
        "Possible attr",
        " - CTL_NO_NEW_PRIVS: set to 1 so that NO_NEW_PRIVS is set on seccomp_load (the default)",
        " - CTL_TSYNC: set to 1 to synchronize the load of filters across all threads in seccomp_load, ",
        "              if cannot synchronize the filter during seccomp_load, seccomp_load will fail.",
        "              Defalt to 0.",
        " - CTL_LOG: set to 1 to log all not allowed syscalls.",
        "              Defalt to 0.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "seccomp_attr_set attr val",
    0                             /* reserved for internal use */
};

int seccomp_syscall_priority_builtin(WORD_LIST *list)
{
    const char *self_name = "seccomp_syscall_priority";
    typedef int (*seccomp_syscall_priority_t)(scmp_filter_ctx, int syscall, uint8_t priority);

    uint32_t arch;
    {
        int result = get_arch(&list, &arch, self_name);
        if (result != (EXECUTION_SUCCESS))
            return result;
    }

    int syscall_number;
    uint8_t priority;
    {
        const char* argv[2];
        if (to_argv(list, 2, argv) == -1)
            return (EX_USAGE);
 
        int result = seccomp_resolve_syscall(arch, argv[0], &syscall_number, 0, self_name);
        if (result != (EXECUTION_SUCCESS))
            return result;
        
        intmax_t num;
        if (legal_number(argv[1], &num) == 0) {
            warnx("%s: 2 arg %s", self_name, "need to be a number");
            builtin_usage();
            return (EX_USAGE);
        } else if (result > UINT8_MAX || result < 0) {
            warnx("%s: 2 arg %s", self_name, "is out of range");
            builtin_usage();
            return (EX_USAGE);
        }
 
        priority = num;
    }

    CHECK_SECCOMP_CTX_NOT_NULL();

    seccomp_syscall_priority_t seccomp_syscall_priority_p = load_libseccomp_sym(self_name);
    int result = seccomp_syscall_priority_p(seccomp_ctx, syscall_number, priority);
    
    if (result != 0) {
        errno = -result;
        warn("%s failed", self_name);
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin seccomp_syscall_priority_struct = {
    "seccomp_syscall_priority",       /* builtin name */
    seccomp_syscall_priority_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "seccomp_syscall_priority set priority of syscall on arch (default to native) to priority.\n",
        "Filters for syscalls with higher priority will be placed earlier in the seccomp filter code",
        "so that they incur less overhead at the expense of syscalls with lower priority.\n",
        "User can set syscall priority prior to seccomp_rule_add.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "seccomp_syscall_priority [-a arch] syscall_name uint8_t:priority",
    0                             /* reserved for internal use */
};

int seccomp_load_builtin(WORD_LIST *list)
{
    const char *self_name = "seccomp_load";
    typedef int (*seccomp_load_t)(scmp_filter_ctx);

    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    if (list != NULL) {
        builtin_usage();
        return (EX_USAGE);
    }

    CHECK_SECCOMP_CTX_NOT_NULL();

    seccomp_load_t seccomp_load_p = load_libseccomp_sym(self_name);
    int result = seccomp_load_p(seccomp_ctx);

    if (result != 0) {
        errno = -result;
        warn("%s failed", self_name);
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin seccomp_load_struct = {
    "seccomp_load",       /* builtin name */
    seccomp_load_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "seccomp_load load the filter into kernel.\n",
        "Unless seccomp_attr_set CTL_NO_NEW_PRIVS 0, otherwise seccomp_load will set NO_NEW_PRIVS before",
        "loading the filter.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "seccomp_load",
    0                             /* reserved for internal use */
};

int seccomp_export_template_builtin(WORD_LIST *list, const char *fname)
{
    typedef int (*fp)(const scmp_filter_ctx, int fd);

    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    int fd;
    {
        const char* argv[1];
        if (to_argv(list, 1, argv) == -1)
            return (EX_USAGE);

        if (str2fd(argv[0], &fd) == -1)
            return (EX_USAGE);
    }

    CHECK_SECCOMP_CTX_NOT_NULL();

    fp f = load_libseccomp_sym(fname);
    int result = f(seccomp_ctx, fd);

    if (result != 0) {
        errno = -result;
        warn("%s failed", fname);
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
int seccomp_export_bpf_builtin(WORD_LIST *list)
{
    return seccomp_export_template_builtin(list, "seccomp_export_bpf");
}
PUBLIC struct builtin seccomp_export_bpf_struct = {
    "seccomp_export_bpf",       /* builtin name */
    seccomp_export_bpf_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "seccomp_export_bpf generate and output the current seccomp filter in BPF to fd.\n",
        "Generated output is suitable to load into a kernel.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "seccomp_export_bpf int:fd",
    0                             /* reserved for internal use */
};

int seccomp_export_pfc_builtin(WORD_LIST *list)
{
    return seccomp_export_template_builtin(list, "seccomp_export_pfc");
}
PUBLIC struct builtin seccomp_export_pfc_struct = {
    "seccomp_export_pfc",       /* builtin name */
    seccomp_export_pfc_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "seccomp_export_pfc generate and output the current seccomp filter in PFC to fd.\n",
        "Generated output is human readable and for debugging purpose.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "seccomp_export_pfc int:fd",
    0                             /* reserved for internal use */
};

int seccomp_api_get_builtin(WORD_LIST *list)
{
    const char *self_name = "seccomp_api_get";
    typedef const unsigned int (*seccomp_api_get_t)();

    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    if (list != NULL) {
        builtin_usage();
        return (EX_USAGE);
    }

    seccomp_api_get_t seccomp_api_get_p = load_libseccomp_sym(self_name);
    return seccomp_api_get_p() + 3;
}
PUBLIC struct builtin seccomp_api_get_struct = {
    "seccomp_api_get",       /* builtin name */
    seccomp_api_get_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "seccomp_api_get returns:",
        " - 1: on failure to load libseccomp or symbol seccomp_api.",
        " - 2: wrong usage", 
        " - 3: Reserved value, not currently used.",
        " - 4: Base level support.",
        " - 5: CTL_TSYNC attribute is supported and libseccomp uses seccomp(2) syscall to load the filter.",
        " - 6: CTL_LOG attribute and LOG action is supported.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "seccomp_api_get",
    0                             /* reserved for internal use */
};

int seccomp_version_builtin(WORD_LIST *list)
{
    const char *self_name = "seccomp_version";
    typedef const struct scmp_version* (*seccomp_version_t)();

    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    if (list != NULL) {
        builtin_usage();
        return (EX_USAGE);
    }

    seccomp_version_t seccomp_version_p = load_libseccomp_sym(self_name);
    const struct scmp_version *version = seccomp_version_p();

    int result = printf("%u.%u.%u\n", version->major, version->minor, version->micro);
    if (result < 0) {
        warn("%s: printf failed", self_name);
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin seccomp_version_struct = {
    "seccomp_version",       /* builtin name */
    seccomp_version_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "seccomp_version prints out the version of libsecomp.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "seccomp_version",
    0                             /* reserved for internal use */
};

int sandboxing_builtin(WORD_LIST *_)
{
    Dl_info info;
    if (dladdr(sandboxing_builtin, &info) == 0) {
        warnx("Failed to get path to the shared object itself by dladdr");
        return 1;
    }

    WORD_DESC words[] = {
        { .word = "-f", .flags = 0 },

        /**
         * Pretty sure that it's not going to be modified in enable_builtin.
         *
         * And since all other words.word here points to string in .rodata and it works,
         * I don't think this is a problem.
         */
        { .word = (char*) info.dli_fname, .flags = 0 },

        { .word = "enable_no_new_privs_strict", .flags = 0 },
        { .word = "set_securebits", .flags = 0 },

        { .word = "clone_ns", .flags = 0 },
        { .word = "unshare_ns", .flags = 0 },
        { .word = "setns", .flags = 0 },
        { .word = "chroot", .flags = 0 },

        { .word = "bind_mount", .flags = 0 },
        { .word = "remount", .flags = 0 },
        { .word = "make_inaccessible", .flags = 0 },
        { .word = "make_accessible_under", .flags = 0 },
        { .word = "mount_pseudo", .flags = 0 },

        { .word = "capng_clear", .flags = 0 },
        { .word = "capng_fill", .flags = 0 },
        { .word = "capng_apply", .flags = 0 },
        { .word = "capng_update", .flags = 0 },
        { .word = "capng_have_capability", .flags = 0 },
        { .word = "capng_have_capabilities", .flags = 0 },

        { .word = "seccomp_init", .flags = 0 },
        { .word = "seccomp_release", .flags = 0 },
        { .word = "seccomp_rule_add", .flags = 0 },
        { .word = "seccomp_arch_add", .flags = 0 },
        { .word = "seccomp_arch_remove", .flags = 0 },
        { .word = "seccomp_arch_exist", .flags = 0 },
        { .word = "seccomp_attr_set", .flags = 0 },
        { .word = "seccomp_syscall_priority", .flags = 0 },
        { .word = "seccomp_load", .flags = 0 },
        { .word = "seccomp_export_bpf", .flags = 0 },
        { .word = "seccomp_export_pfc", .flags = 0 },
        { .word = "seccomp_api_get", .flags = 0 },
        { .word = "seccomp_version", .flags = 0 },
    };

    const size_t builtin_num = sizeof(words) / sizeof(WORD_DESC);

    WORD_LIST list[builtin_num];
    for (size_t i = 0; i != builtin_num; ++i) {
        list[i].word = &words[i];
        list[i].next = i + 1 != builtin_num ? &list[i + 1] : NULL;
    }

    return enable_builtin(list);
}
PUBLIC struct builtin sandboxing_struct = {
    "sandboxing",       /* builtin name */
    sandboxing_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "enables all builtin defined in this file.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "sandboxing",                 /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};
