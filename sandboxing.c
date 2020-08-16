/* sandboxing - loadable builtin that helps user sandbox applications */

#include "utilities.h"

#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include <sys/mount.h>
#include <sys/prctl.h>

#include <linux/securebits.h>

#include <sched.h>

#include <dlfcn.h>

#include <errno.h>

/**
 * Called when `sandboxing' is enabled and loaded from the shared object.
 *
 * If this function returns 0, the load fails.
 */
PUBLIC int sandboxing_builtin_load(char *name)
{
    return (1);
}

/**
 * Called when `template' is disabled.
 */
PUBLIC void sandboxing_builtin_unload(char *name)
{}

int enable_no_new_privs_strict_builtin(WORD_LIST *list)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

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
            char stack[8064];
            pid = clone(clone_ns_fn, stack, flags | SIGCHLD, &env);
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

int unshare_ns_builtin(WORD_LIST *list)
{
    int flags = PARSE_FLAG(&list, "CINMpuU", CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, \
                                             CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS);

    if (list != NULL) {
        builtin_usage();
        return (EX_USAGE);
    }

    if (unshare(flags) == -1) {
        warn("unshare failed");
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin unshare_ns_struct = {
    "unshare_ns",       /* builtin name */
    unshare_ns_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "unshare_ns puts the process in a new namespace",
        "",
        "Check 'help clone_ns' for more information on how to use this function.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "unshare_ns [-CINMpuU]",        /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

int setns_builtin(WORD_LIST *list)
{
    int flags = PARSE_FLAG(&list, "CINMPuU", CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, \
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
        "Check 'help clone_ns' for more information on how to use the flags.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "setns [-CINMPuU] <int> fd",        /* usage synopsis; becomes short_doc */
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

/**
 * @flags should contain flags other than MS_REMOUNT, MS_BIND and MS_REC.
 */
int bind_mount(const char *src, const char *dest, unsigned long flags, unsigned long recursive, 
               const char *fname)
{
    const unsigned long bind_mount_flag = MS_BIND | (recursive & MS_REC);
    if (mount(src, dest, NULL, bind_mount_flag, NULL) == -1) {
        warn("%s: bind_mount: 1st mount (bind mount only) of src = %s, dest = %s failed", 
             fname, src, dest);
        return (EXECUTION_FAILURE);
    }

    if (mount(NULL, dest, NULL, flags | MS_REMOUNT | bind_mount_flag, NULL) == -1) {
        warn("%s: bind_mount: 2st mount (apply options) of %s failed", fname, dest);
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
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
int bind_mount_getopt(WORD_LIST **list, unsigned long *flags, unsigned long *recursive, const char *fname)
{
    reset_internal_getopt();
    for (int opt; (opt = internal_getopt(*list, "o:R")) != -1; ) {
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
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    char tmp_path[] = "/tmp/sandboxing_make_inaccessible_builtinXXXXXX";
    if (mkdtemp(tmp_path) == NULL) {
        warn("make_inaccessible: mkdtemp failed");
        return (EXECUTION_FAILURE);
    }

    int result = make_inaccessible_builtin_impl(list, tmp_path);

    if (rmdir(tmp_path) == -1) {
        warn("make_inaccessible: rmdir failed");
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
int make_accessible_under_builtin_impl(WORD_LIST *list, const char *dest, char **tmp_path, size_t tmp_len,
                                       unsigned long flags, unsigned long recursive)
{
    const char *self_name = "make_accessible_under";
    size_t buf_len = tmp_len;

    for (size_t i = 1; list != NULL; list = list->next, ++i) {
        char *bind_name = basename(list->word->word);
        if (strcmp(bind_name, "/") == 0) {
            warnx("%s: the %zu path points to %s", self_name, i, "/");
            return (EX_USAGE);
        } else if (strcmp(bind_name, ".") == 0) {
            warnx("%s: the %zu path points to %s", self_name, i, ".");
            return (EX_USAGE);
        }
        size_t bind_len = strlen(bind_name);

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

        if (bind_mount(list->word->word, *tmp_path, flags, recursive, self_name) != EXECUTION_SUCCESS)
            return (EXECUTION_FAILURE);
    }

    (*tmp_path)[tmp_len - 1] = '\0';
    return bind_mount(*tmp_path, dest, 0, 1, self_name);
}
int make_accessible_under_builtin(WORD_LIST *list)
{
    unsigned long flags = 0;
    unsigned long recursive = 0;

    const char *self_name = "make_accessible_under";

    int result = bind_mount_getopt(&list, &flags, &recursive, self_name);
    if (result != EXECUTION_SUCCESS)
        return result;

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
    if (mkdtemp(tmp_path) == NULL) {
        warn("%s: mkdtemp failed", self_name);
        return (EXECUTION_FAILURE);
    }

    result = make_accessible_under_builtin_impl(list, dest, &tmp_path, sizeof(template_path), flags, recursive);
    tmp_path[sizeof(template_path) - 1] = '\0';

    if (rmdir(tmp_path) == -1) {
        warn("%s: rmdir failed", self_name);
        result = (EXECUTION_FAILURE);
    }

    (free)(tmp_path);

    return result;
}
PUBLIC struct builtin make_accessible_under_struct = {
    "make_accessible_under",       /* builtin name */
    make_accessible_under_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "make_accessible_under make /path/to/be/accessed/... accessible in dest",
        "",
        "/path/to/be/accessed can be subdir or files in dest in absolute path.",
        "If /path/to/be/accessed is a symlink, if won't get dereferenced.",
        "/path/to/be/accessed must not be '/'",
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
    "make_accessible_under [-R] [-o rdonly,noexec,nosuid,nodev] dest /path/to/be/accessed/ ...",
    0                             /* reserved for internal use */
};

int mount_pseudo_builtin(WORD_LIST *list)
{
    const char *data = NULL;
    unsigned long flags = 0;

    reset_internal_getopt();
    for (int opt; (opt = internal_getopt(list, "O:o:t:")) != -1; ) {
        switch (opt) {
        case 'O':
            if (data != NULL) {
                warnx("mount_pseudo: '-o' option is specified at least twice");
                return (EX_USAGE);
            } else
                data = list_optarg;
            break;

        case 'o':
            if (parse_mount_options(list_optarg, &flags, "mount_pseudo") == -1)
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
        warn("mount_pseudo: mount failed");
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
        { .word = "make_inaccessible", .flags = 0 },
        { .word = "make_accessible", .flags = 0 },
        { .word = "mount_pseudo", .flags = 0 },
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
