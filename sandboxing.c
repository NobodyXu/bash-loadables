/* sandboxing - loadable builtin that helps user sandbox applications */

#include "utilities.h"

#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include <sys/prctl.h>

#include <sched.h>

#include <dlfcn.h>

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

int enable_no_new_orivs_strict_builtin(WORD_LIST *list)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin enable_no_new_orivs_strict_struct = {
    "enable_no_new_orivs_strict",             /* builtin name */
    enable_no_new_orivs_strict_builtin,       /* function implementing the builtin */
    BUILTIN_ENABLED,        /* initial flags for builtin */
    (char*[]){
        "After this function call, no new privileges is allowed for this process and its child process.",
        "It is also preserved accross execve and cannot be unset.",
        (char *)NULL
    },                      /* array of long documentation strings. */
    "enable_no_new_orivs_strict_builtin",             /* usage synopsis; becomes short_doc */
    0                       /* reserved for internal use */
};

int clone_ns_fn(void *arg)
{
    longjmp(*((jmp_buf*) arg), 1);
}
int clone_ns_builtin(WORD_LIST *list)
{
    int flags = PARSE_FLAG(&list, "VCINMPuU", CLONE_VFORK, CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, \
                                              CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS);

    const char *varname = NULL;
    if (to_argv_opt(list, 0, 1, &varname) == -1)
        return (EX_USAGE);

    int pid;
    jmp_buf env;
    if (setjmp(env) == 0) {
        {
            char stack[8064];
            pid = clone(clone_ns_fn, stack, flags, &env);
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
        "If '-C' is passed, child process is put in a new cgroup.",
        "If '-I' is passed, child process is put in a new IPC namespace.",
        "If '-N' is passed, child process is put in a new network namespace.",
        "If '-M' is passed, child process is put in a new mount namespace.",
        "If '-P' is passed, child process is put in a new PID namespace.",
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
        "Check manpage clone(2), namespace(7) and user_namespace(7) for more information.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "clone_ns [-VCINMPuU] [var]",        /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

int unshare_ns_builtin(WORD_LIST *list)
{
    int flags = PARSE_FLAG(&list, "CINMPuU", CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, \
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
    "unshare_ns [-CINMPuU]",        /* usage synopsis; becomes short_doc */
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

        { .word = "enable_no_new_orivs_strict", .flags = 0 },

        { .word = "clone_ns", .flags = 0 },
        { .word = "unshare_ns", .flags = 0 },
        { .word = "chroot", .flags = 0 },
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
