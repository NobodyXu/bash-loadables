/* fd_ops - loadable builtin that defines fd-related functions */

#define _LARGEFILE64_SOURCE // for lseek64

// For fexecve
#define _POSIX_C_SOURCE 200809L

/* See Makefile for compilation details. */
#include "bash/config.h"

#ifndef  _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include "bashansi.h"
#include "loadables.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/mman.h>
#include <sys/types.h>

#include <unistd.h>
#include <errno.h>

void int2str(int integer, char buffer[11])
{
    snprintf(buffer, 11, "%d", integer);
}

/**
 * @param str must not be null
 * @param integer must be a valid pointer.
 *                If str2int failed, its value is unchanged.
 * @return 0 on success, -1 if not enough/too many arguments.
 */
int str2int(const char *str, int *integer)
{
    intmax_t result;
    if (legal_number(str, &result) == 0 || result > INT_MAX || result < INT_MIN) {
        builtin_usage();
        return -1;
    }
 
    *integer = result;
    return 0;
}

/**
 * @param str must not be null
 * @param integer must be a valid pointer.
 *                If str2fd failed, its value is unchanged.
 * @return 0 on success, -1 if not enough/too many arguments.
 */
int str2fd(const char *str, int *fd)
{
    if (str2int(str, fd) == -1)
        return -1;
    if (*fd < 0) {
        builtin_usage();
        return -1;
    }
    return 0;
}

/**
 * Same as to_argv except it allows optional argument.
 * @return 0 on success, -1 if not enough.
 */
int to_argv_impl(WORD_LIST **l, int argc, const char *argv[])
{
    for (int i = 0; i != argc; ++i) {
        if ((*l) == NULL) {
            builtin_usage();
            return -1;
        }

        argv[i] = (*l)->word->word;
        (*l) = (*l)->next;
    }

    return 0;
}
/**
 * @return 0 on success, -1 if not enough/too many arguments.
 */
int to_argv(WORD_LIST *l, int argc, const char *argv[])
{
    to_argv_impl(&l, argc, argv);
    return l != NULL ? -1 : 0;
}
/**
 * @return number of optional arg read in on success, -1 if not enough/too many arguments.
 */
int to_argv_opt(WORD_LIST *l, int argc, int opt_argc, const char *argv[])
{
    to_argv_impl(&l, argc, argv);
    
    int i = 0;
    for (; i != opt_argc; ++i) {
        if (l == NULL)
            return i;

        argv[i] = l->word->word;
        l = l->next;
    }
    return l != NULL ? -1 : i;
}

int memfd_create_builtin(WORD_LIST *list)
{
    reset_internal_getopt();

    unsigned int flags = 0;
    for (int opt; (opt = internal_getopt(list, "C")) != -1; ) {
        switch (opt) {
        case 'C':
            flags |= MFD_CLOEXEC;
            break;

        CASE_HELPOPT;

        default:
            builtin_usage();
            return (EX_USAGE);
        }
    }
    list = loptend;

    const char *var;
    if (to_argv(list, 1, &var) == -1)
        return (EX_USAGE);

    int fd = memfd_create(var, flags);
    if (fd == -1) {
        perror("memfd_create failed");
        if (errno == EFAULT || errno == EINVAL)
            return 100;
        else
            return 1;
    }

    _Static_assert (sizeof(int) <= 4, "sizeof(int) is bigged than 4 bytes");

    char buffer[11]; // 10 bytes is enough for 4-byte unsigned int
    int2str(fd, buffer);
    bind_variable(var, buffer, 0);

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin memfd_create_struct = {
    "memfd_create",             /* builtin name */
    memfd_create_builtin,       /* function implementing the builtin */
    BUILTIN_ENABLED,            /* initial flags for builtin */
    (char*[]){
        "Create an anonymous file in RAM and store it in variable $VAR.",
        "NOTE that if swap is enabled, this anonymous can be swapped onto disk.",
        "",
        "Pass -C to enable CLOEXEC.",
        "",
        "On resource exhaustion, return 1.",
        "On any other error, return 100", 
        (char*) NULL
    },                          /* array of long documentation strings. */
    "memfd_create [-C] VAR",    /* usage synopsis; becomes short_doc */
    0                           /* reserved for internal use */
};

int lseek_builtin(WORD_LIST *list)
{
    reset_internal_getopt();
    if (no_options(list)) // If options present
        return (EX_USAGE);
    list = loptend;

    const char *argv[3];
    if (to_argv(list, 3, argv) == -1)
        return (EX_USAGE);

    int fd;
    if (str2fd(argv[0], &fd) == -1)
        return (EX_USAGE);

    intmax_t offset;
    if (legal_number(argv[1], &offset) == 0) {
        builtin_usage();
        return (EX_USAGE);
    }

    int whence;
    if (strcmp(argv[2], "SEEK_SET") == 0)
        whence = SEEK_SET;
    else if (strcmp(argv[2], "SEEK_CUR") == 0)
        whence = SEEK_CUR;
    else if (strcmp(argv[2], "SEEK_END") == 0)
        whence = SEEK_CUR;
    else {
        builtin_usage();
        return (EX_USAGE);
    }

    off64_t result = lseek64(fd, offset, whence);
    if (result == (off64_t) -1) {
        perror("lseek64 failed");
        return 1;
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin lseek_struct = {
    "lseek",                    /* builtin name */
    lseek_builtin,              /* function implementing the builtin */
    BUILTIN_ENABLED,            /* initial flags for builtin */
    (char*[]){
        "reposition the file offset of fd to the offset according to the third argument:",
        "",
        "SEEK_SET",
        "    The file offset is set to offset bytes.",
        "",
        "SEEK_CUR",
        "    The file offset is set to its current location plus offset bytes.",
        "",
        "SEEK_END",
        "    The file offset is set to the size of the file plus offset bytes.", 
        "",
        "lseek() allows the file offset to be set beyond the end of the file ",
        "(but this does not change the size of the file).",
        "If data is later written at this point, subsequent reads of the data in the gap ",
        "(a \"hole\") return null bytes ('\0') until data is actually written into the gap.",
        "",
        "NOTE that offset can be negative.",
        (char*) NULL
    },                          /* array of long documentation strings. */
    "lseek <int> fd <off64_t> offset SEEK_SET/SEEK_CUR/SEEK_END",    /* usage synopsis; becomes short_doc */
    0                           /* reserved for internal use */
};

int fexecve_builtin(WORD_LIST *list)
{
    reset_internal_getopt();
    if (no_options(list)) // If options present
        return (EX_USAGE);
    list = loptend;

    if (list == NULL) {
        builtin_usage();
        return (EX_USAGE);
    }

    int fd;
    if (str2fd(list->word->word, &fd) == -1)
        return (EX_USAGE);
    list = list->next;

    int argc = list_length(list);
    if (argc == 0) {
        builtin_usage();
        return (EX_USAGE);
    } else if (argc > sysconf(_SC_ARG_MAX)) {
        fputs("Too many arguments!", stderr);
        return (EX_USAGE);
    }

    {
        // Use varadic array, since the maximum size of 
        // argv is (sizeof 1 / 4 of the stack) + 1.
        char *argv[argc + 1];

        to_argv(list, argc, (const char**) argv);
        argv[argc] = NULL;

        fexecve(fd, argv, environ);
    }

    perror("fexecve failed");
    if (errno == ENOSYS)
        return 128;
    else if (errno == ENOENT)
        return 2;
    else
        return 1;
}
PUBLIC struct builtin fexecve_struct = {
    "fexecve",                  /* builtin name */
    fexecve_builtin,            /* function implementing the builtin */
    BUILTIN_ENABLED,            /* initial flags for builtin */
    (char*[]){
        "fexecve execute file referenced by fd instead of a pathname.",
        "",
        "The file descriptor fd must be opened read-only (O_RDONLY) or with the O_PATH flag ", 
        "and the caller must have permission to execute the file that it refers to.",
        "",
        "NOTE that if fd refers to a script, then close-on-exec flag must not set on fd.",
        "",
        "On error:",
        "",
        "    If fd is invalid, returns 1;",
        "    If close-on-exec flag is set on fd and fd refers to a script, returns 2;",
        "    If kernel does not provide execveat and /proc is inaccessible, returns 128.",
        (char*) NULL
    },                          /* array of long documentation strings. */
    "fexecve <int> fd program_name [args...]",    /* usage synopsis; becomes short_doc */
    0                           /* reserved for internal use */
};

int fd_ops_builtin(WORD_LIST *list)
{
    reset_internal_getopt();

    for (int opt; (opt = internal_getopt(list, "")) != -1; ) {
        switch (opt) {
            CASE_HELPOPT;

        default:
            builtin_usage();
            return (EX_USAGE);
        }
    }
    list = loptend;

    return (EXECUTION_SUCCESS);
}

/**
 * If this function returns 0, the load fails.
 */
PUBLIC int fd_ops_builtin_load (char *name)
{
    return (1);
}

/**
 * Called when `template' is disabled.
 */
PUBLIC void fd_ops_builtin_unload (char *name)
{}
