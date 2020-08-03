/* fd_ops - loadable builtin that defines fd-related functions */

#define _LARGEFILE64_SOURCE

/* See Makefile for compilation details. */
#include "bash/config.h"

#include "bashansi.h"
#include "loadables.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

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
 * @return 0 on success, -1 if not enough/too many arguments.
 */
int to_argv(WORD_LIST *l, int argc, const char *argv[])
{
    for (int i = 0; i != argc; ++i) {
        if (l == NULL) {
            builtin_usage();
            return -1;
        }

        argv[i] = l->word->word;
        l = l->next;
    }

    return l != NULL ? -1 : 0;
}

int memfd_create_builtin (WORD_LIST *list)
{
    reset_internal_getopt();

    unsigned int flags = 0;
    for (int opt; (opt = internal_getopt(list, "C")) != -1; ) {
        switch (opt) {
        case 'C':
            flags |= MFD_CLOEXEC;

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

int fd_ops_builtin(WORD_LIST *list)
{
    int rval;

    rval = EXECUTION_SUCCESS;
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

    return (rval);
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
