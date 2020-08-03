/* fd_ops - loadable builtin that defines fd-related functions */

/* See Makefile for compilation details. */
#include "bash/config.h"

#include <unistd.h>
#include "bashansi.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "loadables.h"

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <sys/mman.h>
#include <errno.h>

void int2str(int integer, char buffer[11])
{
    snprintf(buffer, 11, "%d", integer);
}

int memfd_create_builtin (WORD_LIST *list)
{
    reset_internal_getopt();

    unsigned int flags = 0;
    for (int opt; (opt = internal_getopt (list, "C")) != -1; ) {
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

    if (list == 0 || list->next) {
        builtin_usage();
        return (EX_USAGE);
    }
    const char *var = list->word->word;

    int fd = memfd_create(var, flags);
    if (fd == -1) {
        perror("memfd_create failed");
        if (errno == EFAULT || errno == EINVAL)
            return 2;
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
        "On any other error, return EX_SOFTWARE", 
        (char*) NULL
    },                          /* array of long documentation strings. */
    "memfd_create [-C] VAR",    /* usage synopsis; becomes short_doc */
    0                           /* reserved for internal use */
};

int fd_ops_builtin (WORD_LIST *list)
{
    int rval;

    rval = EXECUTION_SUCCESS;
    reset_internal_getopt ();

    for (int opt; (opt = internal_getopt (list, "")) != -1; ) {
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
