/* fd_ops - loadable builtin that defines fd-related functions */

/* See Makefile for compilation details. */
#include "bash/config.h"

#include <unistd.h>
#include "bashansi.h"
#include <stdio.h>
#include <errno.h>

#include "loadables.h"

int memfd_create_builtin (list)
    WORD_LIST *list;
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
PUBLIC struct builtin memfd_create_struct = {
    "memfd_create",             /* builtin name */
    memfd_create_builtin,       /* function implementing the builtin */
    BUILTIN_ENABLED,            /* initial flags for builtin */
    (char*[]){
        "Short description.",
        ""
        "Longer description of builtin and usage.",
        (char *)NULL
    },                          /* array of long documentation strings. */
    "memfd_create",             /* usage synopsis; becomes short_doc */
    0                           /* reserved for internal use */
};

int fd_ops_builtin (list)
    WORD_LIST *list;
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

/* Called when `template' is enabled and loaded from the shared object.  If this
   function returns 0, the load fails. */
PUBLIC int fd_ops_builtin_load (name)
    char *name;
{
    return (1);
}

/* Called when `template' is disabled. */
PUBLIC void fd_ops_builtin_unload (name)
     char *name;
{}
