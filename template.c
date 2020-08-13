/* fd_ops - loadable builtin that defines fd-related functions */

#include "bash/config.h"
#include "bashansi.h"
#include "loadables.h"

#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int template_builtin (WORD_LIST *list)
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
PUBLIC struct builtin template_struct = {
    "template",             /* builtin name */
    template_builtin,       /* function implementing the builtin */
    BUILTIN_ENABLED,        /* initial flags for builtin */
    (char*[]){
        "Short description.",
        ""
        "Longer description of builtin and usage.",
        (char *)NULL
    },                      /* array of long documentation strings. */
    "template",             /* usage synopsis; becomes short_doc */
    0                       /* reserved for internal use */
};

/**
 * Called when `template' is enabled and loaded from the shared object.
 *
 * If this function returns 0, the load fails.
 */
PUBLIC int template_builtin_load (char *name)
{
    printf("Hello, world!");
    return (1);
}

/**
 * Called when `template' is disabled.
 */
PUBLIC void template_builtin_unload (name)
     char *name;
{}
