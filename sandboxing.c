/* sandboxing - loadable builtin that helps user sandbox applications */

#include "utilities.h"

#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include <sys/prctl.h>

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
