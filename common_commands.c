/* fd_ops - loadable builtin that defines fd-related functions */

#include "utilities.h"

#include <stdio.h>
#include <stdlib.h>

#include <limits.h>

#include <dlfcn.h>

#include <unistd.h>
#include <errno.h>

int realpath_builtin(WORD_LIST *list)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    const char *argv[2];
    int opt_argc = to_argv_opt(list, 1, 1, argv);
    if (opt_argc == -1)
        return (EX_USAGE);

    char *rpath = realpath(argv[0], NULL);

    if (opt_argc == 1)
        bind_variable(argv[1], rpath, 0);
    else
        puts(rpath);

    (free)(rpath);

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin realpath_struct = {
    "realpath",             /* builtin name */
    realpath_builtin,       /* function implementing the builtin */
    BUILTIN_ENABLED,        /* initial flags for builtin */
    (char*[]){
        "realpath expands all symlinks and remove extra '/' to produce canonicalized absolute pathname",
        "",
        "If var is present, the result is stored in $var.",
        "If not, the result is printed to stdout.",
        (char*) NULL
    },                      /* array of long documentation strings. */
    "realpath path [var]",             /* usage synopsis; becomes short_doc */
    0                       /* reserved for internal use */
};

int common_commands_builtin(WORD_LIST *_)
{
    Dl_info info;
    if (dladdr(common_commands_builtin, &info) == 0) {
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

        { .word = "realpath", .flags = 0 },
    };

    const size_t builtin_num = sizeof(words) / sizeof(WORD_DESC);

    WORD_LIST list[builtin_num];
    for (size_t i = 0; i != builtin_num; ++i) {
        list[i].word = &words[i];
        list[i].next = i + 1 != builtin_num ? &list[i + 1] : NULL;
    }

    return enable_builtin(list);
}
PUBLIC struct builtin common_commands_struct = {
    "common_commands",       /* builtin name */
    common_commands_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "enables all builtin defined in this file.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "common_commands",                 /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};
