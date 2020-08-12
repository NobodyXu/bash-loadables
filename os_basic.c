/* fd_ops - loadable builtin that defines fd-related functions */

#define _LARGEFILE64_SOURCE // for lseek64

// For fexecve
#define _POSIX_C_SOURCE 200809L
#define _ATFILE_SOURCE

#define _XOPEN_SOURCE 700 // For fchmod

/* See Makefile for compilation details. */
#include "bash/config.h"

#ifndef  _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include "bashansi.h"
#include "loadables.h"

#include "bash/builtins/builtext.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include <pwd.h>
#include <grp.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>

/**
 * on modern linux kernel, SCM_MAX_FD is equal to 253
 */
#define SCM_MAX_FD 253

#define VLA_MAXLEN (50 * sizeof(void*))

/**
 * START_VLA automatically switched between VLA and malloc.
 *
 * It must be put in a single statement.
 *
 * There can only be one START_VLA and one END_VLA in one scope.
 */
#define START_VLA(type, n, varname)                  \
    type vla[n * sizeof(type) > VLA_MAXLEN ? 0 : n]; \
    if (sizeof(vla) == 0) {                          \
        varname = malloc(n * sizeof(type));          \
        if (varname == NULL) {                       \
            warnx("malloc %zu failed", n * sizeof(type)); \
            return (EXECUTION_FAILURE);              \
        }                                            \
    } else                                           \
        varname = vla

/**
 * START_VLA2 is almost the same as START_VLA except that it 
 * initializes the array to 0.
 */
#define START_VLA2(type, n, varname)                 \
    type vla[n * sizeof(type) > VLA_MAXLEN ? 0 : n]; \
    do {                                             \
        if (sizeof(vla) != 0) {                      \
            varname = vla;                           \
            memset(vla, 0, sizeof(vla));             \
        } else {                                     \
            varname = calloc(n, sizeof(type));       \
            if (varname == NULL) {                   \
                warnx("calloc %zu failed", n * sizeof(type)); \
                return (EXECUTION_FAILURE);          \
            }                                        \
        }                                            \
    } while (0)

/**
 * END_VLA must be put in a single statement.
 */
#define END_VLA(varname)  \
    if (sizeof(vla) == 0) \
        (free)(varname)

#define STR_IMPL_(x) #x      //stringify argument
#define STR(x) STR_IMPL_(x)  //indirection to expand argument macros

static uintmax_t min_unsigned(uintmax_t x, uintmax_t y)
{
    return x > y ? y : x;
}

/**
 * @param str must not be null
 * @param integer must be a valid pointer.
 *                If str2int failed, its value is unchanged.
 * @return 0 on success, -1 if not integer, -2 if out of range.
 *
 * NOTE that this function does not call builtin_usage on error.
 */
int str2int(const char *str, int *integer)
{
    intmax_t result;
    if (legal_number(str, &result) == 0) {
        return -1;
    } else if (result > INT_MAX || result < INT_MIN)
        return -2;
 
    *integer = result;
    return 0;
}

/**
 * @param str must not be null
 * @param integer must be a valid pointer.
 *                If str2uint failed, its value is unchanged.
 * @return 0 on success, -1 if not integer, -2 if too large.
 *
 * NOTE that this function does not call builtin_usage on error.
 */
int str2uint(const char *str, unsigned *integer)
{
    intmax_t result;
    if (legal_number(str, &result) == 0)
        return -1;
    else if (result > UINT_MAX || result < 0)
        return -2;
 
    *integer = result;
    return 0;
}

/**
 * @param str must not be null
 * @param integer must be a valid pointer.
 *                If str2uint32 failed, its value is unchanged.
 * @return 0 on success, -1 if not integer, -2 if too large.
 *
 * NOTE that this function does not call builtin_usage on error.
 */
int str2uint32(const char *str, uint32_t *integer)
{
    intmax_t result;
    if (legal_number(str, &result) == 0)
        return -1;
    else if (result > UINT32_MAX || result < 0)
        return -2;
 
    *integer = result;
    return 0;
}

/**
 * @param str must not be null
 * @param integer must be a valid pointer.
 *                If str2pint failed, its value is unchanged.
 * @return 0 on success, -1 if not integer, -2 if out or range.
 *
 * convert str to positive int.
 *
 * NOTE that this function does not call builtin_usage on error.
 */
int str2pint(const char *str, int *integer)
{
    int result = str2int(str, integer);
    if (result < 0)
        return result;
    if (*integer < 0)
        return -2;
    return 0;
}

/**
 * @param str must not be null
 * @param fd must be a valid pointer.
 *           If str2fd failed, its value is unchanged.
 * @return 0 on success, -1 if not enough/too many arguments.
 */
int str2fd(const char *str, int *fd)
{
    int result = str2pint(str, fd);
    if (result == -1) {
        builtin_usage();
        return -1;
    } else if (result == -2) {
        warnx("Input fd too large!");
        return -1;
    }
    return 0;
}

/**
 * @param str must not be null
 * @param mode must be a valid pointer.
 *             If str2fd failed, its value is unchanged.
 * @return 0 on success, -1 if not enough/too many arguments.
 */
int str2mode(const char *str, mode_t *mode)
{
    intmax_t result;
    if (legal_number(str, &result) == 0) {
        builtin_usage();
        return -1;
    } else if (result < 0 || result > (S_ISUID | S_IRWXU | S_IRWXG | S_IRWXO)) {
        warnx("Input mode too large!");
        return -1;
    }
 
    *mode = result;

    return 0;
}

/**
 * @return number of args read in.
 */
int readin_args(WORD_LIST **l, int argc, const char *argv[])
{
    int i = 0;
    for (; i != argc && (*l) != NULL; ++i) {
        argv[i] = (*l)->word->word;
        (*l) = (*l)->next;
    }
    return i;
}

/**
 * @return number of optional arg read in on success, -1 if not enough/too many arguments.
 */
int to_argv_opt(WORD_LIST *l, int argc, int opt_argc, const char *argv[])
{
    if (readin_args(&l, argc, argv) < argc) {
        builtin_usage();
        return -1;
    }

    int i = readin_args(&l, opt_argc, argv + argc);
    if (l != NULL) {
        builtin_usage();
        return -1;
    }
    return i;
}
/**
 * @return 0 on success, -1 if not enough/too many arguments.
 */
int to_argv(WORD_LIST *l, int argc, const char *argv[])
{
    return to_argv_opt(l, argc, 0, argv);
}

/**
 * @return -1 if failed, 0 if succeeds.
 *
 * This function call will also reset_internal_getopt and set list = loptend
 * for you.
 */
int check_no_options(WORD_LIST **list)
{
    reset_internal_getopt();
    if (no_options(*list)) // If options present
        return -1;
    *list = loptend;
    return 0;
}

int readin_fd(WORD_LIST **list, int *fd)
{
    if (*list == NULL) {
        builtin_usage();
        return -1;
    }

    if (str2fd((*list)->word->word, fd) == -1)
        return -1;
    *list = (*list)->next;

    return 0;
}

/**
 * @return NULL on error, otherwise ret value of get_f(name).
 * helper function for retrieving struct passwd* or struct group*.
 */
void* get_pg_impl(void* (*get_f)(const char*), const char *name, 
                  const char *function_name, const char *type /* meta info for printing on error */)
{
    void *ret;
    do {
        errno = 0;
        ret = get_f(name);
    } while (ret == NULL && errno == EINTR);

    if (ret == NULL) {
        if (errno != 0)
            warn("%s(%s) failed!", function_name, name);
        else
            fprintf(stderr, "%s %s not found!\n", type, name);
    }

    return ret;
}
int parse_id_impl(unsigned *id, const char *name, void* (*get_f)(const char*), size_t offset, 
                  /* meta info for printing on error */
                  const char *function_name, const char *name_type, const char *id_type)
{
    if (strcmp(name, "-1") == 0) {
        *id = -1;
        return 0;
    }

    int result = str2uint32(name, id);
    if (result == -1) {
        char *ret = get_pg_impl(get_f, name, function_name, name_type);

        if (ret)
            *id = *((unsigned*) (ret + offset));
        else
            return -1;
    } else if (result == -2) {
        fprintf(stderr, "Input %s is too large!", id_type);
        return -1;
    }

    return 0;
}
#define parse_id(id, name, get_f, offset) \
    parse_id_impl(id, name, (void* (*)(const char*)) get_f, offset, # get_f, # name, # id)

/**
 * @param uid != NULL, only modified on success.
 * @param user != NULL
 * @return -1 on error, 0 otherwise.
 */
int parse_user(uid_t *uid, const char *user)
{
    _Static_assert(sizeof(uid_t) == sizeof(uint32_t), "not supported!");
    _Static_assert((uid_t) -1 > 0, "not supported!");

    return parse_id(uid, user, getpwnam, offsetof(struct passwd, pw_uid));
}

/**
 * @param gid != NULL, only modified on success
 * @param group != NULL
 * @return -1 on error, 0 on success.
 */
int parse_group(gid_t *gid, const char *group)
{
    _Static_assert(sizeof(gid_t) == sizeof(uint32_t), "not supported!");
    _Static_assert((gid_t) -1 > 0, "not supported!");

    return parse_id(gid, group, getgrnam, offsetof(struct group, gr_gid));
}

/**
 * @param arg != NULL, in the form of ':', 'uid' or 'uid:' or 'uid:gid' or ':gid'.
 * @param uid, gid will be filled with uid, gid specified in arg.
 *                 If uid/gid is ignored, it will be set to -1 (unchanged).
 *
 * @return -1 on err, 0 if succeeds.
 *
 * parse uid and gid
 */
int parse_ids(const char *arg, uid_t *uid, gid_t *gid)
{
    char *delimiter = strchr(arg, ':');

    if (delimiter == NULL) {
        if (parse_user(uid, arg) == -1)
            return -1;
        *gid = -1;
        return 0;
    } else if (delimiter == arg) {
        *uid = -1;
    } else {
        size_t size = delimiter - arg;

        if (size > sysconf(_SC_LOGIN_NAME_MAX)) {
            warnx("username too long!");
            return -1;
        }

        char name[size + 1];
        strncpy(name, arg, size);
        name[size] = '\0';

        if (parse_user(uid, name) == -1)
            return -1;
    }

    char *group = delimiter + 1;

    if (*group != '\0') {
        if (parse_group(gid, group) == -1)
            return -1;
    } else
        *gid = -1;

    return 0;
}

#define STR_IMPL_(x) #x      //stringify argument
#define STR(x) STR_IMPL_(x)  //indirection to expand argument macros

int create_memfd_builtin(WORD_LIST *list)
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
        warn("memfd_create failed");
        if (errno == EFAULT || errno == EINVAL)
            return 100;
        else
            return 1;
    }

    bind_var_to_int((char*) var, fd);

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin create_memfd_struct = {
    "create_memfd",             /* builtin name */
    create_memfd_builtin,       /* function implementing the builtin */
    BUILTIN_ENABLED,            /* initial flags for builtin */
    (char*[]){
        "Create an anonymous file in RAM and store its fd in variable $VAR.",
        "NOTE that if swap is enabled, this anonymous can be swapped onto disk.",
        "",
        "Pass -C to enable CLOEXEC.",
        "",
        "On error:",
        "    On resource exhaustion, return 1.",
        "    On any other error, return 100", 
        (char*) NULL
    },                          /* array of long documentation strings. */
    "create_memfd [-C] VAR",    /* usage synopsis; becomes short_doc */
    0                           /* reserved for internal use */
};

int create_tmpfile_builtin(WORD_LIST *list)
{
    reset_internal_getopt();

    int flags = O_TMPFILE;
    for (int opt; (opt = internal_getopt(list, "CE")) != -1; ) {
        switch (opt) {
        case 'C':
            flags |= O_CLOEXEC;
            break;

        case 'E':
            flags |= O_EXCL;
            break;

        CASE_HELPOPT;

        default:
            builtin_usage();
            return (EX_USAGE);
        }
    }
    list = loptend;

    const char *argv[4];
    int opt_argc = to_argv_opt(list, 3, 1, argv);
    if (opt_argc == -1)
        return (EX_USAGE);

    if (strcasecmp(argv[2], "rw") == 0)
        flags |= O_RDWR;
    else if (strcasecmp(argv[2], "w") == 0)
        flags |= O_WRONLY;
    else {
        builtin_usage();
        return (EX_USAGE);
    }

    mode_t mode;
    if (opt_argc == 1) {
        if (str2mode(argv[3], &mode) == -1)
            return (EX_USAGE);
    } else
        mode = S_IRUSR | S_IWUSR;

    int fd;
    do {
        fd = open(argv[1], flags, mode);
    } while (fd == -1 && errno == EINTR);

    if (fd == -1) {
        warn("open failed");
        if (errno == EISDIR)
            return 128;
        else if (errno == EOPNOTSUPP)
            return 129;
        else
            return 1;
    }

    bind_var_to_int((char*) argv[0], fd);

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin create_tmpfile_struct = {
    "create_tmpfile",             /* builtin name */
    create_tmpfile_builtin,       /* function implementing the builtin */
    BUILTIN_ENABLED,              /* initial flags for builtin */
    (char*[]){
        "Create an unnamed tempoary regular file in /path/to/dir and store its fd in variable $VAR.",
        "An unnamed inode will be created in that directory's filesystem.",
        "Anything written to the resulting file will be lost when the last file descriptor is closed, ", 
        "unless the file is given a name.",
        "",
        "Pass '-C' to set close-on-exec flag on fd.",
        "Pass '-E' to disable linking this fd to an actual name.",
        "",
        "The 3rd arg, rw/w is case insensitive.",
        "The 4th arg mode is optional. It is default to be 700",
        "",
        "On error:",
        "    If this kernel does not support O_TMPFILE, returns 128;",
        "    If this filesystem does not support O_TMPFILE, returns 129;",
        "    On any other error, return 1", 
        (char*) NULL
    },                          /* array of long documentation strings. */
    "create_tmpfile [-CE] VAR /path/to/dir rw/w [mode]",
    0                           /* reserved for internal use */
};

int lseek_builtin(WORD_LIST *list)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

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
    if (strcasecmp(argv[2], "SEEK_SET") == 0)
        whence = SEEK_SET;
    else if (strcasecmp(argv[2], "SEEK_CUR") == 0)
        whence = SEEK_CUR;
    else if (strcasecmp(argv[2], "SEEK_END") == 0)
        whence = SEEK_CUR;
    else {
        builtin_usage();
        return (EX_USAGE);
    }

    off64_t result = lseek64(fd, offset, whence);
    if (result == (off64_t) -1) {
        warn("lseek64 failed");
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
        "SEEK_SET (case insensitive)",
        "    The file offset is set to offset bytes.",
        "",
        "SEEK_CUR (case insensitive)",
        "    The file offset is set to its current location plus offset bytes.",
        "",
        "SEEK_END (case insensitive)",
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
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    int fd;
    if (readin_fd(&list, &fd) == -1)
        return (EX_USAGE);

    if (list == NULL) {
        builtin_usage();
        return (EX_USAGE);
    }

    int argc = list_length(list);
    if (argc > sysconf(_SC_ARG_MAX)) {
        warnx("Too many arguments!");
        return (EX_USAGE);
    }

    {
        char **argv;
        START_VLA(char*, argc + 1, argv);

        to_argv(list, argc, (const char**) argv);
        argv[argc] = NULL;

        fexecve(fd, argv, environ);

        END_VLA(argv);
    }

    warn("fexecve failed");
    if (errno == ENOSYS)
        return 128;
    else if (errno == ENOENT)
        return 3;
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
        "    If close-on-exec flag is set on fd and fd refers to a script, returns 3;",
        "    If kernel does not provide execveat and /proc is inaccessible, returns 128.",
        (char*) NULL
    },                          /* array of long documentation strings. */
    "fexecve <int> fd program_name [args...]",    /* usage synopsis; becomes short_doc */
    0                           /* reserved for internal use */
};

int flink_builtin(WORD_LIST *list)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    const char *argv[2];
    if (to_argv(list, 2, argv) == -1)
        return (EX_USAGE);

    int fd;
    if (str2fd(argv[0], &fd) == -1)
        return (EX_USAGE);
    const char *newpath = argv[1];

    int result = linkat(fd, "", AT_FDCWD, newpath, AT_EMPTY_PATH);
    if (result == -1) {
        if (errno == EINVAL) {
            warn("flink not supported on this kernel");
            return 128;
        } else {
            warn("linkat failed");
            return 1;
        }
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin flink_struct = {
    "flink",                    /* builtin name */
    flink_builtin,              /* function implementing the builtin */
    BUILTIN_ENABLED,            /* initial flags for builtin */
    (char*[]){
        "flink can be used to create a hard link to a fd whose count of inode isn't zero or",
        "a tempfile created by create_tmpfile without -E option.",
        "",
        "NOTE that this builtin requires CAP_DAC_READ_SEARCH capability.",
        "",
        "If you do not have CAP_DAC_READ_SEARCH, then you should consider ",
        "using linking /proc if it is accessible.",
        "",
        "On error:",
        "",
        "    If flink is not supported on this kernel, returns 128;",
        "    Otherwise, returns 128.",
        (char*) NULL
    },                          /* array of long documentation strings. */
    "flink <int> fd path",      /* usage synopsis; becomes short_doc */
    0                           /* reserved for internal use */
};

int fchmod_builtin(WORD_LIST *list)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    const char *argv[2];
    if (to_argv(list, 2, argv) == -1)
        return (EX_USAGE);

    int fd;
    if (str2fd(argv[0], &fd) == -1)
        return (EX_USAGE);

    mode_t mode;
    if (str2mode(argv[1], &mode) == -1)
        return (EX_USAGE);

    int result;
    do {
        result = fchmod(fd, mode);
    } while (result == -1 && errno == EINTR);
    if (result == -1) {
        warn("fchmod failed");
        return 1;
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin fchmod_struct = {
    "fchmod",                    /* builtin name */
    fchmod_builtin,              /* function implementing the builtin */
    BUILTIN_ENABLED,             /* initial flags for builtin */
    (char*[]){
        "fchmod changes mode regarding the fd",
        (char*) NULL
    },                          /* array of long documentation strings. */
    "flink <int> fd mode",      /* usage synopsis; becomes short_doc */
    0                           /* reserved for internal use */
};

int fchown_builtin(WORD_LIST *list)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    const char *argv[2];
    if (to_argv(list, 2, argv) == -1)
        return (EX_USAGE);

    int fd;
    if (str2fd(argv[0], &fd) == -1)
        return (EX_USAGE);

    uid_t uid;
    gid_t gid;
    if (parse_ids(argv[1], &uid, &gid) == -1)
        return 1;

    int result;
    do {
        result = fchown(fd, uid, gid);
    } while (result == -1 && errno == EINTR);
    if (result == -1) {
        warn("fchmod failed");
        return 1;
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin fchown_struct = {
    "fchown",                    /* builtin name */
    fchown_builtin,              /* function implementing the builtin */
    BUILTIN_ENABLED,             /* initial flags for builtin */
    (char*[]){
        "fchown changes group and owner regarding the fd",
        "",
        "The second arg can take the form of ':', 'uid/username', 'uid/username:', ",
        "'uid/username:gid/groupname', ':gid/groupname'.",
        "In other words, uid/username and gid/groupname can be omitted if you don't want to",
        "change them.",
        "",
        "If -1 is passed, then the correspond id is not changed.",
        "",
        "NOTE that uid/gid can be arbitary number permitted by the system.",
        "",
        "Only a privileged process (Linux: one with the CAP_CHOWN capability) may change the owner of a file. ",
        "The owner of a file may change the group of the file to any group of which that owner is a member. ", 
        "A privileged process (Linux: with CAP_CHOWN) may change the group arbitrarily.",
        "",
        "When the owner or group of an executable file is changed by an unprivileged user, ", 
        "the S_ISUID and S_ISGID mode bits are cleared. ",
        "POSIX does not specify whether this also should happen when root does the chown(); ",
        "the Linux behavior depends on the kernel version, and since Linux 2.2.13, ", 
        "root is treated like other users. ",
        "In case of a non-group-executable file the S_ISGID bit indicates mandatory locking, ",
        "and is not cleared by a chown().", 
        "",
        "When the owner or group of an executable file is changed (by any user), ",
        "all capability sets for the file are cleared.",
        (char*) NULL
    },                          /* array of long documentation strings. */
    "fchown <int> fd uid/username:gid/groupname",      /* usage synopsis; becomes short_doc */
    0                           /* reserved for internal use */
};

int getresid_impl(WORD_LIST *list, int (*getter)(uint32_t*, uint32_t*, uint32_t*))
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    const char *argv[3];
    if (to_argv(list, 3, argv) == -1)
        return (EX_USAGE);

    uint32_t ids[3];
    getter(ids, ids + 1, ids + 2);

    for (int i = 0; i != 3; ++i)
        bind_var_to_int((char*) argv[i], ids[i]);

    return (EXECUTION_SUCCESS);
}
int getresuid_builtin(WORD_LIST *list)
{
    _Static_assert(sizeof(uid_t) == sizeof(uint32_t), "not supported!");
    _Static_assert((uid_t) -1 > 0, "not supported!");

    return getresid_impl(list, getresuid);
}
int getresgid_builtin(WORD_LIST *list)
{
    _Static_assert(sizeof(gid_t) == sizeof(uint32_t), "not supported!");
    _Static_assert((gid_t) -1 > 0, "not supported!");

    return getresid_impl(list, getresgid);
}
PUBLIC struct builtin getresuid_struct = {
    "getresuid",                 /* builtin name */
    getresuid_builtin,              /* function implementing the builtin */
    BUILTIN_ENABLED,             /* initial flags for builtin */
    (char*[]){
        "get real uid, effective uid and saved uid stored in var1, var2 and var3 respectively.",
        (char*) NULL
    },                          /* array of long documentation strings. */
    "getresuid var1 var2 var3",      /* usage synopsis; becomes short_doc */
    0                           /* reserved for internal use */
};
PUBLIC struct builtin getresgid_struct = {
    "getresgid",                 /* builtin name */
    getresgid_builtin,              /* function implementing the builtin */
    BUILTIN_ENABLED,             /* initial flags for builtin */
    (char*[]){
        "get real gid, effective gid and saved gid stored in var1, var2 and var3 respectively.",
        (char*) NULL
    },                          /* array of long documentation strings. */
    "getresgid var1 var2 var3",      /* usage synopsis; becomes short_doc */
    0                           /* reserved for internal use */
};

int setresid_impl(WORD_LIST *list, int (*setter)(uint32_t, uint32_t, uint32_t), const char *function_name, 
                  int (*parser)(uint32_t*, const char*))
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    const char *argv[3];
    if (to_argv(list, 3, argv) == -1)
        return (EX_USAGE);

    uint32_t ids[3];
    for (int i = 0; i != 3; ++i)
        parser(ids + i, argv[i]);

    int result = setter(ids[0], ids[1], ids[2]);
    if (result == -1) {
        warn("%s failed", function_name);
        if (errno == EAGAIN)
            return 1;
        else
            return 3;
    }

    return (EXECUTION_SUCCESS);
}
int setresuid_builtin(WORD_LIST *list)
{
    _Static_assert(sizeof(uid_t) == sizeof(uint32_t), "not supported!");
    _Static_assert((uid_t) -1 > 0, "not supported!");

    return setresid_impl(list, setresuid, "setresuid", parse_user);
}
int setresgid_builtin(WORD_LIST *list)
{
    _Static_assert(sizeof(gid_t) == sizeof(uint32_t), "not supported!");
    _Static_assert((gid_t) -1 > 0, "not supported!");

    return setresid_impl(list, setresgid, "setresgid", parse_group);
}
PUBLIC struct builtin setresuid_struct = {
    "setresuid",                 /* builtin name */
    setresuid_builtin,              /* function implementing the builtin */
    BUILTIN_ENABLED,             /* initial flags for builtin */
    (char*[]){
        "set real uid/username, effective uid/username and saved uid/username ",
        "according to stored in var1, var2 and var3 respectively.",
        "",
        "Pass -1 then the corresponding value is not changed.",
        "",
        "Note: there are cases where it can fail even when the caller is UID 0; ",
        "it is a grave security error to omit checking for a failure return from setresuid().",
        "",
        "On error:",
        "    If there's a temporary failure allocating necessry kernel dat structures or ",
        "    RLIMIT_NPROC resource limit is reached, returns 1.",
        "    ",
        "    If at least one of the ID is not valid in this user namespace or the operation is not",
        "    permitted (lacks CAP_SETUID or CAP_SETGID), returns 3.",
        (char*) NULL
    },                          /* array of long documentation strings. */
    "setresuid var1 var2 var3",      /* usage synopsis; becomes short_doc */
    0                           /* reserved for internal use */
};
PUBLIC struct builtin setresgid_struct = {
    "setresgid",                 /* builtin name */
    setresgid_builtin,              /* function implementing the builtin */
    BUILTIN_ENABLED,             /* initial flags for builtin */
    (char*[]){
        "set real gid/groupname, effective gid/groupname and saved gid/groupname ",
        "according to stored in var1, var2 and var3 respectively.",
        "",
        "Pass -1 then the corresponding value is not changed.",
        "",
        "Note: there are cases where it can fail even when the caller is UID 0; ",
        "it is a grave security error to omit checking for a failure return from setresuid().",
        "",
        "On error:",
        "    If there's a temporary failure allocating necessry kernel dat structures or ",
        "    RLIMIT_NPROC resource limit is reached, returns 1.",
        "    ",
        "    If at least one of the ID is not valid in this user namespace or the operation is not",
        "    permitted (lacks CAP_SETUID or CAP_SETGID), returns 2.",
        (char*) NULL
    },                          /* array of long documentation strings. */
    "getresgid var1 var2 var3",      /* usage synopsis; becomes short_doc */
    0                           /* reserved for internal use */
};

int get_supplementary_groups_builtin(WORD_LIST *list)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    const char *varname;
    if (to_argv(list, 1, &varname) == -1)
        return (EX_USAGE);

    int result;
    do {
        int ngids = getgroups(0, NULL);

        gid_t *gids;
        START_VLA(gid_t, ngids, gids);

        result = getgroups(ngids, gids);
        if (result == ngids) {
            SHELL_VAR *var = make_new_array_variable((char*) varname);
            ARRAY *array = array_cell(var);

            _Static_assert(sizeof(gid_t) == sizeof(uint32_t), "not supported!");
            _Static_assert((gid_t) -1 > 0, "not supported!");

            char buffer[sizeof(STR(UINT_MAX))];
            for (int i = 0; i != ngids; ++i) {
                snprintf(buffer, sizeof(buffer), "%zu", (size_t) gids[i]);

                array_insert(array, i, buffer);
            }
        }

        END_VLA(gids);
    } while (result == -1 && errno == EINVAL);

    if (result == -1) {
        warn("getgroups failed");
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin get_supplementary_groups_struct = {
    "get_supplementary_groups",                 /* builtin name */
    get_supplementary_groups_builtin,              /* function implementing the builtin */
    BUILTIN_ENABLED,             /* initial flags for builtin */
    (char*[]){
        "get_supplementary_groups will store gid of supplementary groups into varname as array",
        "",
        "It is unspecified whether the effective gid of the calling process is included.",
        "Thus, an application should also call getresgid for effective gid.",
        (char*) NULL
    },                          /* array of long documentation strings. */
    "get_supplementary_groups varname",      /* usage synopsis; becomes short_doc */
    0                           /* reserved for internal use */
};

int set_supplementary_groups_builtin_impl(int ngids, gid_t *gids, WORD_LIST *list)
{
    for (int i = 0; i != ngids; ++i, list = list->next)
        if (parse_group(gids + i, list->word->word) == -1)
            return (EXECUTION_FAILURE);

    if (ngids == 0)
        gids = NULL;

    if (setgroups(ngids, gids) == -1) {
        warn("setgroups failed");
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
int set_supplementary_groups_builtin(WORD_LIST *list)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    int ngids = list_length(list);
    if (ngids > NGROUPS_MAX) {
        warnx("set_supplementary_groups: Too many supplementary groups specified!");
        return (EXECUTION_FAILURE);
    }

    gid_t *gids;
    START_VLA(gid_t, ngids, gids);

    int ret = set_supplementary_groups_builtin_impl(ngids, gids, list);

    END_VLA(gids);

    return ret;
}
PUBLIC struct builtin set_supplementary_groups_struct = {
    "set_supplementary_groups",                 /* builtin name */
    set_supplementary_groups_builtin,              /* function implementing the builtin */
    BUILTIN_ENABLED,             /* initial flags for builtin */
    (char*[]){
        "set_supplementary_groups set the supplementary groups of the process.",
        "Number of groups specified must be <= NGROUPS_MAX (32 before Linux 2.6.4; 65536 since Linux 2.6.4).",
        "",
        "To use this builtin, calling process must have CAP_SETGID in the user namespace it resides",
        "and $(cat /proc/self/setgroups) = \"allow\".",
        (char*) NULL
    },                          /* array of long documentation strings. */
    "set_supplementary_groups gid/group ...",      /* usage synopsis; becomes short_doc */
    0                           /* reserved for internal use */
};

int create_unixsocketpair_builtin(WORD_LIST *list)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    const char *argv[3];
    if (to_argv(list, 3, argv) == -1)
        return (EX_USAGE);

    int type;
    if (strcasecmp(argv[0], "stream") == 0)
        type = SOCK_STREAM;
    else if (strcasecmp(argv[0], "dgram") == 0)
        type = SOCK_DGRAM;
    else {
        builtin_usage();
        return (EX_USAGE);
    }

    int socketfds[2];
    if (socketpair(AF_UNIX, type, 0, socketfds) == -1)
        return 1;

    for (int i = 0; i != 2; ++i)
        bind_var_to_int((char*) argv[i + 1], socketfds[i]);

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin create_unixsocketpair_struct = {
    "create_unixsocketpair",       /* builtin name */
    create_unixsocketpair_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "create_unixsocketpair creates a connected unix socket pair.",
        "",
        "The 1st argument is case insensitive.",
        "If \"dgram\" is passed, then the socket will preserve message boundaries",
        "If not, then it is not guaranteed to preserve message boundaries.",
        "",
        "The fds of two ends will be stored in var1 and var2. They both can be used to receive and send",
        "over the socket.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "create_unixsocketpair stream/dgram var1 var2",      /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

int fdputs_builtin(WORD_LIST *list)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    const char *argv[2];
    if (to_argv(list, 2, argv) == -1)
        return (EX_USAGE);

    int fd;
    if (str2fd(argv[0], &fd) == -1)
        return (EX_USAGE);

    size_t size = strlen(argv[1]);

    ssize_t result;
    for (size_t i = 0; i != size; ) {
        result = write(fd, argv[1] + i, min_unsigned(size - i, SSIZE_MAX));
        if (result == -1) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 10;

            warn("write failed");
            return 1;
        }
 
        i += result;
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin fdputs_struct = {
    "fdputs",       /* builtin name */
    fdputs_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "fdputs write msg to fd without newline.",
        "To use ascii escapes, try fdputs $'hello, world!\n'",
        "",
        "If the operation would block, returns 10.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "fdputs <int> fd msg",      /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

int readv_wrapper(int fd, int iovcnt, struct iovec *iov, size_t total_len)
{
    if (total_len > SSIZE_MAX) {
        warnx("fdecho: total_len of input %zu is greater than SSIZE_MAX", total_len);
        return (EXECUTION_FAILURE);
    }

    for (; ;) {
        ssize_t ret = writev(fd, iov, iovcnt);
        if (ret == -1) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 10;
            warn("writev(%d, %p, %d) failed", fd, iov, iovcnt);
            return (EXECUTION_FAILURE);
        }

        for (; iov->iov_len <= ret; ++iov, --iovcnt)
            ret -= iov->iov_len;

        if (iovcnt == 0)
            break;

        iov->iov_base += ret;
        iov->iov_len -= ret;
    }

    return (EXECUTION_SUCCESS);
}
int fdecho_builtin(WORD_LIST *list)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    int fd;
    if (readin_fd(&list, &fd) == -1)
        return (EX_USAGE);

    if (list == NULL)
        return (EXECUTION_SUCCESS);
    int argc = list_length(list);

    struct iovec *buffer;
    START_VLA(struct iovec, argc, buffer);

    size_t total_len = 0;
    for (size_t i = 0; i != argc; ++i, list = list->next) {
        buffer[i].iov_base = list->word->word;
        buffer[i].iov_len = strlen(buffer[i].iov_base);

        total_len += buffer[i].iov_len;
    }

    int ret = readv_wrapper(fd, argc, buffer, total_len);

    END_VLA(buffer);

    return ret;
}
PUBLIC struct builtin fdecho_struct = {
    "fdecho",       /* builtin name */
    fdecho_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "fdecho write msgs to fd without newline.",
        "To use ascii escapes, try fdecho $'hello, world!\n\' $'thello'",
        "",
        "If the operation would block, returns 10.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "fdecho <int> fd msgs ...",      /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

int sendfds_builtin_impl(int socketfd, int fd_cnt, const struct msghdr *msg, int flags, WORD_LIST *list)
{
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * fd_cnt);

    int *cmsg_data = (int*) CMSG_DATA(cmsg);
    for (int i = 0; i != fd_cnt; ++i, list = list->next) {
        int fd;
        if (str2fd(list->word->word, &fd) == -1)
            return (EX_USAGE);

        memcpy(cmsg_data + i, &fd, sizeof(int));
    }

    ssize_t result;
    do {
        result = sendmsg(socketfd, msg, flags);
    } while (result == -1 && errno == EINTR);

    if (result == -1) {
        warn("sendmsg failed");
        return (EXECUTION_FAILURE);
    } else if (result == 0) {
        warnx("sendmsg returns 0!");
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
int sendfds_builtin(WORD_LIST *list)
{
    int flags = 0;

    reset_internal_getopt();
    for (int opt; (opt = internal_getopt(list, "N")) != -1; ) {
        switch (opt) {
        case 'N':
            flags |= MSG_NOSIGNAL;
            break;

        CASE_HELPOPT;

        default:
            builtin_usage();
            return (EX_USAGE);
        }
    }
    list = loptend;

    int socketfd;
    if (readin_fd(&list, &socketfd) == -1)
        return (EX_USAGE);

    int fd_cnt = list_length(list);
    if (fd_cnt > SCM_MAX_FD /* at most SCM_MAX_FD fds can be sent */) {
        warnx("Too many arguments!");
        return (EX_USAGE);
    }

    char *buffer;
    START_VLA2(char, CMSG_SPACE(sizeof(int) * fd_cnt), buffer);

    struct iovec iov = {
        .iov_base = "\0",
        .iov_len = 1
    };
    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,

        .msg_iov = &iov,
        .msg_iovlen = 1,

        .msg_control = buffer,
        .msg_controllen = CMSG_SPACE(sizeof(int) * fd_cnt)
    };
    int ret = sendfds_builtin_impl(socketfd, fd_cnt, &msg, flags, list);
    END_VLA(buffer);

    return ret;
}
PUBLIC struct builtin sendfds_struct = {
    "sendfds",       /* builtin name */
    sendfds_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "sendfds send file descripter over unix socket.",
        "The other end must use recvfds to receive the fds.",
        "",
        "If '-N' is specified, then SIGPIPE won't be generated if the peer of a stream-oriented unix socket",
        "has closed the connection.",
        "",
        "NOTE that at most 253 fds is accepted at once.",
        "",
        "Implemention detail:",
        "    Since fds is required to be sent with an actual message, sendfds actually sends \"\0\"",
        "    along with the cmsg.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "sendfds [-N] <int> fd_of_unix_socket fd1 [fds...]",      /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

int recvfds_builtin_impl(int socketfd, struct msghdr *msg, int flags, char *varname)
{
    ssize_t result;
    do {
        result = recvmsg(socketfd, msg, flags);
    } while (result == -1 && errno == EINTR);

    if (result == -1) {
        warn("recvmsg failed");
        return 1;
    } else if (result == 0) {
        warnx("recvmsg returns 0!");
        return 5;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);
    
    if (cmsg == NULL) {
        warnx("No cmsg is received");
        return 4;
    }

    if (!(cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)) {
        warnx("Unexpected: received cmsg isn't the type that contains fds");
        return 3;
    }

    SHELL_VAR *var = make_new_array_variable(varname);
    ARRAY *array = array_cell(var);

    int nfd_readin = (cmsg->cmsg_len - CMSG_ALIGN(sizeof(struct cmsghdr))) / sizeof(int);
    int *cmsg_data = (int*) CMSG_DATA(cmsg);

    int fd;
    for (size_t i = 0; i != nfd_readin; ++i) {
        memcpy(&fd, cmsg_data + i, sizeof(int));

        char buffer[sizeof(STR(INT_MAX))];
        snprintf(buffer, sizeof(buffer), "%d", fd);

        array_insert(array, i, buffer);
    }

    return (EXECUTION_SUCCESS);
}
int recvfds_builtin(WORD_LIST *list)
{
    int flags = 0;

    reset_internal_getopt();
    for (int opt; (opt = internal_getopt(list, "C")) != -1; ) {
        switch (opt) {
        case 'C':
            flags |= MSG_CMSG_CLOEXEC;
            break;

        CASE_HELPOPT;

        default:
            builtin_usage();
            return (EX_USAGE);
        }
    }
    list = loptend;

    const char* argv[3];
    if (to_argv(list, 3, argv) == -1)
        return (EX_USAGE);

    int socketfd;
    if (str2fd(argv[0], &socketfd) == -1)
        return (EX_USAGE);

    unsigned fd_cnt;
    switch (str2uint32(argv[1], &fd_cnt)) {
        case -1:
            builtin_usage();
            return (EX_USAGE);

        case 0:
            if (fd_cnt <= SCM_MAX_FD)
                break;

        case -2:
            warnx("nfd is too large!");
            return (EX_USAGE);
    }

    char *buffer;
    START_VLA(char, CMSG_SPACE(sizeof(int) * fd_cnt), buffer);

    char recvbuf[1];
    struct iovec iov = {
        .iov_base = recvbuf,
        .iov_len = 1
    };
    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,

        .msg_iov = &iov,
        .msg_iovlen = 1,

        .msg_control = buffer,
        .msg_controllen = CMSG_SPACE(sizeof(int) * fd_cnt)
    };

    recvfds_builtin_impl(socketfd, &msg, flags, (char*) argv[2]);
    END_VLA(buffer);

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin recvfds_struct = {
    "recvfds",       /* builtin name */
    recvfds_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "recvfds receive nfd of fd sent by sendfds into var in the form of array.",
        "If nfd is less than number of fds sent by sendfds or accepting them will cause the process to ",
        "exceed its RLIMIT_NOFILE resource limit, then the rest of them",
        "will be discarded and closed.",
        "",
        "If '-C' is specified, then the received fds will be marked close-on-exec.",
        "",
        "NOTE that at most 253 fds can be received at once.",
        "",
        "On error:",
        "    If no cmsg is received, returns 4;",
        "    If the cmsg received isn't the type that contains fds, returns 3.",
        "",
        "Implemention detail:",
        "    recvfds would consume one byte from the unix socket and the fds associated with this byte, ",
        "    due to the reason described in sendfds' documentation.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "recvfds [-C] <int> fd_of_unix_socket nfd var",      /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

int pause_builtin(WORD_LIST *list)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    if (list != NULL) {
        builtin_usage();
        return (EX_USAGE);
    }

    pause();

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin pause_struct = {
    "pause",       /* builtin name */
    pause_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "pause causes the process (or thread) to sleep until a signal is delivered ",
        "that either terminates the process or causes the invocation of a signal-catching function.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "pause",      /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

int sleep_builtin(WORD_LIST *list)
{
    reset_internal_getopt();

    int restart_on_signal = 0;
    for (int opt; (opt = internal_getopt(list, "R")) != -1; ) {
        switch (opt) {
        case 'R':
            restart_on_signal = 1;
            break;

        CASE_HELPOPT;

        default:
            builtin_usage();
            return (EX_USAGE);
        }
    }
    list = loptend;

    struct timespec rem;
    {
        const char *argv[2];
        
        int opt_argc = to_argv_opt(list, 1, 1, argv);
        if (opt_argc == -1)
            return (EX_USAGE);

        intmax_t integer;
        if (legal_number(argv[0], &integer) == 0)
            return (EX_USAGE);
        rem.tv_sec = integer;
        if (integer > rem.tv_sec) {
            warnx("sleep: argv[1] too large!");
            return (EX_USAGE);
        } else if (integer < 0) {
            warnx("sleep: argv[1] is negative!");
            return (EX_USAGE);
        }

        if (opt_argc == 1) {
            if (legal_number(argv[1], &integer) == 0)
                return (EX_USAGE);
            if (integer > 999999999) {
                warnx("sleep: argv[2] too large!");
                return (EX_USAGE);
            } else if (integer < 0) {
                warnx("sleep: argv[2] negative!");
                return (EX_USAGE);
            }
            rem.tv_nsec = integer;
        } else
            rem.tv_nsec = 0;
    }

    struct timespec req;
    int result;
    do {
        req = rem;
        result = nanosleep(&req, &rem);
    } while (result == -1 && errno == EINTR && restart_on_signal);

    if (result == -1 && errno != EINTR) {
        warn("nanosleep failed");
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin sleep_struct = {
    "sleep",       /* builtin name */
    sleep_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "If -R is specified, then sleep will restart afer a signal is delivered.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "sleep [-R] seconds nanoseconds",      /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

int has_supplementary_group_member_builtin(WORD_LIST *list)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    const char *argv[1];
    if (to_argv(list, 1, argv) == -1)
        return (EX_USAGE);

    gid_t gid;
    if (parse_group(&gid, argv[0]) == -1)
        return 3;

    return !group_member(gid);
}
PUBLIC struct builtin has_supplementary_group_member_struct = {
    "has_supplementary_group_member",       /* builtin name */
    has_supplementary_group_member_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "Check whether process has group/gid in its supplementary groups.",
        "",
        "Returns 0 if it is in the supplementary group,",
        "returns 1 if not,",
        "returns 2 on wrong usage,",
        "returns 3 on error.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "has_supplementary_group_member group/gid",      /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

int create_socket_builtin(WORD_LIST *list)
{
    reset_internal_getopt();

    int flags = 0;
    for (int opt; (opt = internal_getopt(list, "NC")) != -1; ) {
        switch (opt) {
        case 'N':
            flags |= SOCK_NONBLOCK;
            break;

        case 'C':
            flags |= SOCK_CLOEXEC;
            break;


        CASE_HELPOPT;

        default:
            builtin_usage();
            return (EX_USAGE);
        }
    }
    list = loptend;

    const char *argv[4];
    if (to_argv(list, 4, argv) == -1)
        return (EX_USAGE);

    int domain;
    if (strcasecmp(argv[0], "AF_UNIX") == 0)
        domain = AF_UNIX;
    else if (strcasecmp(argv[0], "AF_INET") == 0)
        domain = AF_INET;
    else if (strcasecmp(argv[0], "AF_INET6") == 0)
        domain = AF_INET6;
    else {
        warnx("create_socket: Unknown argv[1]");
        return (EX_USAGE);
    }

    int type;
    if (strcasecmp(argv[1], "SOCK_STREAM") == 0)
        type = SOCK_STREAM;
    else if (strcasecmp(argv[1], "SOCK_DGRAM") == 0)
        type = SOCK_DGRAM;
    else if (strcasecmp(argv[1], "SOCK_SEQPACKET") == 0)
        type = SOCK_SEQPACKET;
    else {
        warnx("create_socket: Unknown argv[2]");
        return (EX_USAGE);
    }

    int protocol;
    switch (str2int(argv[2], &protocol)) {
        case -1:
            warnx("create_socket: argv[3] is not an integer");
            return (EX_USAGE);
        case -2:
            warnx("create_socket: argv[3] out of range");
            return (EX_USAGE);

        case 0:
            break;
    }

    int socketfd = socket(domain, type | flags, protocol);
    if (socketfd == -1) {
        warn("create_socket failed");
        return (EXECUTION_FAILURE);
    }

    bind_var_to_int((char*) argv[3], socketfd);

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin create_socket_struct = {
    "create_socket",       /* builtin name */
    create_socket_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "create a socket and put it in $var.",
        "",
        "If '-N' is passed, then the socket is marked non-blocking.",
        "If '-C' is passed, then the socket is marked close-on-exec.",
        "",
        "Currently, only AF_UNIX, AF_INET and AF_INET6 is suppported.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "create_socket [-NC] domain type <int> protocol var",      /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

int bind_builtin(WORD_LIST *list)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    const char *argv[3];
    if (to_argv(list, 3, argv) == -1)
        return -1;

    int socketfd;
    if (str2fd(argv[0], &socketfd) == -1)
        return (EX_USAGE);

    socklen_t addrlen;
    union {
        struct sockaddr addr;
        struct sockaddr_in ipv4;
        struct sockaddr_un unix;
    } addr;

    sa_family_t sa_family;
    if (strcasecmp(argv[1], "AF_UNIX") == 0) {
        addrlen = sizeof(struct sockaddr_un);
        addr.unix.sun_family = AF_UNIX;
        strncpy(addr.unix.sun_path, argv[2], sizeof(addr.unix.sun_path));
    } else if (strcasecmp(argv[1], "AF_INET") == 0) {
        addrlen = sizeof(struct sockaddr_in);
        sa_family = AF_INET;

        const char *port = strchr(argv[2], ':');
        if (port == NULL) {
            warnx("bind: port not found in argv[3]");
            return (EX_USAGE);
        }

        char ipv4_addr[INET_ADDRSTRLEN];
        size_t ipv4_len = port - argv[2];
        memcpy(ipv4_addr, argv[2], ipv4_len);
        ipv4_addr[ipv4_len] = '\0';

        switch (inet_pton(AF_INET, ipv4_addr, &addr.ipv4.sin_addr)) {
            case 0:
                warnx("bind: argv[3] does not have a valid network address in the specified address family");
                return (EXECUTION_FAILURE);

            case 1:
                break;
        }

        intmax_t integer;
        if (legal_number(port, &integer) == 0)
            return (EX_USAGE);
        if (integer < 0) {
            warnx("bind: argv[3] contains a negative port number");
            return (EXECUTION_FAILURE);
        } else if (integer > 65535) {
            warnx("bind: argv[3] contains a port number greaeter than 65535");
            return (EXECUTION_FAILURE);
        }

        addr.ipv4.sin_port = htons(integer);
    } else {
        warnx("bind: Unknown argv[1]");
        return (EX_USAGE);
    }

    if (bind(socketfd, &addr.addr, addrlen) == -1) {
        warn("bind: failed");
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin bind_struct = {
    "bind",       /* builtin name */
    bind_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "Currently, only AF_UNIX and AF_INET is suppported.",
        "",
        "If domain == AF_INET, socketaddr must be in format ipv4_addr:port.",
        "If domain == AF_UNIX, length of socketaddr must be <= 108.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "bind <int> socketfd domain socketaddr",      /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

int listen_builtin(WORD_LIST *list)
{
    if (check_no_options(&list) == -1)
        return (EX_USAGE);

    const char *argv[2];
    if (to_argv(list, 2, argv) == -1)
        return (EX_USAGE);

    int socketfd;
    if (str2fd(argv[0], &socketfd) == -1)
        return (EX_USAGE);

    int backlog;
    switch (str2pint(argv[1], &backlog)) {
        case -1:
            warnx("listen: argv[2] is not an integer");
            return (EX_USAGE);
        case -2:
            warnx("listen: argv[2] out of range");
            return (EX_USAGE);
        case 0:
            break;
    }

    if (listen(socketfd, backlog) == -1) {
        warn("listen: failed");
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin listen_struct = {
    "listen",       /* builtin name */
    listen_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "The socketfd is a fd that refers to a socket of type SOCK_STREAM or SOCK_SEQPACKET.",
        "",
        "The backlog defines the max length to which the queue of pending connections for socketfd may grow.",
        "If backlog is greater than the value in /proc/sys/net/core/somaxconn, then it is ",
        "silently truncated to that value.",
        "Since Linux 5.4, the default in this file is 4096; in earlier kernels, the default value is 128.",
        "In kernels before 2.4.25, this limit was a hard coded value, SOMAXCONN, with the value 128.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "listen <int> socketfd <int> backlog",      /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};

int accept_builtin(WORD_LIST *list)
{
    reset_internal_getopt();

    int flags = 0;
    for (int opt; (opt = internal_getopt(list, "NC")) != -1; ) {
        switch (opt) {
        case 'N':
            flags |= SOCK_NONBLOCK;
            break;

        case 'C':
            flags |= SOCK_CLOEXEC;
            break;


        CASE_HELPOPT;

        default:
            builtin_usage();
            return (EX_USAGE);
        }
    }
    list = loptend;

    int socketfd;
    if (readin_fd(&list, &socketfd) == -1)
        return (EX_USAGE);

    int backlog;
    switch (str2pint(argv[1], &backlog)) {
        case -1:
            warnx("listen: argv[2] is not an integer");
            return (EX_USAGE);
        case -2:
            warnx("listen: argv[2] out of range");
            return (EX_USAGE);
        case 0:
            break;
    }

    if (listen(socketfd, backlog) == -1) {
        warn("listen: failed");
        return (EXECUTION_FAILURE);
    }

    return (EXECUTION_SUCCESS);
}
PUBLIC struct builtin listen_struct = {
    "listen",       /* builtin name */
    listen_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "The socketfd is a fd that refers to a socket of type SOCK_STREAM or SOCK_SEQPACKET.",
        "",
        "The backlog defines the max length to which the queue of pending connections for socketfd may grow.",
        "If backlog is greater than the value in /proc/sys/net/core/somaxconn, then it is ",
        "silently truncated to that value.",
        "Since Linux 5.4, the default in this file is 4096; in earlier kernels, the default value is 128.",
        "In kernels before 2.4.25, this limit was a hard coded value, SOMAXCONN, with the value 128.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "listen <int> socketfd <int> backlog",      /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};



// accept
// connect

// epoll

// timer_create

int enable_all_builtin(WORD_LIST *_)
{
    Dl_info info;
    if (dladdr(enable_all_builtin, &info) == 0) {
        warnx("Failed to get path to the shared object itself by dladdr");
        return 1;
    }

    // The path to file has a upper limit
    char pathname[strlen(info.dli_fname) + 1];
    strncpy(pathname, info.dli_fname, sizeof(pathname));

    WORD_DESC words[] = {
        { .word = "-f", .flags = 0 },
        { .word = (char*) info.dli_fname /* Pretty sure that it's not going to be modified in enable_builtin */, .flags = 0 },

        { .word = "create_memfd", .flags = 0 },
        { .word = "create_tmpfile", .flags = 0 },

        { .word = "lseek", .flags = 0 },

        { .word = "fexecve", .flags = 0 },
        { .word = "flink", .flags = 0 },
        { .word = "fchmod", .flags = 0 },
        { .word = "fchown", .flags = 0 },

        { .word = "getresuid", .flags = 0 },
        { .word = "getresgid", .flags = 0 },
        { .word = "setresuid", .flags = 0 },
        { .word = "setresgid", .flags = 0 },
        { .word = "has_supplementary_group_member", .flags = 0 },
        { .word = "get_supplementary_groups", .flags = 0 },
        { .word = "set_supplementary_groups", .flags = 0 },

        { .word = "create_unixsocketpair", .flags = 0 },
        { .word = "fdputs", .flags = 0 },
        { .word = "fdecho", .flags = 0 },
        { .word = "sendfds", .flags = 0 },
        { .word = "recvfds", .flags = 0 },

        { .word = "pause", .flags = 0 },
        { .word = "sleep", .flags = 0 },

        { .word = "create_socket", .flags = 0 },
        { .word = "bind", .flags = 0 },
        { .word = "listen", .flags = 0 },
    };

    const size_t builtin_num = sizeof(words) / sizeof(WORD_DESC);

    WORD_LIST list[builtin_num];
    for (size_t i = 0; i != builtin_num; ++i) {
        list[i].word = &words[i];
        list[i].next = i + 1 != builtin_num ? &list[i + 1] : NULL;
    }

    return enable_builtin(list);
}
PUBLIC struct builtin enable_all_struct = {
    "enable_all",       /* builtin name */
    enable_all_builtin, /* function implementing the builtin */
    BUILTIN_ENABLED,               /* initial flags for builtin */
    (char*[]){
        "enable_all enables all builtin defined in this file.",
        (char*) NULL
    },                            /* array of long documentation strings. */
    "enable_all",                 /* usage synopsis; becomes short_doc */
    0                             /* reserved for internal use */
};
