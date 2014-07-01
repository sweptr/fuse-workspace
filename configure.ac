#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([notifyfs], [1.0], [none])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([fuse-workspace.h])
AC_CONFIG_HEADERS([config.h])


# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h stddef.h stdlib.h string.h strings.h sys/mount.h sys/param.h sys/statvfs.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_CHECK_FUNCS([clock_gettime fdatasync ftruncate memmove memset mkdir realpath rmdir strchr strdup strerror strrchr strstr])
AC_CHECK_FUNCS([inotify_init], [AC_DEFINE([HAVE_INOTIFY], [1], [Check for inotify])])

# AC_CHECK_FUNCS([inotify_init], [AC_DEFINE([HAVE_INOTIFY], [1], [Check for libinotify])])

PKG_CHECK_MODULES(FUSE, [ fuse3 >= 3.0 ])
PKG_CHECK_MODULES(GLIB, [ glib-2.0 ])

AC_MSG_CHECKING([whether to use libnfs])
AC_ARG_WITH([libnfs],
    [AS_HELP_STRING([--with-libnfs], [use libnfs to browse NFS network and optionally access exports])],
    [],
    [with_libnfs=check])

AS_CASE(["$with_libnfs"],
    [yes], [PKG_CHECK_MODULES(NFS, [ libnfs ], [HAVE_LIBNFS=1])],
    [no],
    [PKG_CHECK_MODULES(NFS, [ libnfs ], [HAVE_LIBNFS=1], [HAVE_LIBNFS=0])])

AM_CONDITIONAL([USE_LIBNFS], [test "x$with_libnfs" != xno -a "$HAVE_LIBNFS" = "1"])
AM_COND_IF([USE_LIBNFS], [AC_DEFINE([HAVE_LIBNFS], [1], [Define if using libnfs.])])
AC_MSG_RESULT([$with_libnfs])

AC_MSG_CHECKING([whether to use libsmbclient])
AC_ARG_WITH([libsmbclient],
    [AS_HELP_STRING([--with-libsmbclient], [use libsmbclient to browse SMB network and optionally access shares])],
    [],
    [with_libsmbclient=check])

AS_CASE(["$with_libsmbclient"],
    [yes], [PKG_CHECK_MODULES(SMB, [ smbclient ], [HAVE_LIBSMBCLIENT=1])],
    [no],
    [PKG_CHECK_MODULES(SMB, [ smbclient ], [HAVE_LIBSMBCLIENT=1], [HAVE_LIBSMBCLIENT=0])])

AM_CONDITIONAL([USE_LIBSMBCLIENT], [test "x$with_libsmbclient" != xno -a "$HAVE_LIBSMBCLIENT" = "1"])
AM_COND_IF([USE_LIBSMBCLIENT], [AC_DEFINE([HAVE_LIBSMBCLIENT], [1], [Define if using libsmbclient.])])
AC_MSG_RESULT([$with_libsmbclient])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
