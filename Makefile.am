sbin_PROGRAMS = simpleoverlayfs

simpleoverlayfs_CFLAGS = $(FUSE_CFLAGS) $(GLIB_CFLAGS) -D_FILE_OFFSET_BITS=64 -lm -I common-utils -O3 -Wall -Wno-unused-but-set-variable -Wno-uninitialized -Wno-unused-variable -Wno-unused-label
simpleoverlayfs_LDADD = $(FUSE_LIBS) $(GLIB_LIBS)

simpleoverlayfs_SOURCES = entry-management.c common-utils/beventloop-utils.c common-utils/handlefuseevent.c \
			options.c path-resolution.c \
			simpleoverlayfs.c fschangenotify.c \
			common-utils/utils.c common-utils/workerthreads.c common-utils/simple-list.c \
			common-utils/skiplist.c common-utils/skiplist-locking.c common-utils/skiplist-utils.c \
			common-utils/skiplist-delete.c common-utils/skiplist-find.c common-utils/skiplist-insert.c 
