sbin_PROGRAMS = simpleoverlayfs

simpleoverlayfs_CFLAGS = $(FUSE_CFLAGS) $(GLIB_CFLAGS) -I../common/ -O3 -Wall -Wno-unused-but-set-variable -Wno-uninitialized -Wno-unused-variable -Wno-unused-label
simpleoverlayfs_LDADD = $(FUSE_LIBS) $(GLIB_LIBS)

simpleoverlayfs_SOURCES = entry-management.c ../common/epoll-utils.c ../common/handlefuseevent.c simpleoverlayfs.c options.c path-resolution.c \
		    ../common/utils.c ../common/workerthreads.c
