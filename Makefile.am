sbin_PROGRAMS = simpleoverlayfs

simpleoverlayfs_CFLAGS = $(FUSE_CFLAGS) $(GLIB_CFLAGS) -I../common/ -O3 -Wall -Wno-unused-but-set-variable -Wno-uninitialized -Wno-unused-variable -Wno-unused-label
simpleoverlayfs_LDADD = $(FUSE_LIBS) $(GLIB_LIBS)

simpleoverlayfs_SOURCES = changestate.c entry-management.c ../common/epoll-utils.c ../common/handlefuseevent.c \
		    ../common/notifyfs-fsevent.c handleclientmessage.c \
		    options.c path-resolution.c ../common/message-receive.c ../common/message-send.c \
		    simpleoverlayfs.c ../common/socket.c \
		    ../common/utils.c watches.c ../common/workerthreads.c
