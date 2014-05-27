sbin_PROGRAMS = fuse-workspace

fuse_workspace_CFLAGS = $(FUSE_CFLAGS) $(GLIB_CFLAGS) -D_FILE_OFFSET_BITS=64 -lm -I common-utils -O3 -Wall -Wno-unused-but-set-variable -Wno-uninitialized -Wno-unused-variable -Wno-unused-label
fuse_workspace_LDADD = $(FUSE_LIBS) $(GLIB_LIBS)

fuse_workspace_SOURCES = entry-management.c common-utils/beventloop-utils.c \
			options.c path-resolution.c \
			fuse-workspace.c \
			monitorsessions.c readdir-utils.c objects.c workspaces.c resources.c \
			module/virtual/browsevirtual.c module/file/overlay.c \
			common-utils/utils.c common-utils/workerthreads.c common-utils/simple-list.c \
			common-utils/skiplist.c \
			common-utils/skiplist-delete.c common-utils/skiplist-find.c common-utils/skiplist-insert.c \
			fschangenotify.c fschangenotify-fssync.c fschangenotify-event.c

