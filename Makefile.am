sbin_PROGRAMS = fuse-workspace

fuse_workspace_CFLAGS = $(FUSE_CFLAGS) $(GLIB_CFLAGS) -D_FILE_OFFSET_BITS=64 -lm -I common-utils -O3 -Wall -Wno-unused-but-set-variable -Wno-uninitialized -Wno-unused-variable -Wno-unused-label
fuse_workspace_LDADD = $(FUSE_LIBS) $(GLIB_LIBS)

fuse_workspace_CFLAGS += $(NFS_CFLAGS)
fuse_workspace_LDADD += $(NFS_LIBS)

fuse_workspace_SOURCES = entry-management.c common-utils/beventloop-utils.c \
			options.c path-resolution.c \
			fuse-workspace.c \
			monitorsessions.c readdir-utils.c objects.c workspaces.c resources.c \
			module/virtual/browsevirtual.c module/file/overlay.c \
			common-utils/utils.c common-utils/workerthreads.c common-utils/simple-list.c \
			common-utils/skiplist.c \
			common-utils/skiplist-delete.c common-utils/skiplist-find.c common-utils/skiplist-insert.c \
			fschangenotify.c fschangenotify-fssync.c fschangenotify-event.c


if USE_LIBSMBCLIENT

fuse_workspace_CFLAGS += $(SMB_CFLAGS)
fuse_workspace_LDADD += $(SMB_LIBS)
fuse_workspace_SOURCES += module/smb/libsmbclient-servers.c module/smb/smb-common.c module/smb/libsmbclient-shares-sync.c module/smb/libsmbclient-common.c

endif

if USE_LIBNFS

fuse_workspace_CFLAGS += $(NFS_CFLAGS)
fuse_workspace_LDADD += $(NFS_LIBS)
fuse_workspace_SOURCES += module/nfs/libnfs-servers.c module/nfs/nfs-common.c module/nfs/libnfs-exports-sync.c

endif

fuse_workspace_CFLAGS += -DHAVE_IMMEDIATE_STRUCTURES=1 -I/usr/include/samba-4.0 -llibsmb -ltevent -ltalloc -lsamba-credentials -lsamba-util -lcli_smb_common -lgensec -lsamba-hostconfig -lsamba-policy -ldcerpc -lsmbclient-raw -lcli-ldap -lerrors
fuse_workspace_LDADD += -L/usr/lib/samba 
fuse_workspace_SOURCES += module/smb/smbcli-common.c module/smb/smbcli-shares-sync.c

