/*
  2010, 2011, 2012, 2013, 2014 Stef Bon <stefbon@gmail.com>

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/

#define INOTIFY_EVENT_SIZE (sizeof(struct inotify_event))
#define INOTIFY_BUFF_LEN (1024 * (INOTIFY_EVENT_SIZE + 16))

static struct bevent_xdata_struct xdata_inotify;

static struct simple_group_struct group_watches_inotify;

struct inotify_watch_struct {
    unsigned int wd;
    struct notifywatch_struct *watch;
};

typedef struct inotify_text_struct {
                const char *name;
                unsigned int mask;
                } inotify_text_struct;

static const inotify_text_struct inotify_textmap[] = {
            { "IN_ACCESS", 		IN_ACCESS},
            { "IN_MODIFY", 		IN_MODIFY},
            { "IN_ATTRIB", 		IN_ATTRIB},
            { "IN_CLOSE_WRITE", 	IN_CLOSE_WRITE},
            { "IN_CLOSE_NOWRITE", 	IN_CLOSE_NOWRITE},
            { "IN_OPEN", 		IN_OPEN},
            { "IN_MOVED_FROM", 		IN_MOVED_FROM},
            { "IN_MOVED_TO", 		IN_MOVED_TO},
            { "IN_CREATE", 		IN_CREATE},
            { "IN_DELETE", 		IN_DELETE},
            { "IN_DELETE_SELF", 	IN_DELETE_SELF},
            { "IN_MOVE_SELF", 		IN_MOVE_SELF},
            { "IN_ONLYDIR", 		IN_ONLYDIR},
            { "IN_DONT_FOLLOW", 	IN_DONT_FOLLOW},
#ifdef IN_EXCL_UNLINK
            { "IN_EXCL_UNLINK", 	IN_EXCL_UNLINK},
#endif
            { "IN_MASK_ADD", 		IN_MASK_ADD},
            { "IN_ISDIR", 		IN_ISDIR},
            { "IN_Q_OVERFLOW", 		IN_Q_OVERFLOW},
            { "IN_UNMOUNT", 		IN_UNMOUNT}};


int print_mask(unsigned int mask, char *string, size_t size)
{
    int i, pos=0, len;

    for (i=0;i<(sizeof(inotify_textmap)/sizeof(inotify_textmap[0]));i++) {

        if ( inotify_textmap[i].mask & mask ) {

            len=strlen(inotify_textmap[i].name);

            if ( pos + len + 1  > size ) {

                pos=-1;
                goto out;

            } else {

                if ( pos>0 ) {

                    *(string+pos)='|';
                    pos++;

                }

                strcpy(string+pos, inotify_textmap[i].name);
                pos+=len;

            }

        }

    }

    out:

    return pos;

}

/* functions to lookup a inotify watch using the inotify watch destriptor (wd) */

static unsigned int calculate_wd_hash(unsigned int wd)
{
    return wd % group_watches_inotify.len;
}

static int wd_hashfunction(void *data)
{
    struct inotify_watch_struct *i_watch=(struct inotify_watch_struct *) data;
    return calculate_wd_hash(i_watch->wd);
}

static struct inotify_watch_struct *lookup_inotify_watch_wd(unsigned int wd)
{
    unsigned int hashvalue=calculate_wd_hash(wd);
    void *index=NULL;
    struct inotify_watch_struct *inotify_watch=NULL;

    inotify_watch=(struct inotify_watch_struct *) get_next_element(&group_watches_inotify, &index, hashvalue);

    while(inotify_watch) {

	if (inotify_watch->wd==wd) break;
	inotify_watch=(struct inotify_watch_struct *) get_next_element(&group_watches_inotify, &index, hashvalue);

    }

    return inotify_watch;

}

void add_watch_inotifytable(struct inotify_watch_struct *inotify_watch)
{
    add_element_to_group(&group_watches_inotify, (void *) inotify_watch);
}

void remove_watch_inotifytable(struct inotify_watch_struct *inotify_watch)
{
    remove_element_from_group(&group_watches_inotify, (void *) inotify_watch);
}

void free_inotify_watch(void *data)
{
    struct inotify_watch_struct *i_watch=(struct inotify_watch_struct *) data;

    free(i_watch);

}


/*
    translate a fsnotify mask to inotify mask

    the values used by inotify are the same as fsnotify
    so this is simple

*/

static uint32_t translate_mask_fsnotify_to_inotify(uint32_t mask)
{

    return mask;

}

/*
    function which set a os specific watch on the backend on path with mask mask
*/

int set_watch_backend_inotify(struct notifywatch_struct *watch)
{
    int wd=0;
    uint32_t inotify_mask;
    unsigned int error=0;

    logoutput("set_watch_backend_inotify");

    /*
	test the the underlying fs works with inotify
	for example /proc and /sys do not support inotify
	change this test 
    */

    if (issubdirectory(watch->pathinfo.path, "/proc", 1)==1 || issubdirectory(watch->pathinfo.path, "/sys", 1)==1) {

	error=ENOSYS;
	goto out;

    }

    /*
	translate the fsnotify mask into a inotify mask
    */

    inotify_mask=translate_mask_fsnotify_to_inotify(watch->mask);

    if (inotify_mask>0) {
	char maskstring[128];

	print_mask(inotify_mask, maskstring, 128);

	logoutput("set_watch_backend_inotify: call inotify_add_watch on path %s and mask %i/%s", watch->pathinfo.path, inotify_mask, maskstring);

	/*
	    add some sane flags and all events:
	*/

	inotify_mask |= IN_DONT_FOLLOW | IN_ALL_EVENTS;

#ifdef IN_EXCL_UNLINK

	inotify_mask |= IN_EXCL_UNLINK;

#endif

	wd=inotify_add_watch(xdata_inotify.fd, watch->pathinfo.path, inotify_mask);

	if ( wd==-1 ) {

	    error=errno;

    	    logoutput("set_watch_backend_inotify: setting inotify watch on %s gives error: %i (%s)", watch->pathinfo.path, error, strerror(error));

	} else {
	    struct inotify_watch_struct *inotify_watch=NULL;

	    inotify_watch=lookup_inotify_watch_wd(wd);

	    if (inotify_watch) {

		if (!(inotify_watch->watch==watch)) {

		    logoutput("set_watch_backend_inotify: internal error, inotify watch (wd=%i)(path=%s)", wd, watch->pathinfo.path);

		    inotify_watch->watch=watch;

		    watch->data=(void *) inotify_watch;

		}

	    } else {

		inotify_watch=malloc(sizeof(struct inotify_watch_struct));

		if (inotify_watch) {

		    inotify_watch->wd=wd;
		    inotify_watch->watch=watch;

		    add_watch_inotifytable(inotify_watch);

		    watch->data=(void *) inotify_watch;

		}

	    }

	}

    } else if (inotify_mask==0) {

	logoutput("set_watch_backend_inotify: mask %i", inotify_mask);

    } else {

	logoutput("set_watch_backend_inotify: mask %i", inotify_mask);

    }

    out:

    return (error>0) ? -error : wd;

}

int change_watch_backend_inotify(struct notifywatch_struct *watch)
{

    /* with inotify the changing of an existing is the same call as the adding of a new watch */

    return set_watch_backend_inotify(watch);

}

void remove_watch_backend_inotify(struct notifywatch_struct *watch)
{
    struct inotify_watch_struct *inotify_watch=(struct inotify_watch_struct *) watch->data;

    logoutput("remove_watch_backend_inotify");

    /* lookup the inotify watch, if it's ok then it does not exist already */

    if (inotify_watch) {
	int res;

	remove_watch_inotifytable(inotify_watch);

	res=inotify_rm_watch(xdata_inotify.fd, inotify_watch->wd);

	watch->data=NULL;
	free(inotify_watch);

    }

}

void evaluate_fsevent_inotify_indir(struct inotify_watch_struct *inotify_watch, struct inotify_event *i_event)
{
    struct notifywatch_struct *watch=inotify_watch->watch;
    struct pathinfo_struct pathinfo={NULL, 0, 0};
    struct inode_struct *pinode=watch->inode;
    struct entry_struct *parent=pinode->alias;
    char maskstring[256];
    struct name_struct xname={NULL, 0, 0};
    unsigned int error=0;

    xname.name=(char *) i_event->name;
    xname.len=strlen(xname.name);

    calculate_nameindex(&xname);

    memset(maskstring, '\0', 80);

    print_mask(i_event->mask, maskstring, 80);

    logoutput("evaluate_fsevent_inotify_indir: (%i:%s) on %s (index: %lli, len %i)", i_event->mask, maskstring, i_event->name, xname.index, xname.len);

    if ( !(i_event->mask & IN_DELETE) && !(i_event->mask & IN_MOVED_FROM)){
	struct stat st;
	char *path=NULL;
	struct entry_struct *entry=NULL;

	path=malloc(watch->pathinfo.len + i_event->len + 1);

	if (! path) goto out;

	memcpy(path, watch->pathinfo.path, watch->pathinfo.len);
	*(path + watch->pathinfo.len) = '/';
	memcpy(path + watch->pathinfo.len + 1, i_event->name, i_event->len); /* i_event->name includes the trailing zero */

	pathinfo.path = path;
	pathinfo.len = watch->pathinfo.len + i_event->len;
	pathinfo.flags = PATHINFOFLAGS_ALLOCATED;

	/* this should not give an error */

	if (lstat(pathinfo.path, &st)==0) {

	    entry=find_entry(parent, &xname, &error);

	    if (entry) {
		uint32_t mask=0;
		struct inode_struct *inode=entry->inode;

		inode=entry->inode;

		/*
		    compare stat with cached values
		*/

		mask=determine_fsnotify_mask(inode, &st);
		get_current_time(&entry->synctime);

		logoutput("evaluate_fsevent_inotify_indir: (%i:%s) %s found: mask %i", i_event->mask, maskstring, i_event->name, mask);

		/*
		    here call the right fuse_lowlevel_notify_ function, with what parameters
		    and then what? what should the kernel do with that information?
		*/

	    } else {

		if (error==ENOTDIR || error==ENOENT) {
		    struct inode_struct *inode=NULL;

		    error=0;

		    entry=create_entry(parent, &xname);
		    inode=create_inode();

		    if (entry && inode) {

			entry->inode=inode;
			inode->alias=entry;

			add_inode_hashtable(inode, increase_inodes_workspace, (void *) watch->object->workspace_mount);

			insert_entry(entry, &error, 0);

			inode->mode = st.st_mode;
			inode->uid = st.st_uid;
			inode->gid = st.st_gid;
			inode->nlink = st.st_nlink;

			if (! S_ISDIR(st.st_mode)) inode->size = st.st_size;

			inode->mtim.tv_sec=st.st_mtim.tv_sec;
			inode->mtim.tv_nsec=st.st_mtim.tv_nsec;

			inode->ctim.tv_sec=st.st_ctim.tv_sec;
			inode->ctim.tv_nsec=st.st_ctim.tv_nsec;

			inode->rdev=st.st_rdev;

			get_current_time(&entry->synctime);

			logoutput("evaluate_fsevent_inotify_indir: (%i:%s) on new %s", i_event->mask, maskstring, i_event->name);

			queue_create(watch->object, entry, &error);

		    } else {

			error=ENOMEM;

			if (entry) {

			    destroy_entry(entry);
			    entry=NULL;

			}

			if (inode) {

			    free(inode);
			    inode=NULL;

			}

			goto out;

		    }

		}

	    }


	} else {

	    if (errno==ENOENT) {

		/* inotify does not report delete, but stat does, handle it as a delete */

		i_event->mask|=IN_DELETE;

	    }

	}

    }

    if ((i_event->mask & IN_DELETE) || (i_event->mask & IN_MOVED_FROM)) {
	unsigned int row=0;

	struct entry_struct *entry=NULL;

	logoutput("evaluate_fsevent_inotify_indir: (%i:%s): %s deleted", i_event->mask, maskstring, i_event->name);

	entry=find_entry(parent, &xname, &error);

	if (entry) {

	    error=0;
	    remove_entry(entry, &error);
	    queue_remove(watch->object, entry, &error);

	} else {

	    logoutput("evaluate_fsevent_inotify_indir: %s reported deleted, but not found", i_event->name);

	}

    }

    if (error==0) {

	logoutput("evaluate_fsevent_inotify_indir: ready for (%i:%s) %s", i_event->mask, maskstring, i_event->name);

    } else {

	logoutput("evaluate_fsevent_inotify_indir: error %i for (%i:%s) %s", error, i_event->mask, maskstring, i_event->name);

    }

    out:

    free_path_pathinfo(&pathinfo);

}

void evaluate_fsevent_inotify_ondir(struct inotify_watch_struct *inotify_watch, struct inotify_event *i_event)
{
    struct notifywatch_struct *watch=inotify_watch->watch;
    struct inode_struct *inode=watch->inode;
    struct entry_struct *entry=inode->alias;

    if ( !(i_event->mask & IN_DELETE) && !(i_event->mask & IN_MOVED_FROM) ) {

	if ( i_event->mask & IN_ATTRIB ) {
	    char *path=watch->pathinfo.path;
	    struct stat st;

	    /* something in the attributes has changed, what? */

	    if (lstat(path, &st)==-1) {

		/* strange case: i_event about entry, but stat gives error... */

		logoutput("evaluate_fsevent_inotify_ondir: error, kernel/inotify does not report delete");

		i_event->mask|=IN_DELETE;

	    } else {
		uint32_t mask=0;
		unsigned int error=0;

		mask=determine_fsnotify_mask(inode, &st);

		get_current_time(&entry->synctime);

		logoutput("evaluate_fsevent_inotify_ondir: fsnotify mask %i on %s", mask, entry->name.name);

		if (mask>0) queue_change(watch->object, entry, mask, &error);

	    }

	}

    }

    if ( (i_event->mask & IN_DELETE) || (i_event->mask & IN_MOVED_FROM) ) {
	unsigned int error=0;

	change_notifywatch(watch, 0);

	remove_entry(entry, &error);
	queue_remove(watch->object, entry, &error);

    }

}

/* function to translate an event reported by
   inotify
*/

void evaluate_fsevent_inotify(struct inotify_event *i_event)
{

    if (i_event->mask && IN_ALL_EVENTS) {
	struct inotify_watch_struct *inotify_watch=NULL;

	inotify_watch=lookup_inotify_watch_wd(i_event->wd);

	if (inotify_watch) {
	    struct notifywatch_struct *watch=inotify_watch->watch;

	    if (watch->inode && (watch->notifymask & i_event->mask)) {

		if (i_event->len>0) {

		    /* event on entry in directory */

		    evaluate_fsevent_inotify_indir(inotify_watch, i_event);

		} else {

		    /* event on entry of watch */

		    evaluate_fsevent_inotify_ondir(inotify_watch, i_event);

		}

		if (i_event->mask & (IN_DELETE_SELF | IN_IGNORED)) {

		    if (watch->cb==NULL) {

			change_notifywatch(watch, 0);

		    } else {

			remove_watch_inodetable(watch);

		    }

		}

	    }

	    if (watch->cb) {

		if (i_event->name) {

		    if (i_event->mask & (IN_CREATE | IN_MOVED_TO)) {

			if (watch->cb->create) (*watch->cb->create) (watch, i_event->name);

		    } else if (i_event->mask & (IN_DELETE | IN_MOVED_FROM)) {

			if (watch->cb->remove) (*watch->cb->remove) (watch, i_event->name);

		    } else if (i_event->mask & (IN_ATTRIB | IN_MODIFY)) {

			if (watch->cb->change) (*watch->cb->change) (watch, i_event->name);

		    }

		} else {

		    if (i_event->mask & (IN_DELETE_SELF | IN_IGNORED)) {

			if (watch->cb->destroy) (*watch->cb->destroy) (watch);

		    }

		}

		if (i_event->mask & (IN_DELETE_SELF | IN_IGNORED)) remove_systemwatch(watch);

	    }

	}

    }

}

static int handle_inotify_fd(int fd, void *data, uint32_t events)
{
    char outputstring[256];
    int lenread=0;
    char buff[INOTIFY_BUFF_LEN];

    lenread=read(fd, buff, INOTIFY_BUFF_LEN);

    if ( lenread<0 ) {

        logoutput("handle_inotify_fd: error (%i) reading inotify events (fd: %i)", errno, fd);

    } else {
        int i=0, res;
        struct inotify_event *i_event=NULL;

        while(i<lenread) {

            i_event = (struct inotify_event *) &buff[i];

            if ( (i_event->mask & IN_Q_OVERFLOW) || i_event->wd==-1 ) {

                /* what to do here: read again?? go back ??*/

                goto next;

            }

	    if ( (i_event->mask & IN_ISDIR) && ((i_event->mask & IN_OPEN) || (i_event->mask & IN_CLOSE_NOWRITE))) {

		/* explicit ignore the reading of directories */

		goto next;

	    }

	    evaluate_fsevent_inotify(i_event);

	    next:

            i += INOTIFY_EVENT_SIZE + i_event->len;

    	}

    }

    return 0;

}

void initialize_inotify(unsigned int *error)
{
    struct bevent_xdata_struct *xdata=NULL;
    int result=0, fd=0;

    /* create the inotify instance */

    fd=inotify_init();

    if (fd==-1) {

	*error=errno;
        logoutput("initialize_inotify: error creating inotify fd: %i.", errno);
        goto error;

    }

    /*
	add inotify to the main eventloop
    */

    xdata=add_to_beventloop(fd, EPOLLIN | EPOLLPRI, &handle_inotify_fd, NULL, &xdata_inotify, NULL);

    if ( ! xdata ) {

        logoutput("initialize_inotify: error adding inotify fd to eventloop.");
        goto error;

    } else {

        logoutput("initialize_inotify: inotify fd %i added to eventloop", fd);
	add_xdata_to_list(xdata);

    }

    result=initialize_group(&group_watches_inotify, wd_hashfunction, 256, error);

    if (result<0) {

	*error=abs(result);
    	logoutput("initialize_inotify: error %i adding inotify fd to eventloop", *error);
	goto error;

    }

    return;

    error:

    if (fd>0) {

	close(fd);
	fd=0;

    }

    if (xdata) {

	remove_xdata_from_beventloop(xdata);
	xdata=NULL;

    }

    free_group(&group_watches_inotify, free_inotify_watch);

}

void close_inotify()
{

    if ( xdata_inotify.fd>0 ) {

	close(xdata_inotify.fd);
	xdata_inotify.fd=0;

    }

    remove_xdata_from_beventloop(&xdata_inotify);
    remove_xdata_from_list(&xdata_inotify, 0);

    free_group(&group_watches_inotify, free_inotify_watch);

}

