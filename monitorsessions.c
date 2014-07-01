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

#include "global-defines.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include <inttypes.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <pwd.h>
#include <pthread.h>
#include <dirent.h>

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#include "fuse-workspace.h"
#include "utils.h"
#include "skiplist.h"
#include "entry-management.h"
#include "path-resolution.h"
#include "fschangenotify.h"
#include "monitorsessions.h"

#ifdef LOGGING

#include <syslog.h>

static unsigned char loglevel=1;

#define logoutput_debug(...) if (loglevel >= 5) syslog(LOG_DEBUG, __VA_ARGS__)
#define logoutput_info(...) if (loglevel >= 4) syslog(LOG_INFO, __VA_ARGS__)
#define logoutput_notice(...) if (loglevel >= 3) syslog(LOG_NOTICE, __VA_ARGS__)
#define logoutput_warning(...) if (loglevel >= 2) syslog(LOG_WARNING, __VA_ARGS__)
#define logoutput_error(...) if (loglevel >= 1) syslog(LOG_ERR, __VA_ARGS__)

#define logoutput(...) if (loglevel >= 1) syslog(LOG_DEBUG, __VA_ARGS__)

#else

static inline void dummy_nolog()
{
    return;

}

#define logoutput_debug(...) dummy_nolog()
#define logoutput_info(...) dummy_nolog()
#define logoutput_notice(...) dummy_nolog()
#define logoutput_warning(...) dummy_nolog()
#define logoutput_error(...) dummy_nolog()

#define logoutput(...) dummy_nolog()

#endif

struct userslist_struct {
    uid_t *uids;
    unsigned len;
};

static struct userslist_struct current_users={NULL, 0};
static struct userslist_struct new_users={NULL, 0};

static char *session_path=NULL;
static struct notifywatch_struct *session_watch=NULL;
static void (* session_cb) (char *user, uid_t uid, unsigned char what) = NULL;
static pthread_mutex_t session_mutex=PTHREAD_MUTEX_INITIALIZER;

#define DEFAULT_USERSESSIONS_MAP "/run/systemd/users"

static int read_users_from_system(uid_t **p_uids)
{
    struct dirent *de;
    DIR *dp;
    size_t size;
    int count0=0, count1=0, nreturn=0;
    long startdp;

    dp=opendir(session_path);

    if (dp) {

	/* get the start */

	startdp=telldir(dp);

	while((de=readdir(dp))) {

	    /* skip trivial values */

	    if (strcmp(de->d_name, ".")==0 || strcmp(de->d_name, "..")==0) continue;

	    if (de->d_type==DT_REG) count0++;

	}

	count1=count0;

	logoutput("read_users_from_system: got %i entries", count0);

	if (count0>0) {

	    *p_uids=malloc(count0 * sizeof(uid_t));

	    if ( ! *p_uids) {

		closedir(dp);
		nreturn=-ENOMEM;
		goto out;

	    }

	    seekdir(dp, startdp);
	    count1=0;

	    while((de=readdir(dp))) {

		/* skip trivial values */

		if (strcmp(de->d_name, ".")==0 || strcmp(de->d_name, "..")==0) continue;

		if (de->d_type==DT_REG) {

		    if (count1>count0) {

			/* possible a new user has appeared in the meantime..... */

			*p_uids=realloc(*p_uids, count1 * sizeof(uid_t));

			if ( ! *p_uids ) {

			    closedir(dp);
			    nreturn=-ENOMEM;
			    goto out;

			}

			count0=count1;

		    }

		    (*p_uids)[count1]=(uid_t) atoi(de->d_name);
		    count1++;

		}

	    }

	}

	closedir(dp);

    }

    nreturn=count1;

    out:

    return nreturn;

}

/* sort an arry of uids 
    note:
    the array must at least has two elements, an array of one (or zero) elements is always sorted
*/

static void sort_array_uids(uid_t *uid, int len)
{
    uid_t tuid;
    unsigned i, j;

    for (i=1;i<len;i++) {

	for (j=i-1;j>=0;j--) {

	    /* compare element j and j+1 
               if element j has a bigger value, than swap and continue 
               if not than stop */

	    if ( uid[j] > uid[j+1] ) {

		tuid=uid[j];
		uid[j]=uid[j+1];
		uid[j+1]=tuid;

	    } else {

		break;

	    }

	}

    }

}

static void get_users_from_system(struct userslist_struct *userslist)
{
    int res;
    uid_t *uid;

    res=read_users_from_system(&uid);

    if (res<0) {

	/* error */

	logoutput("get_users_from_system: error %i when reading users from system", abs(res));

	userslist->uids=NULL;
	userslist->len=0;

    } else {

	/* sort the uid list, only when there are more than one */

	logoutput("get_users_from_system: read %i users", res);

	if (res>1) sort_array_uids(uid, res);

	userslist->uids=uid;
	userslist->len=res;

    }

}


static void process_change_users()
{
    unsigned i=0,j=0;

    if (new_users.uids) {

	free(new_users.uids);
	new_users.uids=0;

    }

    new_users.len=0;

    get_users_from_system(&new_users);

    /* walk through both lists, i is index in current, j in new */

    while(1) {

	if (i<current_users.len && j<new_users.len) {

	    if ( new_users.uids[j]==current_users.uids[i]) {

		/* the same, so nothing changed, so do nothing */

		i++;
		j++;
		continue;

	    } else if (new_users.uids[j]<current_users.uids[i]) {

		/* new is smaller: new is added */

		session_cb(NULL, new_users.uids[j], 1);

		j++;
		continue;

	    } else if (new_users.uids[j]>current_users.uids[i]) {

		/* new is bigger: current is removed */

		session_cb(NULL, current_users.uids[i], 0);

		i++;
		continue;

	    }

	} else {

	    if ( i<current_users.len ) {

		/* j must be == new_users.len */

		session_cb(NULL, current_users.uids[i], 0);

		i++;
		continue;

	    } else if ( j<new_users.len ) {

		/* j must be == new_users.len */

		session_cb(NULL, new_users.uids[j], 1);

		j++;
		continue;

	    } else {

		/* both i and j are at the limit */

		break;

	    }

	}

    }

}

static void process_event_sessionwatch()
{

    pthread_mutex_lock(&session_mutex);

    process_change_users();

    /* move the new read userslist from new to current */

    if (current_users.uids) {

	free(current_users.uids);
	current_users.uids=NULL;

    }

    current_users.len=new_users.len;
    current_users.uids=new_users.uids;

    new_users.len=0;
    new_users.uids=NULL;

    pthread_mutex_unlock(&session_mutex);

}

static void sessionwatch_create(struct notifywatch_struct *watch, char *name)
{

    logoutput("sessionwatch_create");

    if (name && watch==session_watch) process_event_sessionwatch();
}

static void sessionwatch_remove(struct notifywatch_struct *watch, char *name)
{

    logoutput("sessionwatch_remove");

    if (name && watch==session_watch) process_event_sessionwatch();
}

static void sessionwatch_destroy(struct notifywatch_struct *watch)
{
    if (watch==session_watch) {

	/* here process the event which should not happen: the removal of the directory containing the sessions */

	logoutput("sessionwatch_destroy");

    }

}

static struct watchcb_struct watchcb = {
	    .create = sessionwatch_create,
	    .remove = sessionwatch_remove,
	    .change = NULL,
	    .destroy = sessionwatch_destroy,
};

int monitor_usersessions(void (* cb) (char *user, uid_t uid, unsigned char what), char *path, unsigned int *error)
{
    int result=0;
    struct pathinfo_struct pathinfo;

    if ( ! cb) {

	*error=EINVAL;
	result=-1;
	goto out;

    }

    if (! path) {

	path=strdup(DEFAULT_USERSESSIONS_MAP);

	if (! path) {

	    *error=ENOMEM;
	    result=-1;
	    goto out;

	}

    }

    logoutput("monitor_usersessions: watch %s", path);

    pathinfo.path=path;
    pathinfo.len=strlen(path) + 1;
    pathinfo.flags=PATHINFO_FLAGS_INUSE;

    session_path=path;
    session_cb=cb;

    /* set fs watch for direntries to be added or deleted */

    session_watch = add_systemwatch(&pathinfo, &watchcb, error);

    if ( ! session_watch) {

	if (*error==0) *error=EIO;
	result = -1;

    }

    out:

    logoutput("monitor_usersessions: result %i", result);

    return result;

}

void list_usersessions()
{
    process_event_sessionwatch();
}

