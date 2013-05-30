/*
 
  2010, 2011, 2012 Stef Bon <stefbon@gmail.com>

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
#include <dirent.h>

#include <sys/stat.h>
#include <sys/param.h>

#include <pthread.h>
#include <time.h>

#include "notifyfs-fsevent.h"

#include "entry-management.h"
#include "logging.h"
#include "utils.h"

#include "workerthreads.h"

#include "message-base.h"
#include "message-send.h"
#include "message-receive.h"

#include "path-resolution.h"
#include "epoll-utils.h"

#include "handleclientmessage.h"
#include "watches.h"
#include "socket.h"
#include "changestate.h"

#define SIMPLEOVERLAYFS_COMMAND_SETWATCH			1

/* TODO delwatch */

struct command_setwatch_struct {
    struct pathinfo_struct pathinfo;
    int owner_watch_id;
    struct fseventmask_struct fseventmask;
};

struct clientcommand_struct {
    uint64_t unique;
    unsigned char type;
    union {
	struct command_setwatch_struct setwatch;
    } command;
};

static struct workerthreads_queue_struct *global_workerthreads_queue=NULL;
extern struct notifyfs_connection_struct notifyfsserver;

void send_clientcommand_reply(struct clientcommand_struct *clientcommand, int error)
{

    send_reply_message(notifyfsserver.fd, clientcommand->unique, error, NULL, 0);

}

/*
    process a message to set a watch

    it can be a message from local client to the local server, via a local socket

    or

    it can be a message about a forwarded watch, when the remote server is the backend

    (todo: a local backend like fuse)

*/

static void process_command_setwatch(struct clientcommand_struct *clientcommand)
{
    struct command_setwatch_struct *command_setwatch=&(clientcommand->command.setwatch);
    struct entry_struct *entry;

    logoutput("process_command_setwatch");

    /* make sure the path does exist (and lookup the entry) */

    entry=check_notifyfs_path(command_setwatch->pathinfo.path);

    if (! entry ) {
	int error=ENOENT;

	logoutput("process_command_setwatch: error (%i:%s) setting watch on %s", error, strerror(error), command_setwatch->pathinfo.path);

	send_clientcommand_reply(clientcommand, error);

	goto finish;

    }

    if (command_setwatch->owner_watch_id>0) {
	struct inode_struct *inode;
	int res;

	inode=entry->inode;

	/* with a local sender, add the mountindex also */

	res=add_clientwatch(inode, &command_setwatch->fseventmask, command_setwatch->owner_watch_id, &command_setwatch->pathinfo);

	if (res<0) {

	    send_clientcommand_reply(clientcommand, abs(res));
	    goto finish;

	}

    }

    send_clientcommand_reply(clientcommand, 0);

    finish:

    free_path_pathinfo(&command_setwatch->pathinfo);

}


static void process_command(void *data)
{
    struct clientcommand_struct *clientcommand=(struct clientcommand_struct *) data;

    if (clientcommand->type==SIMPLEOVERLAYFS_COMMAND_SETWATCH) process_command_setwatch(clientcommand);

    free(clientcommand);

}

void handle_setwatch_message(int fd, void *data, struct notifyfs_setwatch_message *setwatch_message, void *buff, int len, unsigned char typedata)
{
    struct clientcommand_struct *clientcommand=NULL;

    /* some sanity checks */

    if (setwatch_message->watch_id<=0) {

	logoutput("handle setwatch message: error: watch id not positive..");
	goto error;

    }

    if (!buff) {

	logoutput("handle setwatch message: buffer is empty, cannot continue");
	goto error;

    }

    clientcommand=malloc(sizeof(struct clientcommand_struct));

    if (clientcommand) {
	struct workerthread_struct *workerthread;

	memset(clientcommand, 0, sizeof(struct clientcommand_struct));

	clientcommand->unique=setwatch_message->unique;

	clientcommand->type=SIMPLEOVERLAYFS_COMMAND_SETWATCH;
	clientcommand->command.setwatch.pathinfo.path=NULL;
	clientcommand->command.setwatch.pathinfo.len=0;
	clientcommand->command.setwatch.pathinfo.flags=0;

	/* path is first part of buffer */

	clientcommand->command.setwatch.pathinfo.path=strdup((char *) buff);

	if ( ! clientcommand->command.setwatch.pathinfo.path) {

	    logoutput("handle_setwatch_message: no memory to allocate %s", (char *) buff);
	    goto error;

	}

	clientcommand->command.setwatch.pathinfo.flags=PATHINFOFLAGS_ALLOCATED;
	clientcommand->command.setwatch.pathinfo.len=strlen(clientcommand->command.setwatch.pathinfo.path);

	clientcommand->command.setwatch.owner_watch_id=setwatch_message->watch_id;

	clientcommand->command.setwatch.fseventmask.attrib_event=setwatch_message->fseventmask.attrib_event;
	clientcommand->command.setwatch.fseventmask.xattr_event=setwatch_message->fseventmask.xattr_event;
	clientcommand->command.setwatch.fseventmask.move_event=setwatch_message->fseventmask.move_event;
	clientcommand->command.setwatch.fseventmask.file_event=setwatch_message->fseventmask.file_event;
	clientcommand->command.setwatch.fseventmask.fs_event=setwatch_message->fseventmask.fs_event;

	workerthread=get_workerthread(global_workerthreads_queue);

	if (workerthread) {

	    workerthread->processevent_cb=process_command;
	    workerthread->data=(void *) clientcommand;

	    signal_workerthread(workerthread);

	} else {

	    /* no free thread.... what now ?? */

	    logoutput("handle_setwatch_message: no free thread...");
	    goto error;

	}

    } else {

	logoutput("handle_setwatch_message: cannot allocate clientcommand");

    }

    return;

    error:

    if (clientcommand) {

	free_path_pathinfo(&clientcommand->command.setwatch.pathinfo);

	free(clientcommand);
	clientcommand=NULL;

    }

    return;

}

void handle_reply_message(int fd, void *data, struct notifyfs_reply_message *reply_message, void *buff, int len, unsigned char typedata)
{

    if (reply_message->error>0) {

	logoutput("handle_reply_message: got reply with error (%i:%s)", reply_message->error, strerror(reply_message->error));

    }

    process_notifyfs_reply(reply_message->unique, reply_message->error);

}


void init_handleclientmessage(struct workerthreads_queue_struct *workerthreads_queue)
{

    global_workerthreads_queue=workerthreads_queue;

    assign_notifyfs_message_cb_setwatch(handle_setwatch_message);
    assign_notifyfs_message_cb_reply(handle_reply_message);

}
