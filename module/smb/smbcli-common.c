/*
  2010, 2011, 2012, 2103, 2014 Stef Bon <stefbon@gmail.com>

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
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <err.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <time.h>

/* specific samba4 includes */

#include <talloc.h>
#include <tevent.h>

#include <util/time.h>
#include <credentials.h>
#include <smb_cli.h>
#include <gensec.h>
#include <param.h>

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

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

#endif

#include "fuse-workspace.h"
#include "workerthreads.h"
#include "beventloop-utils.h"

#include "entry-management.h"

#include "path-resolution.h"
#include "utils.h"
#include "options.h"

#include "fschangenotify.h"
#include "fschangenotify-event.h"
#include "fschangenotify-fssync.h"

#include "workspaces.h"
#include "resources.h"
#include "objects.h"

#include "smb-common.h"
#include "smbcli-common.h"
#include "smbcli-shares-sync.h"

extern struct fs_options_struct fs_options;
extern struct smb_options_struct smb_options;

static TALLOC_CTX			*global_memory_ctx=NULL;
static struct smbcli_options 		global_smb_options;
static struct smbcli_session_options 	global_smb_session_options;
static struct resolve_context		*global_resolve_context=NULL;
static const char 			*global_socket_options=NULL;
static struct gensec_settings		*global_gensec_settings=NULL;
static const char			**global_ports;
static struct loadparm_context 		*lp_ctx=NULL;

static unsigned char 			initialized=0;
static pthread_mutex_t			init_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct tevent_context 		*global_eventloop=NULL;

extern struct resolve_context *lpcfg_resolve_context(struct loadparm_context *lp);

static unsigned char backslash='\\';
char *smb_rootpath="\\";

static int init_smbcli(unsigned int *error)
{

    logoutput("init_smbcli");

    global_memory_ctx=talloc_init("workspace_smbcli_module");

    if (! global_memory_ctx) {

	logoutput("init_smbcli: error creating global memory context");
	*error=ENOMEM;
	return -1;

    }

    gensec_init();

    lp_ctx = loadparm_init(global_memory_ctx);

    lpcfg_smbcli_options(lp_ctx, &global_smb_options);
    lpcfg_smbcli_session_options(lp_ctx, &global_smb_session_options);
    global_resolve_context=lpcfg_resolve_context(lp_ctx);
    global_socket_options=lpcfg_socket_options(lp_ctx);
    global_gensec_settings=lpcfg_gensec_settings(global_memory_ctx, lp_ctx);
    global_ports=lpcfg_smb_ports(lp_ctx);

    global_eventloop=tevent_context_init(global_memory_ctx);

    initialized=1;

    return 0;

}

int create_smbcli_context(struct smbcli_manager_struct *manager, unsigned int *error)
{
    TALLOC_CTX *context=NULL;

    context=talloc_init("smbcli-manager");

    if (context) {

	manager->memory_ctx = context;

    } else {

	*error=ENOMEM;
	return -1;

    }

    return 0;

}

void init_smbcli_manager(struct smbcli_manager_struct *manager)
{

    manager->memory_ctx=NULL;
    pthread_mutex_init(&manager->mutex, NULL);
    manager->cli=NULL;
    manager->credentials=NULL;
    manager->error=0;

    manager->connect_time.tv_sec=0;
    manager->connect_time.tv_nsec=0;

}

int connect_smbcli_manager(struct net_smb_share_struct *smb_share, struct smbcli_manager_struct *manager, unsigned int *error)
{
    struct net_smb_server_struct *smb_server=smb_share->server;
    struct workspace_host_struct *host=NULL;
    char *name=NULL;
    int result=0;
    NTSTATUS status;

    /* which name of the host to use */

    host=smb_server->host;

    if (host->hostname) {

	name=host->hostname;

    } else if (strlen(host->ipv4)>0) {

	name=host->ipv4;

    } else if (strlen(host->ipv6)>0) {

	name=host->ipv6;

    } else if (smb_server->netbiosname) {

	/* resolving using the netbiosname as last, cause netbios is not native protocol for unix/linux */

	name=smb_server->netbiosname;

    }

    get_current_time(&manager->connect_time);


    /* connect to server/share */

    status = smbcli_full_connection(manager->memory_ctx, &manager->cli, name, global_ports, smb_share->name,
 				    NULL, global_socket_options, manager->credentials, global_resolve_context, 
				    global_eventloop, &global_smb_options, &global_smb_session_options,
				    global_gensec_settings);


    if (NT_STATUS_IS_OK(status)) {

	/* connected */

	*error=0;
	manager->error=0;

    } else {

	logoutput("connect_smbcli_manager: connection failed to %s on %s, error %s", smb_share->name, name, nt_errstr(status));

	/*
	    cannot find function to map a SAMBA/NT error to a linux one 
	    take EIO
	*/

	manager->error=EIO;
	*error=EIO;
	result=-1;

    }

    return result;

}


/*
    create a manager per share for smbcli
*/

int create_smbcli_manager(struct net_smb_share_struct *smb_share, unsigned int *error)
{
    struct smbcli_manager_struct *manager=NULL;
    int result=0;

    logoutput("create_smbcli_manager");

    pthread_mutex_lock(&init_mutex);

    if (initialized==0) {

	if (init_smbcli(error)==-1) {

	    logoutput("create_smbcli_manager: unable to intialize");
	    pthread_mutex_unlock(&init_mutex);
	    return -1;

	}

	initialized=1;

    }

    pthread_mutex_unlock(&init_mutex);

    manager=malloc(sizeof(struct smbcli_manager_struct));

    if (manager) {

	smb_share->context = (void *) manager;

	init_smbcli_manager(manager);

	if (create_smbcli_context(manager, error)==0) {
	    struct net_smb_server_struct *smb_server=smb_share->server;
	    NTSTATUS status;

	    /* set credentials */

	    manager->credentials=cli_credentials_init(manager->memory_ctx);
	    cli_credentials_set_conf(manager->credentials, lp_ctx);

	    if (smb_server->authmethod==WORKSPACE_SMB_AUTHMETHOD_GUEST) {

		cli_credentials_set_anonymous(manager->credentials);
		cli_credentials_set_kerberos_state(manager->credentials, CRED_DONT_USE_KERBEROS);

	    } else if (smb_server->authmethod==WORKSPACE_SMB_AUTHMETHOD_PASSWORD) {
		struct workspace_smb_password_struct *smb_password=(struct workspace_smb_password_struct *) smb_server->authdata;

		cli_credentials_set_username(manager->credentials, smb_password->username, CRED_SPECIFIED);
		cli_credentials_set_password(manager->credentials, smb_password->password, CRED_SPECIFIED);

		cli_credentials_set_kerberos_state(manager->credentials, CRED_DONT_USE_KERBEROS);

	    } else {

		/* set to guest for everything else */

		cli_credentials_set_anonymous(manager->credentials);
		cli_credentials_set_kerberos_state(manager->credentials, CRED_DONT_USE_KERBEROS);

	    }

	} else {

	    logoutput("create_smbcli_manager: unable to create memory context");
	    result=-1;

	}


    }

    return result;

}

/*
    construct a SMB path (replace a slash by a backslash
*/

void convert_path_smb(struct pathinfo_struct *pathinfo, char *path)
{

    if (strlen(path)==0) {

	pathinfo->path=(char *) smb_rootpath;
	pathinfo->len=1;
	pathinfo->flags=0;

    } else {
	char *sep=strchr(path, '/');

	pathinfo->path=path;
	pathinfo->len=strlen(path);
	pathinfo->flags=PATHINFO_FLAGS_INUSE;

	while(sep) {

	    *sep=backslash;
	    sep++;
	    sep=strchr(sep, '/');

	}

	logoutput("convert_path_smb: converted %s", path);

    }

}

void convert_path_smb_reverse(struct pathinfo_struct *pathinfo)
{

    if (pathinfo->flags==PATHINFO_FLAGS_INUSE) {
	char *sep=strchr(pathinfo->path, backslash);

	while(sep) {

	    *sep='/';
	    sep++;
	    sep=strchr(sep, backslash);

	}

    }

}
