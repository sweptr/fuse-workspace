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

#include <libsmbclient.h>

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

#include "workspaces.h"
#include "resources.h"
#include "objects.h"

#include "smb-common.h"
#include "libsmbclient-common.h"
#include "libsmbclient-servers.h"

extern struct fs_options_struct fs_options;
extern struct smb_options_struct smb_options;

static void smbclient_doauth_with_ctx(SMBCCTX *context, const char *smbserver, const char *smbshare, char *smbworkgroup, int lenwg, char *user, int lenuser, char *pw, int lenpw)
{
    struct smbclient_manager_struct *manager =NULL;

    logoutput("smbclient_doauth_with_ctx");

    manager=(struct smbclient_manager_struct *) smbc_getOptionUserData(context);

    if (manager->smb_share) {
	struct net_smb_share_struct *smb_share = NULL;
	struct net_smb_server_struct *smb_server = NULL;

	smb_share = manager->smb_share;
	smb_server = smb_share->server;

	/* auth is done per server */

	if (smb_server->authmethod==WORKSPACE_SMB_AUTHMETHOD_GUEST || smb_server->authmethod==WORKSPACE_SMB_AUTHMETHOD_KERBEROS) {

	    /* guest or kerberos: nothing specially required here, everything is already set when creating the smbclient context */

	    return;

	} else if (smb_server->authmethod==WORKSPACE_SMB_AUTHMETHOD_PASSWORD) {
	    struct workspace_smb_password_struct *smb_password=NULL;

	    smb_password=(struct workspace_smb_password_struct *) smb_server->authdata;

	    /* set the user */

	    strncpy(user, smb_password->username, lenuser);

	    /* set the password */

	    strncpy(pw, smb_password->password, lenpw);

	}

    }

}

int create_smbclient_context(struct smbclient_manager_struct *manager, unsigned int *error)
{
    SMBCCTX *context=NULL;

    context=smbc_new_context();

    if (context) {
	unsigned char smb_authmethod=WORKSPACE_SMB_AUTHMETHOD_GUEST;

	/*
	    test for the server which authmethod to use
	    it's possible that there is no share specified
	    that is possible when the context is used for browsing the
	    shares per server
	    in that case guest authification is used
	*/

	if (manager->smb_share) {
	    struct net_smb_share_struct *smb_share = manager->smb_share;
	    struct net_smb_server_struct *smb_server = smb_share->server;

	    smb_authmethod=smb_server->authmethod;

	}

	smbc_init_context(context);

	/* link the manager to the context */

	smbc_setOptionUserData(context, (void *) manager);

	/* set some defaults */

	smbc_setFunctionAuthDataWithContext(context, smbclient_doauth_with_ctx);

	if (smb_authmethod==WORKSPACE_SMB_AUTHMETHOD_GUEST) {

	    smbc_setOptionUseKerberos(context, 0);
	    smbc_setOptionNoAutoAnonymousLogin(context, 0);

	} else if (smb_authmethod==WORKSPACE_SMB_AUTHMETHOD_PASSWORD) {

	    smbc_setOptionUseKerberos(context, 0);
	    smbc_setOptionNoAutoAnonymousLogin(context, 1);

	} else if (smb_authmethod==WORKSPACE_SMB_AUTHMETHOD_KERBEROS) {

	    smbc_setOptionUseKerberos(context, 1);
	    smbc_setOptionNoAutoAnonymousLogin(context, 0);

	} else {

	    /* guest for everything else */

	    smbc_setOptionUseKerberos(context, 0);
	    smbc_setOptionNoAutoAnonymousLogin(context, 0);

	}

	smbc_set_context(context);
	manager->context = context;

    } else {

	*error=ENOMEM;
	return -1;

    }

    return 0;

}


void init_smbclient_manager(struct smbclient_manager_struct *manager)
{

    pthread_mutex_init(&manager->mutex, NULL);
    pthread_cond_init(&manager->cond, NULL);
    manager->inuse=0;
    manager->context=NULL;
    manager->error=0;
    manager->smb_share=NULL;

    manager->connect_time.tv_sec=0;
    manager->connect_time.tv_nsec=0;

}

struct smbclient_manager_struct *create_smbclient_manager()
{
    struct smbclient_manager_struct *manager=NULL;

    manager=malloc(sizeof(struct smbclient_manager_struct));

    if (manager) {
	unsigned int error=0;

	init_smbclient_manager(manager);

    }

    return manager;

}

