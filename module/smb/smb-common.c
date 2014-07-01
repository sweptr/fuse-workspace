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

#include <arpa/inet.h>
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
#include "libsmbclient-servers.h"

extern struct fs_options_struct fs_options;
struct smb_options_struct smb_options = SMB_OPTIONS_INITIALIZER;

static struct workspace_smb_password_struct 	*list_passwords=NULL;
static pthread_mutex_t				list_passwords_mutex=PTHREAD_MUTEX_INITIALIZER;

void set_authmethod_default(struct net_smb_server_struct *smb_server)
{
    smb_server->authmethod = WORKSPACE_SMB_AUTHMETHOD_GUEST;
    smb_server->authdata = NULL;

}

/*
    callbacks for setting the uid and gid

    these callbacks are used to change the uid and gid reported by the server

*/

void setuser_stat_none_cb(struct workspace_mount_struct *workspace_mount, struct net_smb_server_struct *smb_server, struct stat *st)
{
    /* do nothing */
}

void setuser_stat_owner_cb(struct workspace_mount_struct *workspace_mount, struct net_smb_server_struct *smb_server, struct stat *st)
{
    struct workspace_user_struct *workspace_user=workspace_mount->workspace_user;

    st->st_uid=workspace_user->private_uidnr;
    st->st_gid=workspace_user->private_gidnr;

}

static int read_credentials_file(char *file, char **username, char **password, unsigned int *error)
{
    FILE *fp;
    int result=0;

    *error=0;

    fp=fopen(file, "r");

    if (fp) {
	char line[256];
	char *sep, *value;

	while (fgets(line, 256, fp)) {

	    sep=strchr(line, '=');
	    if (! sep) continue;

	    convert_to(line, UTILS_CONVERT_SKIPSPACE);

	    *sep='\0';
	    value=sep+1;

	    if (strcmp(line, "username")==0) {

		 if (*username) {

		    /* username already set */

		    logoutput("get_password_authmethod: username specified more than once, ignoring");

		} else {

		    *username=strdup(value);

		    if (! *username) {

			logoutput("get_password_authmethod: error allocating memory for username");
			*error=ENOMEM;
			break;

		    }

		}

	    }

	    if (strcmp(line, "password")==0) {

		 if (*password) {

		    /* password already set */

		    logoutput("get_password_authmethod: password specified more than once, ignoring");

		} else {

		    *password=strdup(value);

		    if (! *password) {

			logoutput("get_password_authmethod: error allocating memory for password");
			*error=ENOMEM;
			break;

		    }

		}

	    }

	}

	if (*error==0) {

	    /* no error, check both username and password are read */

	    if (! *username || ! *password) *error=EINVAL;

	}

	if (*error>0) {

	    if (*username) {

		free(*username);
		*username=NULL;

	    }

	    if (*password) {

		free(*password);
		*password=NULL;

	    }

	}

	fclose(fp);

    } else {

	*error=errno;

    }

    return result;

}

struct workspace_smb_password_struct *get_smb_password_authmethod(char *file)
{
    struct workspace_smb_password_struct *authmethod=NULL;
    unsigned int error=0;

    pthread_mutex_lock(&list_passwords_mutex);

    authmethod=list_passwords;

    while(authmethod) {

	if (strcmp(authmethod->file, file)==0) break;

	authmethod=authmethod->next;

    }

    if ( ! authmethod) {
	char *username=NULL;
	char *password=NULL;

	if (read_credentials_file(file, &username, &password, &error)==0) {
	    char *dupfile=NULL;

	    authmethod=malloc(sizeof(struct workspace_smb_password_struct));
	    dupfile=strdup(file);

	    if (dupfile && authmethod) {

		authmethod->file=dupfile;
		authmethod->username=username;
		authmethod->password=password;

		/* add to simple linked list */

		authmethod->next=list_passwords;
		list_passwords=authmethod;

	    } else {

		if (dupfile) {

		    free(dupfile);
		    dupfile=NULL;

		}

		if (authmethod) {

		    free(authmethod);
		    authmethod=NULL;

		}

		free(username);
		username=NULL;

		free(password);
		password=NULL;

	    }

	}

    }

    pthread_mutex_unlock(&list_passwords_mutex);

    return authmethod;

}

/* struct meant as buffer to test a string is a valid ipv4 or ipv6 string */

struct inet_buff_struct {
    union {
	struct in_addr in;
	struct in6_addr in6;
    } addr;
};

int construct_base_server_uri(struct net_smb_server_struct *smb_server, struct pathinfo_struct *pathinfo, unsigned int *error)
{
    char *smb_uri=NULL;
    unsigned int len=0;
    struct workspace_host_struct *host=smb_server->host;

    logoutput("construct_base_server_uri");

    *error=0;

    /*
	construct the base uri used for communication
	in stead of creating it every time, construct it once

	start with ipv4, next ipv6, next dnsname, last netbiosname
    */

    len=strlen(host->ipv4);

    if (len>0) {
	unsigned int len0=len + 8;

	smb_uri = malloc(len0);

	if (smb_uri) {
	    char *pos=smb_uri;

	    memcpy(pos, "smb://", 6);
	    pos+=6;
	    memcpy(pos, host->ipv4, len);
	    pos+=len;
	    *pos='\0';

	    pathinfo->path=smb_uri;
	    pathinfo->len=len0 - 1; /* len0 includes trailing \0 */
	    pathinfo->flags=PATHINFO_FLAGS_ALLOCATED;

	    logoutput("construct_base_server_uri: uri created %s", smb_uri);

	    return 0;

	} else {

	    *error=ENOMEM;
	    return -1;

	}

    }

    len=strlen(host->ipv6);

    if (len>0) {
	unsigned int len0=len + 8;

	smb_uri = malloc(len0);

	if (smb_uri) {
	    char *pos=smb_uri;

	    memcpy(pos, "smb://", 6);
	    pos+=6;
	    memcpy(pos, host->ipv6, len);
	    pos+=len;

	    *pos='\0';

	    pathinfo->path=smb_uri;
	    pathinfo->len=len0 - 1; /* len0 includes trailing \0 */
	    pathinfo->flags=PATHINFO_FLAGS_ALLOCATED;

	    logoutput("construct_base_server_uri: uri created %s", smb_uri);

	    return 0;

	} else {

	    *error=ENOMEM;
	    return -1;

	}

    }

    len=host->len_hostname;

    if (len>0) {
	unsigned int len0=len + 8;

	smb_uri = malloc(len0);

	if (smb_uri) {
	    char *pos=smb_uri;

	    memcpy(pos, "smb://", 6);
	    pos+=6;
	    memcpy(pos, host->hostname, len);
	    pos+=len;
	    *pos='\0';

	    pathinfo->path=smb_uri;
	    pathinfo->len=len0 - 1; /* len0 includes trailing \0 */
	    pathinfo->flags=PATHINFO_FLAGS_ALLOCATED;

	    logoutput("construct_base_share_uri: uri created %s", smb_uri);

	    return 0;

	} else {

	    *error=ENOMEM;
	    return -1;

	}

    }

    len=smb_server->len;

    if (len>0) {
	unsigned int len0=len + 8;

	smb_uri = malloc(len0);

	if (smb_uri) {
	    char *pos=smb_uri;

	    memcpy(pos, "smb://", 6);
	    pos+=6;
	    memcpy(pos, smb_server->netbiosname, len);
	    pos+=len;
	    *pos='\0';

	    pathinfo->path=smb_uri;
	    pathinfo->len=len0 - 1; /* len0 includes trailing \0 */
	    pathinfo->flags=PATHINFO_FLAGS_ALLOCATED;

	    logoutput("construct_base_share_uri: uri created %s", smb_uri);

	    return 0;

	} else {

	    *error=ENOMEM;
	    return -1;

	}

    }

    *error=EINVAL;
    return -1;

}
/*
    function which create the base path for every share

    when using the smbclient functions like smbc_stat and smbc_opendir, the path
    is something like:

    smb://servername/sharename/path/in/share

    this function creates the first part

    smb://servername/sharename

    so this is not necessary everytime over and over again

    note:

    this function tries several addresses/names in the following order:
    - ipv4
    - ipv6
    - hostname
    - netbiosname

*/

int construct_base_share_uri(struct net_smb_share_struct *smb_share, struct pathinfo_struct *pathinfo, unsigned int *error)
{
    char *smb_uri=NULL;
    unsigned int len=0;
    struct net_smb_server_struct *smb_server=smb_share->server;
    struct workspace_host_struct *host=smb_server->host;

    logoutput("construct_base_share_uri");

    *error=0;

    /*
	construct the base uri used for communication
	in stead of creating it every time, construct it once

	start with ipv4, next ipv6, next dnsname, last netbiosname
    */

    len=strlen(host->ipv4);

    if (len>0) {
	unsigned int len0=len + 8 + smb_share->len;

	smb_uri = malloc(len0);

	if (smb_uri) {
	    char *pos=smb_uri;

	    memcpy(pos, "smb://", 6);
	    pos+=6;
	    memcpy(pos, host->ipv4, len);
	    pos+=len;
	    *pos='/';
	    pos++;
	    memcpy(pos, smb_share->name, smb_share->len);
	    pos+=smb_share->len;
	    *pos='\0';

	    pathinfo->path=smb_uri;
	    pathinfo->len=len0 - 1; /* len0 includes trailing \0 */
	    pathinfo->flags=PATHINFO_FLAGS_ALLOCATED;

	    logoutput("construct_base_share_uri: uri created %s", smb_uri);

	    return 0;

	} else {

	    *error=ENOMEM;
	    return -1;

	}

    }

    len=strlen(host->ipv6);

    if (len>0) {
	unsigned int len0=len + 8 + smb_share->len;

	smb_uri = malloc(len0);

	if (smb_uri) {
	    char *pos=smb_uri;

	    memcpy(pos, "smb://", 6);
	    pos+=6;
	    memcpy(pos, host->ipv6, len);
	    pos+=len;
	    *pos='/';
	    pos++;
	    memcpy(pos, smb_share->name, smb_share->len);
	    pos+=smb_share->len;
	    *pos='\0';

	    pathinfo->path=smb_uri;
	    pathinfo->len=len0 - 1; /* len0 includes trailing \0 */
	    pathinfo->flags=PATHINFO_FLAGS_ALLOCATED;

	    logoutput("construct_base_share_uri: uri created %s", smb_uri);

	    return 0;

	} else {

	    *error=ENOMEM;
	    return -1;

	}

    }

    len=host->len_hostname;

    if (len>0) {
	unsigned int len0=len + 8 + smb_share->len;

	smb_uri = malloc(len0);

	if (smb_uri) {
	    char *pos=smb_uri;

	    memcpy(pos, "smb://", 6);
	    pos+=6;
	    memcpy(pos, host->hostname, len);
	    pos+=len;
	    *pos='/';
	    pos++;
	    memcpy(pos, smb_share->name, smb_share->len);
	    pos+=smb_share->len;
	    *pos='\0';

	    pathinfo->path=smb_uri;
	    pathinfo->len=len0 - 1; /* len0 includes trailing \0 */
	    pathinfo->flags=PATHINFO_FLAGS_ALLOCATED;

	    logoutput("construct_base_share_uri: uri created %s", smb_uri);

	    return 0;

	} else {

	    *error=ENOMEM;
	    return -1;

	}

    }

    len=smb_server->len;

    if (len>0) {
	unsigned int len0=len + 8 + smb_share->len;

	smb_uri = malloc(len0);

	if (smb_uri) {
	    char *pos=smb_uri;

	    memcpy(pos, "smb://", 6);
	    pos+=6;
	    memcpy(pos, smb_server->netbiosname, len);
	    pos+=len;
	    *pos='/';
	    pos++;
	    memcpy(pos, smb_share->name, smb_share->len);
	    pos+=smb_share->len;
	    *pos='\0';

	    pathinfo->path=smb_uri;
	    pathinfo->len=len0 - 1; /* len0 includes trailing \0 */
	    pathinfo->flags=PATHINFO_FLAGS_ALLOCATED;

	    logoutput("construct_base_share_uri: uri created %s", smb_uri);

	    return 0;

	} else {

	    *error=ENOMEM;
	    return -1;

	}

    }

    *error=EINVAL;
    return -1;

}

/*
    this function creates the full smb uri like

    smb://servername/sharename/path/in/share

    it does that by putting together the base path which is present already for every share
    and the path in that share

    note:
    the path in the share has to be decoded

*/

int construct_decoded_smb_path(struct net_smb_share_struct *smb_share, char *path, unsigned int len, struct pathinfo_struct *pathinfo, unsigned int *error)
{

    logoutput("construct_decoded_smb_path");

    if (len==0) {

	/* just take the base path for this share */

	pathinfo->path=smb_share->pathinfo.path;
	pathinfo->len=smb_share->pathinfo.len;
	pathinfo->flags=smb_share->pathinfo.flags | PATHINFO_FLAGS_INUSE;

	logoutput("construct_decoded_smb_path: simple path %s", pathinfo->path);

	return 0;

    } else {
	char *decoded_path=malloc(smb_share->pathinfo.len + 2 + len);

	if (decoded_path) {
	    char *pos=decoded_path;
	    char *slash, *name=path;
	    char enc_name[255]; /* use a constant here ? */
	    unsigned int len0;

	    memcpy(pos, smb_share->pathinfo.path, smb_share->pathinfo.len);
	    pos+=smb_share->pathinfo.len;
	    *pos='/';
	    pos++;

	    while(1) {

		slash=strchr(name, '/');

		if (slash==name) {

		    name++;
		    if (*name=='\0') break;
		    continue;

		}

		if (slash) *slash='\0';
		smbc_urlencode(enc_name, name, 255);

		len0=strlen(enc_name);
		memcpy(pos, enc_name, len0);

		pos+=len0;

		if ( ! slash) {

		    *pos='\0';
		    break;

		}

		*pos='/';
		pos++;

		*slash='/';
		name=slash+1;

	    }

	    pos+=len;
	    *pos='\0';

	    pathinfo->path=decoded_path;
	    pathinfo->len=smb_share->pathinfo.len + 2 + len;
	    pathinfo->flags = PATHINFO_FLAGS_ALLOCATED;

	    logoutput("construct_decoded_smb_path: path %s", pathinfo->path);

	    *error=0;
	    return 0;

	} else {

	    logoutput("construct_decoded_smb_path: memory error");
	    *error=ENOMEM;

	}

    }

    return -1;

}

/*
    create a SMB server
*/

struct workspace_object_struct *workspace_smb_connect_server(struct workspace_uri_struct *uri, struct workspace_mount_struct *workspace, unsigned int *error)
{
    struct workspace_object_struct *object=NULL;
    struct resource_struct *resource=NULL;
    struct net_smb_server_struct *smb_server;
    struct workspace_host_struct *host=NULL;
    int family=0;
    struct inet_buff_struct inet_buff;
    char *name=NULL;
    unsigned char type_name=0;
    unsigned int len_name=0;

    logoutput("workspace_smb_connect_server: try %s", uri->address);

    /*
	test path is a valid address (only ip for now, ipv4 or ipv6)
    */

    if (inet_pton(AF_INET, uri->address, &inet_buff.addr)==1) {

	family=AF_INET;
	host=get_host_ipv4(uri->address);

	if (host) {

	    type_name=HOSTNAME_TYPE_IPV4;
	    name=host->ipv4;
	    len_name=INET_ADDRSTRLEN;

	}

    } else if (inet_pton(AF_INET6, uri->address, &inet_buff.addr)==1) {

	family=AF_INET6;
	type_name=HOSTNAME_TYPE_IPV6;

    } else {

	*error=EINVAL;
	return NULL;

    }

    if (! host) {

	*error=EINVAL;
	return NULL;

    }

    if (smb_options.init==0) read_smb_options();

    /*
	- test server does exist
	how? opendir("smb://netbiosname") should not give an error
    */


    object=get_workspace_object();

    if (! object) {

	*error=ENOMEM;
	return NULL;

    }

    object->primary=1;
    object->workspace_mount=workspace;

    /* howto browse this server */

    if (smb_options.browse_use_smbclient) {

	set_module_calls_libsmbclient_server(&object->module_calls);

    }

    lock_resources();

    /* look for existing SMB servers */

    resource=get_next_resource(NULL);

    while(resource) {

	if (resource->group==RESOURCE_GROUP_SMB && resource->type==SMB_TYPE_SERVER) {

	    /* look for public nfs servers (although they are always public....) */

	    if (resource->security==RESOURCE_SECURITY_PUBLIC) {

		smb_server=(struct net_smb_server_struct *) resource->data;

		if (smb_server->host) {

		    if (smb_server->host==host) break;

		}

	    }

	}

	resource=get_next_resource(resource);

    }

    if (resource) {

	resource->refcount++;
	object->resource=resource;

    } else {

	resource=get_resource();
	smb_server=malloc(sizeof(struct net_smb_server_struct));

	if (resource && smb_server) {

	    resource->security=RESOURCE_SECURITY_PUBLIC;
	    resource->status=RESOURCE_STATUS_OK;
	    resource->group=RESOURCE_GROUP_SMB;
	    resource->type=SMB_TYPE_SERVER;

	    resource->data=(void *) smb_server;
	    resource->refcount=1;

	    smb_server->netbiosname=NULL;
	    smb_server->host=host;
	    smb_server->forceuser=uri->type.smbinfo.forceuser;
	    smb_server->workgroup=NULL;

	    smb_server->pathinfo.path=NULL;
	    smb_server->pathinfo.len=0;
	    smb_server->pathinfo.flags=0;

	    /*
		set the function to set the uid and the gid
	    */

	    if (uri->type.smbinfo.forceuser==WORKSPACE_FORCEUSER_OWNER) {

		smb_server->setuser_stat=setuser_stat_owner_cb;

	    } else {

		smb_server->setuser_stat=setuser_stat_none_cb;

	    }

	    /*
		set the authmethod (guest, password or kerberos)
	    */

	    if (uri->type.smbinfo.authmethod==WORKSPACE_AUTHMETHOD_GUEST) {

		smb_server->authmethod = WORKSPACE_SMB_AUTHMETHOD_GUEST;

	    } else if (uri->type.smbinfo.authmethod==WORKSPACE_AUTHMETHOD_KERBEROS) {

		smb_server->authmethod = WORKSPACE_SMB_AUTHMETHOD_KERBEROS;

	    } else if (uri->type.smbinfo.authmethod==WORKSPACE_AUTHMETHOD_PASSWORD) {

		smb_server->authmethod = WORKSPACE_SMB_AUTHMETHOD_PASSWORD;
		smb_server->authdata = (void *) get_smb_password_authmethod(uri->type.smbinfo.authdata);

		if (! smb_server->authdata) {

		    logoutput("workspace_smb_connect_server: error: set default autmethod");

		    set_authmethod_default(smb_server);

		}

	    } else if (uri->type.smbinfo.authmethod==WORKSPACE_AUTHMETHOD_DEFAULT) {

		set_authmethod_default(smb_server);

	    }

	    if (construct_base_server_uri(smb_server, &smb_server->pathinfo, error)==0) {

		logoutput("create smb server object: uri %s", smb_server->pathinfo.path);

	    } else {

		logoutput("create smb server object: failed to create uri for %s, error %i", name, *error);

	    }

	    insert_resource_list(resource);

	    object->resource=resource;

	} else {

	    if (resource) {

		free_resource(resource);
		resource=NULL;

	    }

	    if (smb_server) {

		free(smb_server);
		smb_server=NULL;

	    }

	    free(object);
	    object=NULL;

	    *error=ENOMEM;

	}

    }

    unlock:

    unlock_resources();

    return object;

}

struct workspace_object_struct *create_smb_share_object(char *name, struct workspace_object_struct *server_object, unsigned int *error)
{

    /* here:

	create a smb_context (per share)
	mount export using 

    */

    struct workspace_object_struct *object=NULL;
    struct resource_struct *resource=NULL;
    struct net_smb_share_struct *smb_share;

    object=get_workspace_object();

    if (! object) {

	*error=ENOMEM;
	return NULL;

    }

    logoutput("create smb share object: %s", name);

    object->primary=1;
    object->parent=server_object;
    object->workspace_mount=server_object->workspace_mount;

    lock_resources();

    /* look for existing NFS servers */

    resource=get_next_resource(NULL);

    while(resource) {

	if (resource->group==RESOURCE_GROUP_SMB && resource->type==SMB_TYPE_SHARE) {

	    /* look for public smb shares (just public for now) */

	    if (resource->security==RESOURCE_SECURITY_PUBLIC) {

		smb_share=(struct net_smb_share_struct *) resource->data;

		if (smb_share->name) {

		    if (strcmp(smb_share->name, name)==0) break;

		}

	    }

	}

	resource=get_next_resource(resource);

    }

    if (resource) {

	resource->refcount++;
	object->resource=resource;
	object->parent=server_object;
	object->workspace_mount=server_object->workspace_mount;

    } else {

	resource=get_resource();
	smb_share=malloc(sizeof(struct net_smb_share_struct));

	if (resource && smb_share) {
	    struct resource_struct *server_resource=server_object->resource;
	    struct net_smb_server_struct *smb_server=(struct net_smb_server_struct *) server_resource->data;

	    resource->security=RESOURCE_SECURITY_PUBLIC;
	    resource->status=RESOURCE_STATUS_OK;
	    resource->group=RESOURCE_GROUP_SMB;
	    resource->type=SMB_TYPE_SHARE;

	    resource->data=(void *) smb_share;
	    resource->refcount=1;

	    smb_share->name=strdup(name);
	    smb_share->len=strlen(name);
	    smb_share->server=smb_server;
	    smb_share->context=NULL;

	    pthread_mutex_init(&smb_share->mutex, NULL);

	    if (construct_base_share_uri(smb_share, &smb_share->pathinfo, error)==0) {

		logoutput("create smb share object: uri %s", smb_share->pathinfo.path);

	    } else {

		logoutput("create smb share object: failed to create uri for %s, error %i", name, *error);

	    }

	    insert_resource_list(resource);

	    object->resource=resource;

	} else {

	    if (resource) {

		free_resource(resource);
		resource=NULL;

	    }

	    if (smb_share) {

		free(smb_share);
		smb_share=NULL;

	    }

	    free(object);
	    object=NULL;

	    *error=ENOMEM;

	}

    }

    unlock:

    unlock_resources();

    return object;

}

#define DEFAULT_SMB_OPTIONS_FILENAME 		"smb.config"

static void _read_smb_options(char *path)
{
    FILE *fp;
    unsigned int len0 = strlen(path);
    unsigned int len =  len0 + 2 + strlen(DEFAULT_SMB_OPTIONS_FILENAME);
    char *pos = NULL;
    char configpath[len];
    char line[256];
    char *option, *value;

    /* set defaults */

    /* howto browse the network neighbourhood: server and shares
    */

    smb_options.browse_use_smbclient=1;
    smb_options.browse_use_cache=1;

    smb_options.share_use_smbclient=0;
    smb_options.share_use_vfsmount=1;
    smb_options.share_use_smbcli=1;

    smb_options.smbclient_retryperiod_onerror=10;
    smb_options.authmethod=NULL;

    /* where is the smb config file ?? */

    snprintf(configpath, len, "%s/%s", path, DEFAULT_SMB_OPTIONS_FILENAME);

    fp=fopen(configpath, "r");

    if (fp) {

	while( ! feof(fp)) {

	    if ( ! fgets(line, 256, fp)) continue;

	    pos=strchr(line, '\n');
	    if (pos) *pos='\0';

	    pos=strchr(line, '=');
	    if (!pos) continue;

	    *pos='\0';
	    option=line;
	    value=pos+1;

	    if (strcmp(option, "smb.browse.use.cache")==0) {

		if (atoi(value)>0) {

		    smb_options.browse_use_cache=1;

		}

#ifdef HAVE_LIBSMBCLIENT

	    } else if (strcmp(option, "smb.browse.use.smbclient")==0) {

		/* howto browse the smb network */

		if (atoi(value)>0) {

		    smb_options.browse_use_smbclient=1;

		}

	    } else if (strcmp(option, "smb.share.use.smbclient")==0) {

		/* howto access a smb share: use libsmbclient */

		if (atoi(value)>0) {

		    smb_options.share_use_smbclient=1;

		}

#endif

	    } else if (strcmp(option, "smb.share.use.smbcli")==0) {

		/* howto access a smb share: use libsmbclient */

		if (atoi(value)>0) {

		    smb_options.share_use_smbcli=1;

		}


	    } else if (strcmp(option, "smb.share.use.vfsmount")==0) {

		/* howto access a smb share: use libsmbclient */

		if (atoi(value)>0) {

		    smb_options.share_use_vfsmount=1;

		}

	    } else if (strcmp(option, "smb.authmethod")==0) {

		/* global authmethod */

		if (strlen(value)>0) {

		    if (strcmp(value, "guest")==0) {

			smb_options.authmethod=strdup(value);

		    } else if (strncmp(value, "file://", 7)==0) {

			smb_options.authmethod=strdup(value);

		    } else if (strcmp(value, "kerberos")==0) {

			smb_options.authmethod=strdup(value);

		    }

		}

	    }

	}

	fclose(fp);

    }

}


void read_smb_options()
{

    if (fs_options.basemap) {

	_read_smb_options(fs_options.basemap);

    } else {

	_read_smb_options(FUSE_WORKSPACE_BASEMAP);

    }

    smb_options.init=1;

}

