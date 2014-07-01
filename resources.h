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

#ifndef FUSE_WORKSPACE_RESOURCES_H
#define FUSE_WORKSPACE_RESOURCES_H

#include <netinet/in.h>

#define RESOURCE_GROUP_DISK			1
#define RESOURCE_GROUP_CDROM			2
#define RESOURCE_GROUP_SMB			3
#define RESOURCE_GROUP_FTP			4
#define RESOURCE_GROUP_FILE			5
#define RESOURCE_GROUP_NFS			6

#define RESOURCE_GROUP_MAX			6

#define RESOURCE_SECURITY_NOTSET                0
#define RESOURCE_SECURITY_PRIVATE               1
#define RESOURCE_SECURITY_PUBLIC                2
#define RESOURCE_SECURITY_UNKNOWN               3

#define RESOURCE_STATUS_OK                      1
#define RESOURCE_STATUS_NOTAVAIL                2
#define RESOURCE_STATUS_NOTVALID                3
#define RESOURCE_STATUS_NOPARENT		4

#define NFS_TYPE_NOTSET				0
#define NFS_TYPE_NETWORK			1
#define NFS_TYPE_SERVER				2
#define NFS_TYPE_EXPORT				3
#define NFS_TYPE_UNKNOWN			4

#define SMB_TYPE_NOTSET				0
#define SMB_TYPE_NETWORK			1
#define SMB_TYPE_WORKGROUP			2
#define SMB_TYPE_SERVER				3
#define SMB_TYPE_SHARE				4
#define SMB_TYPE_UNKNOWN			5

#define SMB_PATH_LEN 1024

#define HOSTNAME_TYPE_DNSNAME			1
#define HOSTNAME_TYPE_IPV4			2
#define HOSTNAME_TYPE_IPV6			3
#define HOSTNAME_TYPE_NETBIOS			4

#define WORKSPACE_FORCEUSER_NONE		0
#define WORKSPACE_FORCEUSER_OWNER		1
#define WORKSPACE_FORCEUSER_GUEST		2
#define WORKSPACE_FORCEUSER_DEFAULT		3

#define WORKSPACE_AUTHMETHOD_GUEST		0
#define WORKSPACE_AUTHMETHOD_PASSWORD		1
#define WORKSPACE_AUTHMETHOD_KERBEROS		2
#define WORKSPACE_AUTHMETHOD_DEFAULT		3


struct workspace_uri_struct {
    unsigned int 				group;
    char					*address;
    union {
	struct smbinfo_s {
	    unsigned char			authmethod;
	    char 				*authdata;
	    unsigned char			forceuser;
	} smbinfo;
	struct nfsinfo_s {
	    unsigned char			forceuser;
	} nfsinfo;

    } type;
};

struct workspace_host_struct {
    unsigned int 				options;
    char 					*hostname;
    unsigned int				len_hostname;
    char 					ipv4[INET_ADDRSTRLEN+1];
    char					ipv6[INET6_ADDRSTRLEN+1];
    struct workspace_host_struct		*next;
};

/* smb server */

struct net_smb_server_struct {
    char 					*netbiosname;
    unsigned int 				len;
    char 					*workgroup;
    struct workspace_host_struct		*host;
    unsigned char				forceuser;
    struct pathinfo_struct			pathinfo;
    unsigned char 				authmethod;
    void					*authdata;
    void 					(* setuser_stat)(struct workspace_mount_struct *workspace_mount, struct net_smb_server_struct *server, struct stat *st);
};

/* smb share */

struct net_smb_share_struct {
    char 					*name;
    unsigned int 				len;
    struct net_smb_server_struct		*server;
    void 					*context;
    struct pathinfo_struct			pathinfo;
    pthread_mutex_t				mutex;
};


/* nfs server */

struct net_nfs_server_struct {
    struct workspace_host_struct		*host;
    struct timespec 				detect_time;
    struct timespec 				refresh_time;
    void 					*data;
};

/* nfs export*/

struct net_nfs_export_struct {
    struct pathinfo_struct			pathinfo;
    struct timespec 				detect_time;
    struct timespec 				refresh_time;
    void 					*data;
    pthread_mutex_t				mutex;
};

struct localfile_struct {
    unsigned char 				options;
    struct pathinfo_struct 			pathinfo;
};

struct resource_struct {
    unsigned char 			security;
    unsigned char	 		group;
    unsigned char 			type;
    unsigned char 			status;
    int 				refcount;
    struct timespec 			detecttime_cache;
    struct timespec 			detecttime_browse;
    struct resource_struct 		*next;
    struct resource_struct 		*prev;
    struct resource_struct 		*parent;
    void 				*data;
    unsigned char 			primary;
    pthread_rwlock_t 			rwlock;
};

// Prototypes

/* manage resources */

void init_resource(struct resource_struct *resource);
struct resource_struct *get_resource();
void free_resource(struct resource_struct *resource);

int lock_resources();
int unlock_resources();
struct resource_struct *get_next_resource(struct resource_struct *resource);
void insert_resource_list(struct resource_struct *resource);
void remove_resource_list(struct resource_struct *resource);

struct workspace_host_struct *get_host_ipv4(char *ipv4);

void free_workspace_uri(struct workspace_uri_struct *uri);

#endif
