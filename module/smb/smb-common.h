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

#ifndef FUSE_SMB_COMMON_H
#define FUSE_SMB_COMMON_H

#define WORKSPACE_SMB_AUTHMETHOD_GUEST					1
#define WORKSPACE_SMB_AUTHMETHOD_KERBEROS				2
#define WORKSPACE_SMB_AUTHMETHOD_PASSWORD				3
#define WORKSPACE_SMB_AUTHMETHOD_DEFAULT				4

struct workspace_smb_password_struct {
    char					*file;
    char					*username;
    char					*password;
    struct workspace_smb_password_struct	*next;
};

struct smb_options_struct {
    unsigned char 	browse_use_smbclient;
    unsigned int 	smbclient_retryperiod_onerror;
    unsigned char 	browse_use_cache;
    unsigned char 	share_use_smbclient;
    unsigned char 	share_use_vfsmount;
    unsigned char	share_use_smbcli;
    unsigned char 	init;
    char		*authmethod;
};

#define SMB_OPTIONS_INITIALIZER			{0, 0, 0, 0, 0, 0, 0, NULL}

int construct_base_share_uri(struct net_smb_share_struct *smb_share, struct pathinfo_struct *pathinfo, unsigned int *error);
int construct_base_server_uri(struct net_smb_server_struct *smb_server, struct pathinfo_struct *pathinfo, unsigned int *error);

int construct_decoded_smb_path(struct net_smb_share_struct *smb_share, char *path, unsigned int len, struct pathinfo_struct *pathinfo, unsigned int *error);

struct workspace_object_struct *workspace_smb_connect_server(struct workspace_uri_struct *uri, struct workspace_mount_struct *workspace, unsigned int *error);
struct workspace_object_struct *create_smb_share_object(char *name, struct workspace_object_struct *server_object, unsigned int *error);

void read_smb_options();

#endif
