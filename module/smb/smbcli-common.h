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

#ifndef FUSE_SMBCLI_COMMON_H
#define FUSE_SMBCLI_COMMON_H

/* struct per connection to server/share */

struct smbcli_manager_struct {
    TALLOC_CTX				*memory_ctx;
    struct smbcli_state 		*cli;
    struct cli_credentials 		*credentials;
    pthread_mutex_t			mutex;
    struct timespec			connect_time;
    unsigned int			error;
};

int create_smbcli_manager(struct net_smb_share_struct *smb_share, unsigned int *error);
int connect_smbcli_manager(struct net_smb_share_struct *smb_share, struct smbcli_manager_struct *manager, unsigned int *error);

void convert_path_smb(struct pathinfo_struct *pathinfo, char *path);
void convert_path_smb_reverse(struct pathinfo_struct *pathinfo);

#endif
