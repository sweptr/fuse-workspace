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

#ifndef FUSE_LIBSMBCLIENT_COMMON_H
#define FUSE_LIBSMBCLIENT_COMMON_H

#define SMB_PATH_LEN 1024

struct smbclient_manager_struct {
    SMBCCTX			*context;
    pthread_mutex_t		mutex;
    pthread_cond_t		cond;
    unsigned char		inuse;
    struct timespec		connect_time;
    struct net_smb_share_struct *smb_share;
    unsigned int 		error;
};

int create_smbclient_context(struct smbclient_manager_struct *manager, unsigned int *error);
void init_smbclient_manager(struct smbclient_manager_struct *manager);
struct smbclient_manager_struct *create_smbclient_manager();

#endif
