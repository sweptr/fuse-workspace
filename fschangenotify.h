/*
  2010, 2011 Stef Bon <stefbon@gmail.com>

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

#ifndef _WATCHES_H
#define _WATCHES_H

struct notifywatch_struct {
    unsigned long ctr;
    struct inode_struct *inode;
    struct pathinfo_struct pathinfo;
    uint32_t mask;
    pthread_mutex_t mutex;
    void *backend;
};

// Prototypes

void lock_watch(struct notifywatch_struct *watch);
void unlock_watch(struct notifywatch_struct *watch);

struct notifywatch_struct *lookup_watch_inode(struct inode_struct *inode);
void add_watch_inodetable(struct notifywatch_struct *watch);
void remove_watch_inodetable(struct notifywatch_struct *watch);

struct notifywatch_struct *lookup_watch_ctr(unsigned int ctr);
void add_watch_ctrtable(struct notifywatch_struct *watch);
void remove_watch_ctrtable(struct notifywatch_struct *watch);

struct notifywatch_struct *add_notifywatch(struct inode_struct *inode, uint32_t mask, struct pathinfo_struct *pathinfo);
void change_notifywatch(struct notifywatch_struct *watch);

int init_fschangenotify(unsigned int *error);
void end_fschangenotify();

#endif
