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

#ifndef _FSCHANGENOTIFY_H
#define _FSCHANGENOTIFY_H

#define NOTIFYWATCH_BACKEND_OS				1
#define NOTIFYWATCH_BACKEND_FSSYNC			2

#define NOTIFYWATCH_FLAG_SYSTEM				1
#define NOTIFYWATCH_FLAG_NOTIFY				2

struct notifywatch_struct {
    unsigned char flags;
    struct inode_struct *inode;
    struct workspace_object_struct *object;
    struct pathinfo_struct pathinfo;
    uint32_t notifymask;
    uint32_t mask;
    pthread_mutex_t mutex;
    struct watchbackend_struct *backend;
    struct watchcb_struct *cb;
    void *data;
    struct notifywatch_struct *next;
    struct notifywatch_struct *prev;
};

struct watchbackend_struct {
    unsigned char type;
    int (* set_watch) (struct notifywatch_struct *watch);
    int (* change_watch) (struct notifywatch_struct *watch);
    void (* remove_watch) (struct notifywatch_struct *watch);
};

struct watchcb_struct {
    void (* create) (struct notifywatch_struct *watch, char *name);
    void (* remove) (struct notifywatch_struct *watch, char *name);
    void (* change) (struct notifywatch_struct *watch, char *name);
    void (* destroy) (struct notifywatch_struct *watch);
};

// Prototypes

void lock_watch(struct notifywatch_struct *watch);
void unlock_watch(struct notifywatch_struct *watch);

struct notifywatch_struct *lookup_watch_inode(struct inode_struct *inode);
void add_watch_inodetable(struct notifywatch_struct *watch);
void remove_watch_inodetable(struct notifywatch_struct *watch);

uint32_t determine_fsnotify_mask(struct inode_struct *inode, struct stat *st);

struct notifywatch_struct *add_notifywatch(struct inode_struct *inode, uint32_t mask, struct pathinfo_struct *pathinfo, struct workspace_object_struct *object, unsigned int *error);
void change_notifywatch(struct notifywatch_struct *watch, uint32_t mask);

struct notifywatch_struct *add_systemwatch(struct pathinfo_struct *pathinfo, struct watchcb_struct *cb, unsigned int *error);
void remove_systemwatch(struct notifywatch_struct *watch);

int init_fschangenotify(unsigned int *error);
void end_fschangenotify();

#endif
