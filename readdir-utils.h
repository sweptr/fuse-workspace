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

#ifndef _READDIR_UTILS_H
#define _READDIR_UTILS_H

#define _READDIR_MODE_READDIR				1
#define _READDIR_MODE_GETDENTS				2

#define _READDIR_GETDENTS_BUFFSIZE			1024

struct _readdir_getdents_struct {
    char 					*buffer;
    size_t					size;
    unsigned int				pos;
    unsigned int				read;
};

struct _readdir_readdir_struct {
    DIR						*dp;
    char 					*de;
    size_t					size;
};

struct readdir_struct {
    unsigned char 				mode;
    int 					fd;
    struct timespec				synctime;
    union {
	struct _readdir_getdents_struct 	getdents;
	struct _readdir_readdir_struct 		readdir;
    } type;
    int 					(*get_direntry) (struct readdir_struct *readdir, struct name_struct *name, unsigned char *type, unsigned int *error);
    void					(*close) (struct readdir_struct *r);
};


// Prototypes

struct readdir_struct *init_readdir_getdents(char *path, int fd, unsigned int *error);
struct readdir_struct *init_readdir_readdir(char *path, int fd, unsigned int *error);

#endif
