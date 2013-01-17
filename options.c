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

#include "global-defines.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include <inttypes.h>
#include <ctype.h>

#include <sys/stat.h>
#include <sys/param.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <fuse/fuse_lowlevel.h>

#include "logging.h"
#include "simpleoverlayfs.h"

#include "options.h"

extern struct overlayfs_options_struct overlayfs_options;

static void print_usage(const char *progname)
{
	fprintf(stdout, "usage: %s [opts]"
	                "          --notifyfs-socket=FILE\n"
	                "          [--logging=NR,]\n"
	                "          [--logarea=NR,]\n"
	                "          --mountpoint=PATH\n", progname);

}

static void print_help() {
    unsigned char defaultloglevel=1;

#ifdef LOG_DEFAULT_LEVEL
    defaultloglevel=LOG_DEFAULT_LEVEL;
#endif

    fprintf(stdout, "General options:\n");
    fprintf(stdout, "    --opt                      options\n");
    fprintf(stdout, "    -h   --help                print help\n");
    fprintf(stdout, "    -V   --version             print version\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Overlayfs options:\n");
    fprintf(stdout, "    --notifyfs-socket=FILE     socket of notifyfs server\n");

#ifdef LOGGING
    fprintf(stdout, "    --logging=NUMBER           set loglevel\n");
    fprintf(stdout, " 			            when omitted no logging\n");
    fprintf(stdout, " 			            without number take the default: %i\n", defaultloglevel);
    fprintf(stdout, " 			            NUMBER indicates level of logging: 0 - 3, 3 is highest level\n");
    fprintf(stdout, "    --logarea=NUMBER           set logarea mask (0=no area)\n");
#endif

    fprintf(stdout, "\n");

}

static void print_version()
{

    printf("overlayfs version %s\n", PACKAGE_VERSION);
    //printf("Fuse version %s\n", fuse_version());
    /* here kernel module version... */

}

/* function to parse all the commandline arguments, and split the normal notifyfs arguments 
   and the arguments meant for fuse
   normal options are specified as long options, like --logging
   fuse options are specified in a "single" option with -osomefuseoption,anotherfuseoption*/

int parse_arguments(int argc, char *argv[], struct fuse_args *fs_fuse_args)
{
    static struct option long_options[] = {
	{"help", 		optional_argument, 		0, 0},
	{"version", 		optional_argument, 		0, 0},
	{"logging", 		optional_argument, 		0, 0},
	{"logarea", 		optional_argument, 		0, 0},
	{"notifyfs-socket", 	optional_argument,		0, 0},
	{"mountpoint", 		optional_argument,		0, 0},
	{0,0,0,0}
	};
    int res, long_options_index=0, nreturn=0;
    char *fuseoptions=NULL;
    struct stat st;

    /* set defaults */

    /* no logging*/

    overlayfs_options.logging=0;

    /* only the filesystem logging */

    overlayfs_options.logarea=LOG_LOGAREA_FILESYSTEM;

    /* socket */

    memset(overlayfs_options.notifyfs_socket, '\0', PATH_MAX);

    /* mountpoint */

    memset(overlayfs_options.mountpoint, '\0', PATH_MAX);

    /* start the fuse options with the program name, just like the normal argv */

    logoutput("parse_options: add fuse arg %s", argv[0]);

    nreturn=fuse_opt_add_arg(fs_fuse_args, argv[0]);
    if (nreturn<0) goto out;


    while(1) {

	res=getopt_long(argc, argv, "", long_options, &long_options_index);

	if ( res==-1 ) {

	    break;

	}

	switch(res) {

	    case 0:

		/* a long option */

		if ( strcmp(long_options[long_options_index].name, "help")==0 ) {

		    print_usage(argv[0]);
		    print_help();
		    nreturn=-1;
		    goto out;


		} else if ( strcmp(long_options[long_options_index].name, "version")==0 ) {

		    print_version(argv[0]);
		    nreturn=-1;
		    goto out;


		} else if ( strcmp(long_options[long_options_index].name, "logging")==0 ) {

		    if ( optarg ) {

			overlayfs_options.logging=atoi(optarg);

		    } else {

			fprintf(stderr, "Warning: option --logging requires an argument. Taking default.\n");

			overlayfs_options.logging=1;

		    }

		} else if ( strcmp(long_options[long_options_index].name, "logarea")==0 ) {

		    if ( optarg ) {

			overlayfs_options.logarea=atoi(optarg);

		    } else {

			fprintf(stderr, "Warning: option --logarea requires an argument. Taking default.\n");

		    }

		} else if ( strcmp(long_options[long_options_index].name, "notifyfs-socket")==0 ) {

		    if ( optarg ) {

			if ( strlen(optarg) >= PATH_MAX ) {

			    fprintf(stderr, "Length of socket %s is too big.\n", optarg);
			    nreturn=-1;
			    goto out;

			}

			if ( stat(optarg, &st)==-1 ) {

			    /* does not exist */

			    fprintf(stderr, "Socket %s does not exist, cannot continue.", optarg);
			    nreturn=-1;
			    goto out;


			} else if (! S_ISSOCK(st.st_mode)) {

			    /* does exist, but not a socket */

			    fprintf(stderr, "Socket %s does exist, but not a socket, cannot continue.", optarg);
			    nreturn=-1;
			    goto out;


			}

			strcpy(overlayfs_options.notifyfs_socket, optarg);

			fprintf(stdout, "Taking socket %s.\n", overlayfs_options.notifyfs_socket);

		    } else {

			fprintf(stderr, "Error: option --notifyfs-socket requires an argument. Abort.\n");
			nreturn=-1;
			goto out;

		    }

		} else if ( strcmp(long_options[long_options_index].name, "fuseoptions")==0 ) {

		    if ( optarg ) {

			fuseoptions=strdup(optarg);

			if ( ! fuseoptions ) {

			    nreturn=-1;
			    goto out;

			}


		    } else {

			fprintf(stderr, "Warning: option --fuseoptions requires an argument. Ignoring.\n");

		    }

		} else if ( strcmp(long_options[long_options_index].name, "mountpoint")==0 ) {

		    if ( optarg ) {

			if ( ! realpath(optarg, overlayfs_options.mountpoint)) {

			    nreturn=-1;
			    fprintf(stderr, "Error:(%i) option --mountpoint=%s cannot be parsed. Cannot continue.\n", errno, optarg);
			    goto out;

			}

		    } else {

			fprintf(stderr, "Error: option --mountpoint requires an argument. Cannot continue.\n");
			nreturn=-1;
			goto out;

		    }

		}

	    case '?':

		break;

	    default:

		fprintf(stdout,"Warning: getoption returned character code 0%o!\n", res);

	}

    }

    out:

    return nreturn;

}

