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

#include "fuse-workspace.h"
#include "skiplist.h"
#include "entry-management.h"
#include "path-resolution.h"
#include "options.h"
#include "utils.h"

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

#define logoutput(...) dummy_nolog()

#endif

extern struct fs_options_struct fs_options;

static void print_usage(const char *progname)
{
	fprintf(stdout, "Usage: \n"
			"%s [opts]\n"
			"\n"
	                "          --configfile=PATH\n"
	                "          --fuseoptions=COMMASEP STRING\n", progname);

}

static void print_help() {

    fprintf(stdout, "General options:\n");
    fprintf(stdout, "    --opt                      options\n");
    fprintf(stdout, "    -h   --help                print help\n");
    fprintf(stdout, "    -V   --version             print version\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Overlayfs options:\n");

    fprintf(stdout, "\n");

}

static void print_version()
{

    printf("overlayfs version %s\n", PACKAGE_VERSION);
    //printf("Fuse version %s\n", fuse_version());
    /* here kernel module version... */

}

static void read_config(char *path)
{
    FILE *fp;

    fp=fopen(path, "r");

    if ( fp ) {
        char line[512];
        char *sep;

	while( ! feof(fp)) {

	    if ( ! fgets(line, 512, fp)) continue;

	    sep=strchr(line, '\n');
	    if (sep) *sep='\0';

	    sep=strchr(line, '=');
	    if ( sep ) {
		char *option=line;
		char *value=sep+1;

		*sep='\0';

		convert_to(option, UTILS_CONVERT_SKIPSPACE | UTILS_CONVERT_TOLOWER);

		if (strcmp(option, "fuse.attr_timeout")==0) {

		    if (strlen(value)>0) {

			fs_options.attr_timeout=strtod(value, NULL);

		    }

		} else if (strcmp(option, "fuse.entry_timeout")==0) {

		    if (strlen(value)>0) {

			fs_options.entry_timeout=strtod(value, NULL);

		    }

		} else if (strcmp(option, "fuse.negative_timeout")==0) {

		    if (strlen(value)>0) {

			fs_options.negative_timeout=strtod(value, NULL);

		    }

		} else if (strcmp(option, "logging.fuse")==0) {

		    if (strlen(value)>0) {

			fs_options.fuse_logging=atoi(value);

			if (fs_options.fuse_logging>5) {

			    fs_options.fuse_logging=5;

			} else if (fs_options.fuse_logging<0) {

			    fs_options.fuse_logging=0;

			}

		    }

		} else if (strcmp(option, "logging.main")==0) {

		    if (strlen(value)>0) {

			fs_options.main_logging=atoi(value);

			if (fs_options.main_logging>5) {

			    fs_options.main_logging=5;

			} else if (fs_options.main_logging<0) {

			    fs_options.main_logging=0;

			}

		    }

		} else if (strcmp(option, "logging.fschangenotify")==0) {

		    if (strlen(value)>0) {

			fs_options.fschangenotify_logging=atoi(value);

			if (fs_options.fschangenotify_logging>5) {

			    fs_options.fschangenotify_logging=5;

			} else if (fs_options.fschangenotify_logging<0) {

			    fs_options.fschangenotify_logging=0;

			}

		    }

		} else if (strcmp(option, "logging.entry")==0) {

		    if (strlen(value)>0) {

			fs_options.entry_logging=atoi(value);

			if (fs_options.entry_logging>5) {

			    fs_options.entry_logging=5;

			} else if (fs_options.entry_logging<0) {

			    fs_options.entry_logging=0;

			}

		    }

		} else if (strcmp(option, "logging.path")==0) {

		    if (strlen(value)>0) {

			fs_options.path_logging=atoi(value);

			if (fs_options.path_logging>5) {

			    fs_options.path_logging=5;

			} else if (fs_options.path_logging<0) {

			    fs_options.path_logging=0;

			}

		    }

		} else if (strcmp(option, "logging.skiplist")==0) {

		    if (strlen(value)>0) {

			fs_options.skiplist_logging=atoi(value);

			if (fs_options.skiplist_logging>5) {

			    fs_options.skiplist_logging=5;

			} else if (fs_options.skiplist_logging<0) {

			    fs_options.skiplist_logging=0;

			}

		    }

		}

	    }

	}

	fclose(fp);

    }

}

/* function to parse all the commandline arguments, and split the normal notifyfs arguments 
   and the arguments meant for fuse
   normal options are specified as long options, like --logging
   fuse options are specified in a "single" option with -osomefuseoption,anotherfuseoption*/

int parse_arguments(int argc, char *argv[], unsigned int *error)
{
    static struct option long_options[] = {
	{"help", 		optional_argument, 		0, 0},
	{"version", 		optional_argument, 		0, 0},
	{"configfile", 		optional_argument,		0, 0},
	{"basemap", 		optional_argument,		0, 0},
	{0,0,0,0}
	};
    int res, long_options_index=0, result=0;
    struct stat st;

    /* set defaults */

    /* configfile */

    fs_options.configfile=NULL;
    fs_options.basemap=NULL;

    fs_options.attr_timeout=1.0;
    fs_options.entry_timeout=1.0;
    fs_options.negative_timeout=1.0;

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
		    result=-1;
		    *error=0;
		    goto finish;


		} else if ( strcmp(long_options[long_options_index].name, "version")==0 ) {

		    print_version(argv[0]);
		    result=-1;
		    *error=0;
		    goto finish;


		} else if ( strcmp(long_options[long_options_index].name, "configfile")==0 ) {

		    if ( optarg ) {

			fs_options.configfile=realpath(optarg, NULL);

			if ( ! fs_options.configfile) {

			    result=-1;
			    *error=ENOMEM;
			    fprintf(stderr, "Error:(%i) option --configfile=%s cannot be parsed. Cannot continue.\n", errno, optarg);
			    goto out;

			}

		    } else {

			fprintf(stderr, "Error: option --configfile requires an argument. Cannot continue.\n");
			result=-1;
			*error=EINVAL;
			goto out;

		    }

		} else if ( strcmp(long_options[long_options_index].name, "basemap")==0 ) {

		    if ( optarg ) {

			fs_options.basemap=realpath(optarg, NULL);

			if ( ! fs_options.basemap) {

			    result=-1;
			    *error=ENOMEM;
			    fprintf(stderr, "Error:(%i) option --basemap=%s cannot be parsed. Cannot continue.\n", errno, optarg);
			    goto out;

			}

		    } else {

			fprintf(stderr, "Error: option --basemap requires an argument. Cannot continue.\n");
			result=-1;
			*error=EINVAL;
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

    if (fs_options.configfile) {

	read_config(fs_options.configfile);

    } else {

	read_config(FUSE_WORKSPACE_CONFIGFILE);

    }


    finish:

    return result;

}

