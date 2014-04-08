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

#include <fuse3/fuse_lowlevel.h>


#include "simpleoverlayfs.h"
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

extern struct overlayfs_options_struct overlayfs_options;

static void print_usage(const char *progname)
{
	fprintf(stdout, "Usage: \n"
			"%s [opts]\n"
			"\n"
	                "          --configfile=PATH\n"
	                "          --fuseoptions=COMMASEP STRING\n"
	                "          --mountpoint=PATH\n", progname);

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

static void read_config(char *path, char **fuseoptions)
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

			overlayfs_options.attr_timeout=strtod(value, NULL);

		    }

		} else if (strcmp(option, "fuse.entry_timeout")==0) {

		    if (strlen(value)>0) {

			overlayfs_options.entry_timeout=strtod(value, NULL);

		    }

		} else if (strcmp(option, "fuse.negative_timeout")==0) {

		    if (strlen(value)>0) {

			overlayfs_options.negative_timeout=strtod(value, NULL);

		    }

		} else if (strcmp(option, "logging.fuse")==0) {

		    if (strlen(value)>0) {

			overlayfs_options.fuse_logging=atoi(value);

			if (overlayfs_options.fuse_logging>5) {

			    overlayfs_options.fuse_logging=5;

			} else if (overlayfs_options.fuse_logging<0) {

			    overlayfs_options.fuse_logging=0;

			}

		    }

		} else if (strcmp(option, "logging.main")==0) {

		    if (strlen(value)>0) {

			overlayfs_options.main_logging=atoi(value);

			if (overlayfs_options.main_logging>5) {

			    overlayfs_options.main_logging=5;

			} else if (overlayfs_options.main_logging<0) {

			    overlayfs_options.main_logging=0;

			}

		    }

		} else if (strcmp(option, "logging.fschangenotify")==0) {

		    if (strlen(value)>0) {

			overlayfs_options.fschangenotify_logging=atoi(value);

			if (overlayfs_options.fschangenotify_logging>5) {

			    overlayfs_options.fschangenotify_logging=5;

			} else if (overlayfs_options.fschangenotify_logging<0) {

			    overlayfs_options.fschangenotify_logging=0;

			}

		    }

		} else if (strcmp(option, "logging.entry")==0) {

		    if (strlen(value)>0) {

			overlayfs_options.entry_logging=atoi(value);

			if (overlayfs_options.entry_logging>5) {

			    overlayfs_options.entry_logging=5;

			} else if (overlayfs_options.entry_logging<0) {

			    overlayfs_options.entry_logging=0;

			}

		    }

		} else if (strcmp(option, "logging.path")==0) {

		    if (strlen(value)>0) {

			overlayfs_options.path_logging=atoi(value);

			if (overlayfs_options.path_logging>5) {

			    overlayfs_options.path_logging=5;

			} else if (overlayfs_options.path_logging<0) {

			    overlayfs_options.path_logging=0;

			}

		    }

		} else if (strcmp(option, "logging.skiplist")==0) {

		    if (strlen(value)>0) {

			overlayfs_options.skiplist_logging=atoi(value);

			if (overlayfs_options.skiplist_logging>5) {

			    overlayfs_options.skiplist_logging=5;

			} else if (overlayfs_options.skiplist_logging<0) {

			    overlayfs_options.skiplist_logging=0;

			}

		    }

		} else if (strcmp(option, "fuse.options")==0) {

		    if (strlen(value)>0) {

			if (! *fuseoptions) {

			    *fuseoptions=strdup(value);

			} else {

			    fprintf(stderr, "fuseoptions set in configfile %s, but also set on commandline %s\n", path, *fuseoptions);

			}

		    }

		}

	    }

	}

	fclose(fp);

    }

}



/* function which processes one fuse option by adding it to the fuse arguments list 
   important here is that every fuse option has to be prefixed by a -o */

static int parsefuseoption(struct fuse_args *fs_fuse_args, char *fuseoption)
{
    int len=strlen("-o")+strlen(fuseoption)+1;
    char tmpoption[len];

    memset(tmpoption, '\0', len);
    snprintf(tmpoption, len, "-o%s", fuseoption);

    return fuse_opt_add_arg(fs_fuse_args, tmpoption);

}

/* function to parse all the commandline arguments, and split the normal notifyfs arguments 
   and the arguments meant for fuse
   normal options are specified as long options, like --logging
   fuse options are specified in a "single" option with -osomefuseoption,anotherfuseoption*/

int parse_arguments(int argc, char *argv[], struct fuse_args *fs_fuse_args, unsigned int *error)
{
    static struct option long_options[] = {
	{"help", 		optional_argument, 		0, 0},
	{"version", 		optional_argument, 		0, 0},
	{"mountpoint", 		optional_argument,		0, 0},
	{"configfile", 		optional_argument,		0, 0},
	{0,0,0,0}
	};
    int res, long_options_index=0, result=0;
    char *fuseoptions=NULL;
    struct stat st;

    /* set defaults */

    /* mountpoint */

    overlayfs_options.mountpoint=NULL;

    /* configfile */

    overlayfs_options.configfile=NULL;

    overlayfs_options.attr_timeout=1.0;
    overlayfs_options.entry_timeout=1.0;
    overlayfs_options.negative_timeout=1.0;

    /* start the fuse options with the program name, just like the normal argv */

    if (fuse_opt_add_arg(fs_fuse_args, argv[0])<0) {

	result=-1;
	*error=EINVAL;

    }


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

			overlayfs_options.configfile=realpath(optarg, NULL);

			if ( ! overlayfs_options.configfile) {

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

		} else if ( strcmp(long_options[long_options_index].name, "fuseoptions")==0 ) {

		    if ( optarg ) {

			fuseoptions=strdup(optarg);

			if ( ! fuseoptions ) {

			    result=-1;
			    *error=ENOMEM;
			    goto out;

			}


		    } else {

			fprintf(stderr, "Warning: option --fuseoptions requires an argument. Ignoring.\n");

		    }

		} else if ( strcmp(long_options[long_options_index].name, "mountpoint")==0 ) {

		    if ( optarg ) {

			overlayfs_options.mountpoint=realpath(optarg, NULL);

			if ( ! overlayfs_options.mountpoint) {

			    result=-1;
			    *error=ENOMEM;
			    fprintf(stderr, "Error:(%i) option --mountpoint=%s cannot be parsed. Cannot continue.\n", errno, optarg);
			    goto out;

			}

		    } else {

			fprintf(stderr, "Error: option --mountpoint requires an argument. Cannot continue.\n");
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

    if (! overlayfs_options.mountpoint) {

	fprintf(stderr, "Error: option --mountpoint not defined. Cannot continue.\n");
	result=-1;
	*error=EINVAL;

    }

    if (overlayfs_options.configfile) {

	read_config(overlayfs_options.configfile, &fuseoptions);

    } else {

	read_config(SIMPLEOVERLAYFS_CONFIGFILE, &fuseoptions);

    }

    if (fuseoptions) {
	char *sep=NULL;
	char *fuseoption=fuseoptions;

	/* parse the comma seperated list into something fuse understands */

	while(1) {

	    sep=strchr(fuseoption, ',');

	    if (sep) {

		*sep='\0';
		result=parsefuseoption(fs_fuse_args, fuseoption);

		if (result<0) {

		    result=-1;
		    *error=ENOMEM;
		    goto finish;

		}

		*sep=',';
		sep++;
		fuseoption=sep;

	    } else {

		if (strlen(fuseoption)>0) {

		    result=parsefuseoption(fs_fuse_args, fuseoption);

		    if (result<0) {

			result=-1;
			*error=ENOMEM;
			goto finish;

		    }

		}

		break;

	    }

	}

    }

    finish:

    return (*error==0) ? 0 : -1;

}

