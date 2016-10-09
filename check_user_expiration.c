/*
 * Nagios plugin to check the expiration date of a user.
 * As this plugin needs to access /etc/shadow, it needs a root suid bit
 * on solaris, and at least the CAP_DAC_READ_SEARCH capability on linux.
 * On AIX, it needs to access /etc/security/user and /etc/security/passwd,
 * so it needs a root suid bit as well.
 * This plugin does not depend on any library except standard libc.
 * 
 * On AIX and Solaris:
 *	chown root check_user_expiration; chmod u+s check_user_expiration
 * On linux:
 *	setcap CAP_DAC_READ_SEARCH+ep check_user_expiration
 *	
 * AIX information taken from
 * http://www.ibm.com/developerworks/aix/library/au-password_expiry/
 */

#include <ctype.h>
#ifndef	_AIX			/* AIX has getopt in unistd.h */
#include <getopt.h>
#endif
#include <libgen.h>
#ifndef	_AIX
#include <shadow.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


#ifdef _AIX
char *getsecattr(char *filename, char *user, char *attrib);
#endif

int opt_warn=14;
int opt_crit=7;
char *progname;

#define ok(x) do { \
		printf("%s OK: %s\n", basename(progname), x);\
		exit(0);\
		} while (0)
#define warning(x) do { \
		printf("%s WARNING: %s\n", basename(progname), x);\
		exit(1);\
		} while (0)
#define critical(x) do { \
		printf("%s CRITICAL: %s\n", basename(progname), x);\
		exit(2);\
		} while (0)
#define unknown(x) do { \
		printf("%s UNKNOWN: %s\n", basename(progname), x);\
		exit(3);\
		} while (0)

int main(int argc, char **argv) {
	
#ifdef	_AIX
	char *lastchange;
	char *maxage;
#else
	struct spwd *spwd;
#endif
	long nextchange;
	long now;
	char msg[80];
	int i, opt;

	progname=argv[0];

	while ((opt=getopt(argc, argv, "w:c:"))!=-1) {
		switch (opt) {
		case 'c':
			opt_crit=atoi(optarg);
			break;
		case 'w':
			opt_warn=atoi(optarg);
			break;
		}
	}

	if (argc<=optind || argv[optind]==NULL || argv[optind][0]=='\0') {
		unknown("No user name given");
	}

	/* Do some sanity checks on the user name, just to avoid feeding
	 * weird stuff to a function that possibly can't handle it.
	 */
	if (strlen(argv[optind])>40) {
		unknown("Unreasonable user name");
	}
	for (i=0; argv[optind][i]; i++) {
		if (!isalnum(argv[optind][i])) {
			unknown("Unreasonable user name");
		}
	}

#ifdef	_AIX
	lastchange=getsecattr("passwd", argv[optind], "lastupdate");
	maxage=    getsecattr("user"  , argv[optind], "maxage");
	if (lastchange==NULL || maxage==NULL) {
		unknown("Cannot read user attributes");
	}
	if (atoi(maxage)==0) {
		ok("User does not expire");
	}
	nextchange=atoi(lastchange)/86400+atoi(maxage)*7;
#else
	if ((spwd=getspnam(argv[optind]))==NULL) {
		snprintf(msg, sizeof msg,
			"Cannot read shadow entry for %s", argv[optind]);
		unknown(msg);
	}

	if (spwd->sp_max<0) {
		ok("User does not expire");
	}
	nextchange=spwd->sp_lstchg + spwd->sp_max;
#endif
	now=time(0L)/86400;

	snprintf(msg, sizeof msg, "Password expires in %ld days",
						(long)nextchange-(long)now);
	if ((nextchange-now)>opt_warn) {
		ok(msg);
	} else if ((nextchange-now)>opt_crit) {
		warning(msg);
	} else if ((nextchange-now)>0) {
		critical(msg);
	} else {
		snprintf(msg, sizeof msg, "Password expired since %ld days",
				(long)now-(long)nextchange);
		critical(msg);
	}
	/* This should be unreachable. */
	unknown("Internal error, review source code.");
}

#ifdef	_AIX
char *getsecattr(char *filename, char *user, char *attrib) {
	FILE *fp;

	char *realfile;
	char *path="/etc/security/";
	char *section=NULL;
	char *value=NULL;
	char buf[256];
	int pos, len;

	if (strchr(filename, '/'))	/* no paths, just plain files */
		return NULL;
	if ((realfile=malloc(strlen(filename)+strlen(path)+1))==NULL)
		return NULL;
	strcpy(realfile, path);
	strcat(realfile, filename);
	if ((fp=fopen(realfile, "rt"))==NULL) {
		free(realfile);
		return NULL;
	}
	while (fgets(buf, sizeof buf, fp)) {
		if ((len=strlen(buf))<=0
		||  buf[len-1]!='\n') {
			free(realfile);
			fclose(fp);
			return NULL;
		}
		if (len>1 && isalpha(buf[0]) && buf[len-2]==':') {
			buf[len-2]='\0';
			if (section)
				free(section);
			section=strdup(buf);
			continue;
		}
		if (section==NULL
		||   (strcmp(section, "default") && strcmp(section, user)))
			continue;
		for (pos=0; buf[pos] && isspace(buf[pos]); pos++)
			;
		if (strncmp(buf+pos, attrib, strlen(attrib)))
			continue;
		pos+=strlen(attrib);
		while (buf[pos] && isspace(buf[pos]))
			pos++;
		if (buf[pos]!='=')
			continue;
		pos++;
		while (buf[pos] && isspace(buf[pos]))
			pos++;
		while (len>pos && isspace(buf[len-1]))
			buf[--len]='\0';
		if (value!=NULL)
			free(value);
		value=strdup(buf+pos);
	}
	free(realfile);
	fclose(fp);
	return value;
}
#endif
