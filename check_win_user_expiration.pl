#!/usr/bin/perl
# The hashbang doesn't really make much sense, since this program is supposed to run on windows.

use POSIX qw(mktime strftime);
use strict;
use warnings;

if (!defined($ARGV[0])) {
	unknown("No User name given");
}

my $warning=60;
my $critical=15;

while (defined($ARGV[0]) && substr($ARGV[0], 0, 1) eq "-") {
	if ($ARGV[0] eq "-w") { $warning=$ARGV[1]; shift; shift; next; }
	if ($ARGV[0] eq "-c") { $critical=$ARGV[1]; shift; shift; next; }
}

my $user=$ARGV[0];
my $expiration="";
my $domain="";

if ($user =~ /[\/\\]/) {
	$domain="/domain";  # No, we can't use the domain part. Only local domain possible.
	$user=~s/.*[\\\/]//;
}

open(INFO, "net user $user $domain 2>&1 |");
while (<INFO>) {
	chomp;
	y/\r//d;
	if (/Password expires +(.*)/
        ||  /Kennwort l.*uft ab +(.*)/) {
		$expiration=$1;
	}
}

if ($expiration eq "") {
	unknown("No password expiration found in user info (net user $user)");
}

if ($expiration =~ /^N/) {
	ok("Passwort Expiration: $expiration");
}

# At least on the systems i know, even english language servers seem to
# use this time format. 
if ($expiration =~ /(\d\d.\d\d.\d\d\d\d \d\d:\d\d:\d\d)/) {
	my $day=substr($expiration, 0, 2);
	my $month=substr($expiration, 3, 2);
	my $year=substr($expiration, 6, 4);
	my $when=POSIX::mktime(0, 0, 0, $day, $month-1, $year-1900)/86400;
	my $now=time()/86400;
	my $rest=int($when-$now);

	if ($when < $now) {
		critical("$user\'s password expired on $expiration");
	} elsif ($when < $now+$critical) {
		critical("$user\'s password will expire in $rest days on $expiration");
	} elsif ($when < $now+$warning) {
		warning ("$user\'s password will expire in $rest days on $expiration");
	} else {
		ok      ("$user\'s password will expire in $rest days on $expiration");
	}
}






sub ok {
	print "$0 OK - ", shift, "\n";
	exit(0);
}

sub warning {
	print "$0 WARNING - ", shift, "\n";
	exit(1);
}

sub critical {
	print "$0 CRITICAL - ", shift, "\n";
	exit(2);
}

sub unknown {
	print "$0 UNKNOWN - ", shift, "\n";
	exit(3);
}
