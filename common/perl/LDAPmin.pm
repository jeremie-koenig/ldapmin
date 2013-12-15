#!/usr/bin/perl

package LDAPmin;

use Net::LDAP qw(LDAP_NO_SUCH_OBJECT);
use Memoize;
use warnings;
use strict;

BEGIN {
	require Exporter;
	our $VERSION = 1.00;
	our @ISA = qw(Exporter);
	our @EXPORT = qw();
	our @EXPORT_OK = qw(shiftdn dn2domain search);
}

# Configuration options
my %searchopts = ("filter" => "(objectClass=*)");
my $server = "localhost";
my $binddn;
my %bindopts = ();

# The global LDAP connection
my $ldap;

# Read the global LDAP configuration file and interpret the associated
# environment variables.
sub parseconf {
	my %ldap_conf = (
		"BASE"	 => sub { $searchopts{base} = shift; },
		"URI"	 => sub { $server = shift; },
		"BINDDN" => sub { $binddn = shift; },
		"BINDPW" => sub { $bindopts{password} = shift; },
	);
	my ($opt, $val);

	return if exists($ENV{"LDAPNOINIT"});

	open LC, "< $_[0]" or return;
	while(<LC>) {
		($opt, $val) = /^\s*(\w+)\s+(.*)\s*$/ or next;
		&{$ldap_conf{$opt}}($val) if exists $ldap_conf{$opt};
	}
	close LC;

	foreach $opt (keys(%ldap_conf)) {
		$val = $ENV{"LDAP$opt"};
		&{$ldap_conf{$opt}}($val) if $val;
	}
}

# Read the configuration, and connect.
{
	parseconf "/etc/ldap/ldap.conf";
	parseconf "/etc/ldapmin/ldap.conf";

	if ($ENV{LDAPMIN_DEBUG}) {
		my @so = map("$_ => $searchopts{$_}", keys(%searchopts));
		printf STDERR "server: %s\n", $server;
		printf STDERR "bind dn: %s\n", $binddn if defined($binddn);
		printf STDERR "searchopts: %s\n", join(", ", @so);
	}

	$ldap = Net::LDAP->new($server) or die "$@";
	$ldap->bind($binddn, %bindopts) or die "$@";
}

# Drop the first component of a distinguished name
sub shiftdn ($) {
	my $dn = shift;
	$dn =~ s/^[^,]*(,|$)//;
	return length($dn) ? $dn : undef;
}

# Translate a DN to a domain name using the 'cn' and 'dc' components
sub dn2domain ($) {
	my $dn = shift;
	my $domain = "";

	while ($dn =~ /^(.+?)=([^,]*),?(.*)/) {
		$domain = "${domain}$2." if ($1 eq 'cn' || $1 eq 'dc');
		$dn = $3;
	}

	return length($dn) ? undef : $domain;
}

# Produce a list of ancestors for a given DN
sub ancestors ($) {
	my $dn = shift;
	my @dn = ();
	do { push @dn, $dn; } while($dn = shiftdn($dn));
	return @dn;
}

# Perform a search, using sensible default parameters.
# If the search fails, the whole script is aborted.
sub search (@) {
	my %params = (%searchopts, @_);

	# Trace the searches being performed for debugging purposes
	if (exists $ENV{LDAPMIN_DEBUG}) {
		my @params = map("$_ => $params{$_}", keys(%params));
		printf STDERR "search: %s\n" , join(", ", @params);
	}

	my $mesg = $ldap->search(%params);
	$mesg->code == LDAP_NO_SUCH_OBJECT and return ();
	$mesg->code && die $mesg->error;

	# Bless the returned entries as LDAPmin::Entry so that we can use the
	# extended interface below.
	my @entries = $mesg->entries;
	bless $_, 'LDAPmin::Entry' foreach @entries;

	# Show the results
	if (exists $ENV{LDAPMIN_DEBUG}) {
		printf STDERR "result: %s\n", $_->dn() foreach @entries;
	}

	return @entries;
}

# We reuse the LDAP::Entry objects returned by searches, but provide
# additional methods for our own purposes below.
package LDAPmin::Entry
{
	our @ISA = qw(Net::LDAP::Entry);

	# Compute the domain name associated with this entry.
	sub associated_domain ($) {
		my $entry = shift;

		# If the entry has an explicit 'associatedDomain' attibute,
		# (as used in the 'domainRelatedObject' class), use that.
		if ($entry->exists('associatedDomain')) {
			return $entry->get_value('associatedDomain');
		}

		# Otherwise, use the 'cn' and 'dc' RDNs to derive a domain
		# name automatically.
		my $dn = $entry->dn();
		my $domain = "";

		while ($dn =~ /^(.+?)=([^,]*),?(.*)/) {
			$domain = "${domain}$2." if ($1 eq 'cn' || $1 eq 'dc');
			$dn = $3;
		}

		return length($dn) ? undef : $domain;
	}

	sub parent ($) {
		my $entry = shift;
		my $parentdn = LDAPmin::shiftdn($entry->dn());
		my @parent = LDAPmin::search(base => $parentdn, scope => 'base');
		return $parent[0];
	}

	# FIXME: the whole service offer/request thing below should be
	# rethought perhaps.

	# Retreives the ldapminServiceOffer objects associated with a given
	# ldapminServiceRequest object.
	sub service_offers ($) {
		my $entry = shift;

		# We're looking for service offers which either directly
		# target this object, or one of its ancestors.
		my $f = "(&(objectClass=ldapminServiceOffer)(|";
		$f .= "(ldapminServiceDN=$_)" foreach LDAPmin::ancestors($entry->dn());
		$f .= "))";

		return LDAPmin::search(filter => $f);
	}
}

# Returns a list of entries which correspond to this host.
memoize 'who_am_i';
sub who_am_i () {
	# The environment variables LDAPMIN_HOSTDN can specify who we are.
	if (exists $ENV{LDAPMIN_HOSTDN}) {
		return search(base => $ENV{LDAPMIN_HOSTDN}, scope => 'base');
	}

	# Otherwise, use the local ethernet addresses to identify us.
	my $macfilters;
	open IP, "ip addr |";
	while (<IP>) {
		next unless m{link/ether ([a-zA-Z0-9:]+)};
		$macfilters .= "(macAddress=$1)";
	}
	close IP;
	return search(filter => "(|$macfilters)");
}


# Given a service name, return the entries for the ones we should provide
sub service_requests ($) {
	my $name = shift;

	# FIXME: use our serviceOffer's as base for searches
	my $f = "(&(objectClass=ldapminServiceRequest)(cn=$name))";
	return search(filter => $f);
}

1;
