#!/usr/bin/perl -w
use Net::LDAP qw(LDAP_NO_SUCH_OBJECT);
use Memoize;

sub ldap_parseconf {
	my %ldap_conf = (
		"BASE"	 => sub { $ldap_searchopts{base} = shift; },
		"URI"	 => sub { $ldap_server = shift; },
		"BINDDN" => sub { $ldap_binddn = shift; },
		"BINDPW" => sub { $ldap_bindpw = shift; },
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

BEGIN {
	%ldap_searchopts = ( "filter" => "(objectClass=*)" );
	$ldap_server = "localhost";

	ldap_parseconf "/etc/ldap/ldap.conf";
	ldap_parseconf "/etc/ldapmin/ldap.conf";
	$ldap = Net::LDAP->new($ldap_server) or die "$@";

	my %opt;
	$opt{password} = $ldap_bindpw if defined($ldap_bindpw);
	$ldap->bind($ldap_binddn, %opt) or die "$@";
}

sub ldap_entry2hash ($) {
	my $entry = shift;
	my %ret;

	$ret{dn} = [$entry->dn];
	$ret{$_} = [$entry->get_value($_)] foreach $entry->attributes;
	return \%ret;
}

sub ldap_search (@) {
	my %params = (%ldap_searchopts, @_);
	#print STDERR "search:" , map(" $_=>$params{$_}", keys(%params)), "\n";
	my $mesg = $ldap->search(%params);
	$mesg->code == LDAP_NO_SUCH_OBJECT and return ();
	$mesg->code && die $mesg->error;
	return map(ldap_entry2hash($_), $mesg->entries);
}

memoize 'who_am_i';
sub who_am_i () {
	return $ENV{PATNET_ID} if exists $ENV{PATNET_ID};

	# retreive the local ethernet addresses
	my $macfilters;
	open IP, "ip addr |";
	while (<IP>) {
		next unless m{link/ether ([a-zA-Z0-9:]+)};
		$macfilters .= "(macAddress=$1)";
	}
	close IP;

	# look for them
	return map($$_{dn}->[0], ldap_search(filter => "(|$macfilters)"));
}

sub ldap_dn2host ($) {
	my $dn = shift;
	my $e;


	# look for an 'ipHost' object among the entry and its parents
	do {
		return undef unless defined $dn;
		($e) = ldap_search(base => $dn, scope => 'base');
		return undef unless defined $e;
		$dn =~ s/[^,]*,?//;
	} while (!grep(/^patnetHost$/, @{$$e{objectClass}}));

	# get the unqualified hostname and convert the trailing DN to a domain
	my $host = $dn;
	$host =~ s/(?:^|.*?,)dc=/$$e{cn}->[0]./;
	$host =~ s/,dc=/\./g;

	return $host;
}


1;
