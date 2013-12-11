cg_comment(`//')

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";

cg_foreach(`DOMAIN', 1, `m4_dnl
zone "DOMAIN" {
	type master;
	file "m4_esyscmd(`pwd | cg_m4ify')`/ldapmin/domain/zones/'DOMAIN";
};

', ldapmin_domain_zones)m4_dnl
