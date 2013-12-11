# Add bind configuration to the appropriate hooks

stamp/etc: \
	etc/bind/named.conf.local \

stamp/init: \
	stamp/init.d/bind9 \

stamp/init.d/bind9: \
	etc/bind/named.conf.local \
	ldapmin/domain/zones \

