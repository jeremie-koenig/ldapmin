# Base rules for ldapmin

# Add the pkgsync configuration files
stamp/etc: \
	etc/pkgsync/musthave \
	etc/pkgsync/mayhave \
	etc/pkgsync/maynothave \
	etc/hostname \
	etc/hosts \

