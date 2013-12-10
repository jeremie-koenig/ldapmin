CFGF=/usr/sbin/cfgf

default:
	@echo "Try 'make tmp/test' for instance."

tmp/%:
	mkdir -p tmp
	$(CFGF) -f ./cfgf.conf.tmp $*

clean:
	$(RM) -r tmp

