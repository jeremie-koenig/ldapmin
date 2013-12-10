CFGF=/usr/sbin/cfgf

default:
	@echo "Try 'make tmp/test' for instance."

tmp/%: ALWAYS_DO
	mkdir -p tmp
	$(CFGF) -f ./cfgf.conf.tmp $*

clean:
	$(RM) -r tmp

ALWAYS_DO:

