PBCDIR = pbc-0.5.11
PYPBCDIR = pypbc

all: install-pbc install-pypbc

pbc:
	$(MAKE) -C $(PBCDIR)

pypbc:
	$(MAKE) -C $(PYPBCDIR)

install: install-pbc install-pypbc

install-pbc: pbc
	$(MAKE) install -C $(PBCDIR)

install-pypbc: pypbc
	$(MAKE) install -C $(PYPBCDIR)

clean:
	$(MAKE) clean -C $(PBCDIR) && $(MAKE) clean -C $(PYPBCDIR)

