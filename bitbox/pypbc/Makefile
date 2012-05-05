BUILD_DIR = build/lib.*
CLEAN_BUILD = if [ -d build ]; then rm -r build; fi;
CLEAN_DIST = if [ -d dist ]; then rm -r dist; fi; if [ -f MANIFEST ]; then rm MANIFEST; fi;
CLEAN = $(CLEAN_BUILD) $(CLEAN_DIST)
BUILD = $(CLEAN) ./setup.py build

pypbc:
	$(BUILD)
	
dist:
	$(BUILD) sdist
	$(CLEAN)

play:
	$(BUILD)
	cd $(BUILD_DIR); python3 -i -c "from pypbc import *; from KSW import *"
	$(CLEAN)

commit:
	rm *~ 2> /dev/null
	git add .
	git commit
	git push origin master

install:
	$(BUILD) install
	$(CLEAN)
	
clean:
	$(CLEAN)
