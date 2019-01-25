# TODO: On install chmod ssl/*

all:
	@/bin/echo -e "\n--------- pynl80211 Makefile"
	$(MAKE) -C slbd/pynl80211/
	
	@/bin/echo -e "\n--------- slbcore Makefile"
	$(MAKE) -C slbcore/
	
clean:
	@/bin/echo -e "\n--------- pynl80211 Makefile"
	$(MAKE) -C slbd/pynl80211/ clean
	
	@/bin/echo -e "\n--------- slbcore Makefile"
	$(MAKE) -C slbcore/ clean
	
	@/bin/echo -e "\n--------- Cleaning files"
	
	rm -rf *.pyc slbd/*.pyc *.log .tmp_versions/