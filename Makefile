all: clean ocsp_monitor

# Tidy up files created by compiler/linker.
clean:
	rm -f ocsp_monitor

ocsp_monitor:
	GOPATH=/root/go go build ocsp_monitor.go processor_main.go
