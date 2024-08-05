all: clean ocsp_monitor

# Tidy up files created by compiler/linker.
clean:
	rm -f ocsp_monitor

ocsp_monitor:
	go build -ldflags "-X main.build_date=`date -u +%Y-%m-%d.%H:%M:%S`" ocsp_monitor.go processor_main.go
