.PHONY: generate ebpf-trace

generate:
	GOWORK=off go generate ./...

ebpf-trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

test:
	sudo go test -count=1 -run=TestAttachRB -v github.com/soverenio/ssl-capture/capture/ebpf
