.PHONY: generate ebpf-trace

run:
	sudo go run capture/cmd/capture-openssl/main.go

generate:
	GOWORK=off go generate ./...

ebpf-trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

test:
	sudo go test -count=1 -run=TestAttach -v github.com/soverenio/ssl-capture/capture/ebpf
