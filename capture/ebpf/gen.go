//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --target amd64 -type event openssl openssl.c -- -I../system/include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --target amd64 -type event openssl_rb openssl_rb.c -- -I../system/include
package ebpf
