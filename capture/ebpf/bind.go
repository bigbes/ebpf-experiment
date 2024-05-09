package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/saferwall/elf"
)

func wrap(err error, msg string) error {
	return fmt.Errorf("%s: %w", msg, err)
}

type Binder struct {
	opensslPath    string
	libcryptoPath  string
	opensslVersion string
	symbols        []string

	rbuf *ringbuf.Reader

	objects opensslObjects
	spec    *ebpf.CollectionSpec
	links   []link.Link
}

func (b *Binder) Init(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return wrap(err, "failed to remove memlock rlimit")
	}

	// 1. Find libssl.so
	opensslPath, err := FindOpenSSLSo()
	if err != nil {
		return wrap(err, "failed to find libssl.so")
	}

	symbols, err := FindSoSymbols(opensslPath)
	if err != nil {
		return wrap(err, "failed to find symbols in libssl.so")
	}
	b.symbols = Convert(symbols, func(in elf.Symbol) string { return in.Name })

	libcryptoPath, err := FindLibCryptoSo()
	if err != nil {
		return wrap(err, "failed to find libcrypto.so")
	}

	version, err := ReadOpenSSLVersionFromFile(libcryptoPath)

	b.libcryptoPath = libcryptoPath
	b.opensslPath = opensslPath
	b.opensslVersion = version

	return nil
}

func (b *Binder) Attach() error {
	err := loadOpensslObjects(&b.objects, &ebpf.CollectionOptions{
		Maps:            ebpf.MapOptions{},
		Programs:        ebpf.ProgramOptions{},
		MapReplacements: nil,
	})
	if err != nil {
		return wrap(err, "failed to load eBPF programs")
	}

	b.spec, err = loadOpenssl()
	if err != nil {
		return wrap(err, "failed to load eBPF programs")
	}

	{
		b.spec.Programs["uprobe_ssl_read"].AttachTarget = b.objects.UprobeSslRead
		b.spec.Programs["uretprobe_ssl_read"].AttachTarget = b.objects.UretprobeSslRead
		b.spec.Programs["uprobe_ssl_write"].AttachTarget = b.objects.UprobeSslWrite
		b.spec.Programs["uretprobe_ssl_write"].AttachTarget = b.objects.UretprobeSslWrite
	}

	for i := 0; i < 4; i++ {
		err = b.objects.SslStatsMap.Put(uint32(i), uint64(0))
		if err != nil {
			return wrap(err, "failed to put ssl stats map "+strconv.Itoa(i))
		}
	}

	lib, err := link.OpenExecutable(b.opensslPath)
	if err != nil {
		return wrap(err, "failed to open shared lib")
	}

	for _, prog := range b.spec.Programs {
		symbolExpectedName := prog.SectionName
		onReturn := false

		switch {
		case strings.HasPrefix(symbolExpectedName, "uprobe/"):
			symbolExpectedName = symbolExpectedName[len("uprobe/"):]
		case strings.HasPrefix(symbolExpectedName, "uretprobe/"):
			symbolExpectedName = symbolExpectedName[len("uretprobe/"):]
			onReturn = true
		default:
			continue
		}

		if !slices.Contains(b.symbols, symbolExpectedName) {
			continue
		}

		var linkI link.Link
		if onReturn {
			linkI, err = lib.Uretprobe(symbolExpectedName, prog.AttachTarget, nil)
		} else {
			linkI, err = lib.Uprobe(symbolExpectedName, prog.AttachTarget, nil)
		}

		if err != nil {
			return wrap(err, "failed to attach")
		}

		b.links = append(b.links, linkI)
	}

	b.rbuf, err = ringbuf.NewReader(b.objects.Events)
	if err != nil {
		return wrap(err, "failed to create ringbuf reader")
	}

	return nil
}

func (b *Binder) Detach(ctx context.Context) error {
	for _, linkI := range b.links {
		_ = linkI.Close()
	}

	_ = b.objects.Close()
	_ = b.rbuf.Close()

	return nil
}

func (b *Binder) Events(ctx context.Context) error {
	var record ringbuf.Record

	var (
		totalBytesRead, totalBytesWritten      int
		totalOpsRead, totalOpsWrite            int
		totalBytesRSkipped, totalBytesWSkipped int
	)

	defer func() {
		fmt.Println("Total bytes read", totalBytesRead)
		fmt.Println("Total bytes written", totalBytesWritten)
		fmt.Println("Total bytes read skipped", totalBytesRSkipped)
		fmt.Println("Total bytes read written", totalBytesWSkipped)
		fmt.Println("Total packets read", totalOpsRead)
		fmt.Println("Total packets write", totalOpsWrite)
		fmt.Println("---------------------------------")
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		err := b.rbuf.ReadInto(&record)
		switch {
		case errors.Is(err, ringbuf.ErrClosed):
			return nil
		case err != nil:
			fmt.Println("error: failed to read ringbuf record", err)
			return nil
		}

		perfEvent := opensslEvent{}
		buf := bytes.NewBuffer(record.RawSample)
		if err = binary.Read(buf, binary.LittleEndian, &perfEvent); err != nil {
			fmt.Println("error: failed to read perf event", err)
			return nil
		}

		switch {
		case perfEvent.SkippedBytes > 0 && perfEvent.Op == 1:
			totalBytesRSkipped += int(perfEvent.SkippedBytes)
			totalOpsRead++
		case perfEvent.SkippedBytes > 0 && perfEvent.Op == 3:
			totalBytesWSkipped += int(perfEvent.SkippedBytes)
			totalOpsWrite++
		case perfEvent.Op == 1 && perfEvent.ByteSize > 0:
			totalBytesRead += int(perfEvent.ByteSize)
			totalOpsRead++
		case perfEvent.Op == 3 && perfEvent.ByteSize > 0:
			totalBytesWritten += int(perfEvent.ByteSize)
			totalOpsWrite++
		}
	}
}

type BinderStats struct {
	ReadCount  uint64
	ReadSize   uint64
	WriteCount uint64
	WriteSize  uint64
}

func (b *Binder) Stats() (BinderStats, error) {
	var stats BinderStats

	err := b.objects.SslStatsMap.Lookup(uint32(0), &stats.ReadCount)
	if err != nil {
		return BinderStats{}, wrap(err, "failed to lookup ssl read count stats")
	}

	err = b.objects.SslStatsMap.Lookup(uint32(1), &stats.ReadSize)
	if err != nil {
		return BinderStats{}, wrap(err, "failed to lookup ssl read size stats")
	}

	err = b.objects.SslStatsMap.Lookup(uint32(2), &stats.WriteCount)
	if err != nil {
		return BinderStats{}, wrap(err, "failed to lookup ssl read write count")
	}

	err = b.objects.SslStatsMap.Lookup(uint32(3), &stats.WriteSize)
	if err != nil {
		return BinderStats{}, wrap(err, "failed to lookup ssl read write stats")
	}

	return stats, nil
}
