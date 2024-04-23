package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/saferwall/elf"
)

func AttachRB() {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Println("failed to remove memlock rlimit:", err)
		return
	}

	// 1. Find libssl.so
	soPath, err := FindOpenSSLSo()
	if err != nil {
		fmt.Println("failed to find libssl.so", err)
		return
	}

	// 2. Find symbols in libssl.so
	symbols, err := FindSoSymbols(soPath)
	if err != nil {
		fmt.Println("failed to find symbols in libssl.so", err)
		return
	}

	objs := openssl_rbObjects{}
	err = loadOpenssl_rbObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			// LogLevel: ebpf.LogLevelInstruction,
			LogLevel: ebpf.LogLevelBranch,
			LogSize:  10_000_000,
		},
	})
	switch {
	case err != nil:
		fmt.Println("unwinding error chain:")
		for {
			fmt.Printf("%T\t\t %+v\n", err, err)

			err = errors.Unwrap(err)
			if err == nil {
				break
			}
		}

		return
	}
	defer func() { _ = objs.Close() }()

	// 3. Load eBPF programs
	osslTable, err := loadOpenssl_rb()
	if err != nil {
		fmt.Println("failed to load eBPF programs:", err)
		return
	}

	osslTable.Programs["uprobe_ssl_read"].AttachTarget = objs.UprobeSslRead
	osslTable.Programs["uretprobe_ssl_read"].AttachTarget = objs.UretprobeSslRead
	osslTable.Programs["uretprobe_ssl_write"].AttachTarget = objs.UretprobeSslWrite
	// osslTable.Programs["uretprobe_ssl_read_ex"].AttachTarget = objs.UretprobeSslReadEx
	// osslTable.Programs["uretprobe_ssl_write_ex"].AttachTarget = objs.UretprobeSslWriteEx
	// osslTable.Programs["uretprobe_ssl_write_ex2"].AttachTarget = objs.UretprobeSslWriteEx2

	lib, err := link.OpenExecutable(soPath)
	if err != nil {
		fmt.Println("failed to open shared lib ", soPath, err)
		return
	}

	// 4. Attach eBPF programs
	for _, prog := range osslTable.Programs {
		symbolExpectedName := prog.SectionName
		onReturn := false
		if strings.HasPrefix(symbolExpectedName, "uprobe/") {
			symbolExpectedName = symbolExpectedName[len("uprobe/"):]
		} else if strings.HasPrefix(symbolExpectedName, "uretprobe/") {
			onReturn = true
			symbolExpectedName = symbolExpectedName[len("uretprobe/"):]
		} else {
			continue
		}

		if !slices.ContainsFunc(symbols, func(symbol elf.Symbol) bool { return symbol.Name == symbolExpectedName }) {
			continue
		}

		var linkI link.Link
		if onReturn {
			linkI, err = lib.Uretprobe(symbolExpectedName, prog.AttachTarget, nil)
		} else {
			linkI, err = lib.Uprobe(symbolExpectedName, prog.AttachTarget, nil)
		}

		if err != nil {
			fmt.Println("failed to attach", prog.SectionName, err)
			continue
		}

		defer func(linkI link.Link) {
			_ = linkI.Close()
		}(linkI)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		fmt.Println("failed to create ringbuf reader", err)
		return
	}

	go func() {
		for {
			fmt.Println("reading")
			rec, err := rd.Read()
			fmt.Println("read")

			switch {
			case errors.Is(err, ringbuf.ErrClosed):
				fmt.Println("ringbuf reader closed")
				return
			case err != nil:
				fmt.Println("failed to read ringbuf record", err)
			}

			perfEvent := openssl_rbEvent{}

			buf := bytes.NewBuffer(rec.RawSample)
			if err = binary.Read(buf, binary.LittleEndian, &perfEvent); err != nil {
				fmt.Println("failed to read perf event", err)
			}

			if perfEvent.SkippedBytes > 0 {
				fmt.Println(perfEvent.Op, "skipped bytes", perfEvent.SkippedBytes)
			} else {
				fmt.Println(perfEvent.Op, "body:", string(perfEvent.Bytes[:perfEvent.ByteSize]))
				Hexdump(perfEvent.Bytes[:perfEvent.ByteSize])
			}
		}
	}()

	time.Sleep(20 * time.Second)
}
