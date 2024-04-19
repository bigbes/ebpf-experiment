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
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/saferwall/elf"
)

func GetAttachableNames() ([]string, error) {
	osslTable, err := loadOpenssl()
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, len(osslTable.Programs))
	for _, prog := range osslTable.Programs {
		symbolExpectedName := prog.SectionName
		if strings.HasPrefix(symbolExpectedName, "uprobe/") {
			symbolExpectedName = symbolExpectedName[len("uprobe/"):]
		} else if strings.HasPrefix(symbolExpectedName, "uretprobe/") {
			symbolExpectedName = symbolExpectedName[len("uretprobe/"):]
		}

		out = append(out, symbolExpectedName)
	}

	return out, nil
}

func Attach() {
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

	objs := opensslObjects{}
	err = loadOpensslObjects(&objs, &ebpf.CollectionOptions{
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
	osslTable, err := loadOpenssl()
	if err != nil {
		fmt.Println("failed to load eBPF programs:", err)
		return
	}

	osslTable.RewriteConstants(map[string]interface{}{})

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
			// linkI, err = lib.Uprobe(symbolExpectedName, prog.AttachTarget, nil)
		}

		if err != nil {
			fmt.Println("failed to attach", prog.SectionName, err)
			continue
		}

		defer func(linkI link.Link) {
			_ = linkI.Close()
		}(linkI)
	}

	rd, err := perf.NewReader(objs.Events, 1024*10)
	if err != nil {
		fmt.Println("failed to create perf reader", err)
		return
	}

	go func() {
		for {
			fmt.Println("reading")
			rec, err := rd.Read()
			fmt.Println("read")

			switch {
			case errors.Is(err, perf.ErrClosed):
				fmt.Println("perf reader closed")
				return
			case err != nil:
				fmt.Println("failed to read perf record", err)
			}

			if rec.LostSamples != 0 {
				fmt.Println("lost samples", rec.LostSamples)
			}

			perfEvent := opensslEvent{}

			buf := bytes.NewBuffer(rec.RawSample)
			fmt.Println("size:", buf.Len())
			if err = binary.Read(buf, binary.LittleEndian, &perfEvent); err != nil {
				fmt.Println("failed to read perf event", err)
			}
			fmt.Printf("%#v\n", perfEvent)
		}
	}()

	time.Sleep(20 * time.Second)
}
