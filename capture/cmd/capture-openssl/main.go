package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/soverenio/ssl-capture/capture/ebpf"
)

func main() {
	var (
		binder ebpf.Binder
		ctx    = context.Background()
	)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	go func() {
		<-sigChan
		fmt.Println("info: received interrupt signal")

		stats, err := binder.Stats()
		if err != nil {
			fmt.Println("error: failed to get stats: ", err)
		}

		fmt.Println("total bytes read processed:    ", stats.ReadSize)
		fmt.Println("total bytes written processed: ", stats.WriteSize)
		fmt.Println("total ops read processed:  ", stats.ReadCount)
		fmt.Println("total ops write processed: ", stats.WriteCount)

		fmt.Println("total uprobe read processed:     ", stats.UprobeReadCount)
		fmt.Println("total uretprobe read processed:  ", stats.UretprobeReadCount)
		fmt.Println("total uprobe write processed:    ", stats.UprobeWriteCount)
		fmt.Println("total uretprobe write processed: ", stats.UretprobeWriteCount)
		fmt.Println("---------------------------------")

		_ = binder.Detach(ctx)

		os.Exit(0)
	}()

	if err := binder.Init(ctx); err != nil {
		fmt.Println("error: failed to init binder: ", err)
		os.Exit(1)
	}

	if err := binder.Attach(); err != nil {
		fmt.Println("error: failed to attach binder: ", err)
		os.Exit(1)
	}

	fmt.Println("success: binder attached")

	_ = binder.Events(ctx)
}
