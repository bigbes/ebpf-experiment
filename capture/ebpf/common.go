package ebpf

import (
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/saferwall/elf"
)

func FindOpenSSLSo() (string, error) {
	libDirs := []string{
		"/lib",
		"/lib64",
		"/usr/lib",
		"/usr/lib64",
	}

	for _, libDir := range libDirs {
		sslPath := path.Join(libDir, "libssl.so")
		fileInfo, err := os.Lstat(sslPath)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("not found", sslPath)
			continue
		}

		if (fileInfo.Mode() & os.ModeSymlink) == 0 {
			fmt.Println("not a symlink", sslPath)
			continue
		}

		newPath, err := os.Readlink(sslPath)
		if err != nil {
			fmt.Println("readlink failed", sslPath, err)
			continue
		}

		if !path.IsAbs(newPath) {
			return path.Join(path.Dir(sslPath), newPath), nil
		}
		return newPath, nil
	}

	return "", os.ErrNotExist
}

func FindSoSymbols(soPath string) ([]elf.Symbol, error) {
	file, err := elf.New(soPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.CloseFile() }()

	err = file.Parse()
	if err != nil {
		return nil, err
	}

	return file.F.ELFSymbols.NamedSymbols, nil
}
