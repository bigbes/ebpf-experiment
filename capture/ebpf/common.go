package ebpf

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/saferwall/elf"
)

func zero[T any]() (val T) {
	return
}

func Convert[I any, O any](in []I, convertFn func(I) O) (out []O) {
	for _, elem := range in {
		out = append(out, convertFn(elem))
	}

	return
}

func findInSlice[T any](slice []T, compFn func(elem T) bool) (bool, T) {
	for _, elem := range slice {
		if compFn(elem) {
			return true, elem
		}
	}
	return false, zero[T]()
}

func findAllInSlice[T any](slice []T, compFn func(elem T) bool) (found []T) {
	for _, elem := range slice {
		if compFn(elem) {
			found = append(found, elem)
		}
	}

	return
}

var OpenSSLSymbolVersion = regexp.MustCompile(`OpenSSL \S+ [0-9]+ \S+ [0-9]+`)
var OpenSSLSymbolNameVersion = regexp.MustCompile(`OPENSSL_(\d+.\d+.\d+[a-z]?)`)

func ReadOpenSSLVersionFromFile(opensslPath string) (string, error) {
	file, err := os.Open(opensslPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	idxs := OpenSSLSymbolVersion.FindReaderIndex(bufio.NewReader(file))
	if idxs == nil {
		return "", errors.New("OpenSSL version not found")
	}

	_, err = file.Seek(int64(idxs[0]), io.SeekStart)

	buf := [1024]byte{}
	read, err := file.Read(buf[:])
	if err != nil {
		return "", err
	}
	if read == 0 {
		return "", errors.New("empty file")
	}

	return string(OpenSSLSymbolVersion.Find(buf[:read])), nil

}

// func LoadOpenSSLVersionSymbol(opensslPath string) (string, error) {
// 	file, err := elf.New(opensslPath)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer func() { _ = file.CloseFile() }()
//
// 	err = file.Parse()
// 	if err != nil {
// 		return "", err
// 	}
//
// 	el := findAllInSlice(file.F.ELFSymbols.NamedSymbols, func(symbol elf.Symbol) bool {
// 		return OpenSSLSymbolNameVersion.MatchString(symbol.Name)
// 		// return strings.HasPrefix(symbol.Name, "OPENSSL_") && len(symbol.Library) == 0 && symbol.Size == 0
// 	})
//
// 	if len(el) == 0 {
// 		return "", errors.New("OPENSSL_ symbol not found")
// 	}
//
// 	return "", nil
//
// 	// for _, symbol := range file.F.ELFSymbols.NamedSymbols {
// 	// 	fmt.Println(symbol.Name, symbol.Library, symbol.Version, symbol.Value, symbol.Size)
// 	// }
// 	//
// 	// found, symbol := findInSlice(file.F.ELFSymbols.NamedSymbols,
// 	// 	func(symbol elf.Symbol) bool { return symbol.Name == "SSL_version" })
// 	// if !found {
// 	// 	return "", errors.New("SSL_version not found")
// 	// }
// 	//
// 	// var dataer interface{ Data() ([]byte, error) } = nil
// 	//
// 	// switch {
// 	// case len(file.F.Sections32) > 0:
// 	// 	if int(symbol.Index) >= len(file.F.Sections32) {
// 	// 		return "", errors.New("symbol index out of bounds")
// 	// 	} else if symbol.Index < 0 {
// 	// 		return "", errors.New("negative symbol index")
// 	// 	}
// 	//
// 	// 	dataer = file.F.Sections32[symbol.Index]
// 	// case len(file.F.Sections64) > 0:
// 	// 	if int(symbol.Index) >= len(file.F.Sections64) {
// 	// 		return "", errors.New("symbol index out of bounds")
// 	// 	} else if symbol.Index < 0 {
// 	// 		return "", errors.New("negative symbol index")
// 	// 	}
// 	//
// 	// 	dataer = file.F.Sections64[symbol.Index]
// 	// default:
// 	// 	return "", errors.New("no sections found")
// 	// }
// 	//
// 	// sectionBody, err := dataer.Data()
// 	// if err != nil {
// 	// 	return "", throw.W(err, "failed to read section data")
// 	// }
// 	//
// 	// if symbol.Value > uint64(len(sectionBody)) {
// 	// 	return "", errors.New("symbol start out of bounds")
// 	// } else if symbol.Value+symbol.Size > uint64(len(sectionBody)) {
// 	// 	return "", errors.New("symbol end out of bounds")
// 	// } else if symbol.Value < 0 {
// 	// 	return "", errors.New("negative symbol start")
// 	// } else if symbol.Size == 0 {
// 	// 	return "", errors.New("zero symbol size")
// 	// }
// 	//
// 	// return string(sectionBody[symbol.Value : symbol.Value+symbol.Size]), nil
// }

const EnvLibraryPaths = "LIBRARY_PATH"

func FindSo(name string) (string, error) {
	libDirs := []string{
		"/lib",
		"/lib64",
		"/usr/lib",
		"/usr/lib64",
	}

	if envLibraryPath := os.Getenv(EnvLibraryPaths); envLibraryPath != "" {
		extLibraryPath := strings.Split(envLibraryPath, ":")
		libDirs = append(libDirs, extLibraryPath...)
	}

	for _, libDir := range libDirs {
		soPath := path.Join(libDir, name)

		fileInfo, err := os.Lstat(soPath)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("not found", soPath)
			continue
		}

		if (fileInfo.Mode() & os.ModeSymlink) == 0 {
			fmt.Println("not a symlink", soPath)
			continue
		}

		newPath, err := os.Readlink(soPath)
		if err != nil {
			fmt.Println("readlink failed", soPath, err)
			continue
		}

		if !path.IsAbs(newPath) {
			return path.Join(path.Dir(soPath), newPath), nil
		}
		return newPath, nil
	}

	return "", os.ErrNotExist
}

func FindOpenSSLSo() (string, error) {
	return FindSo("libssl.so")
}

func FindLibCryptoSo() (string, error) {
	return FindSo("libcrypto.so")
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

func Hexdump(data []byte) {
	for i := 0; i < len(data); i += 16 {
		fmt.Printf("%08x: ", i)
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				fmt.Printf("%02x ", data[i+j])
			} else {
				fmt.Print("   ")
			}
		}
		fmt.Print(" ")
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				if data[i+j] >= 32 && data[i+j] <= 126 {
					fmt.Printf("%c", data[i+j])
				} else {
					fmt.Print(".")
				}
			}
		}
		fmt.Println()
	}
}
