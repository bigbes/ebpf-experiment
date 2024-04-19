package ebpf

import (
	"fmt"
	"slices"
	"testing"

	"github.com/saferwall/elf"

	"github.com/stretchr/testify/require"
)

func TestFindOpenSSLSo(t *testing.T) {
	path, err := FindOpenSSLSo()
	require.NoError(t, err)
	require.NotEmpty(t, path)
}

func TestFindSoSymbols(t *testing.T) {
	names, err := GetAttachableNames()
	require.NoError(t, err)
	require.NotEmpty(t, names)

	path, err := FindOpenSSLSo()
	require.NoError(t, err)
	require.NotEmpty(t, path)

	symbols, err := FindSoSymbols(path)
	require.NoError(t, err)

	var extSymbol []elf.Symbol
	for _, sym := range symbols {
		if sym.Library != "" {
			continue
		}

		// fmt.Printf("%#v\n", sym)

		if slices.Contains(names, sym.Name) {
			extSymbol = append(extSymbol, sym)
		}
	}

	require.NotEmpty(t, extSymbol)
	for _, sym := range extSymbol {
		fmt.Printf("%#v\n", sym)
	}
}

func TestAttach(t *testing.T) {
	Attach()
}
