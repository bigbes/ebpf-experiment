package ebpf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadOpenSSLVersionFromFile(t *testing.T) {
	sslSoPath, err := FindLibCryptoSo()
	require.NoError(t, err)

	version, err := ReadOpenSSLVersionFromFile(sslSoPath)
	require.NoError(t, err)

	require.NotEmpty(t, version)
	t.Log("version: ", version)
}

func TestCheckRegexp(t *testing.T) {
	for _, line := range []string{
		"OpenSSL 3.0.0 7 sep 2021",
		"OpenSSL 0.9.5a 1 Apr 2000",
		"OpenSSL 1.0.1e-fips 11 Feb 2013",
		"OpenSSL 1.0.2n 7 Dec 2017",
	} {
		t.Run(line, func(t *testing.T) {
			require.True(t, OpenSSLSymbolVersion.MatchString(line))
		})
	}
}
