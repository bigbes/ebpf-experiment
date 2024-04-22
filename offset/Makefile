PREFIX?=$(PWD)
CC=clang
CFLAGS=

SOURCES=openssl-offsets.c

openssl-1.1.1u:
	$(CC) -o bin/openssl-1.1.1u $(CFLAGS) -I$(PREFIX)/openssl-1.1.1u -I$(PREFIX)/openssl-1.1.1u/include $(SOURCES)

openssl-3.0.0:
	$(CC) -o bin/openssl-3.0.0 $(CFLAGS) -I$(PREFIX)/openssl-3.0.0 -I$(PREFIX)/openssl-3.0.0/include $(SOURCES)

openssl-3.1.0:
	$(CC) -o bin/openssl-3.1.0 $(CFLAGS) -I$(PREFIX)/openssl-3.1.0 -I$(PREFIX)/openssl-3.1.0/include $(SOURCES)

openssl-3.2.0:
	$(CC) -o bin/openssl-3.2.0 $(CFLAGS) -I$(PREFIX)/openssl-3.2.0 -I$(PREFIX)/openssl-3.2.0/include $(SOURCES)

openssl-3.3.0:
	$(CC) -o bin/openssl-3.3.0 $(CFLAGS) -I$(PREFIX)/openssl-3.3.0 -I$(PREFIX)/openssl-3.3.0/include $(SOURCES)

.PHONY: openssl-1.1.1u openssl-3.0.0 openssl-3.1.0 openssl-3.2.0 openssl-3.3.0
.PHONY: all build execute prepare

all: build execute

build: openssl-1.1.1u openssl-3.0.0 openssl-3.1.0 openssl-3.2.0 openssl-3.3.0

execute:
	./bin/openssl-1.1.1u
	./bin/openssl-3.0.0
	./bin/openssl-3.1.0
	./bin/openssl-3.2.0
	./bin/openssl-3.3.0

prepare:
	git clone https://github.com/openssl/openssl.git --depth=1 --branch OpenSSL_1_1_1u openssl-1.1.1u && cd openssl-1.1.1u && ./config && make -j
	git clone https://github.com/openssl/openssl.git --depth=1 --branch openssl-3.0.0  openssl-3.0.0  && cd openssl-3.0.0  && ./config && make -j
	git clone https://github.com/openssl/openssl.git --depth=1 --branch openssl-3.1.0  openssl-3.1.0  && cd openssl-3.1.0  && ./config && make -j
	git clone https://github.com/openssl/openssl.git --depth=1 --branch openssl-3.2.0  openssl-3.2.0  && cd openssl-3.2.0  && ./config && make -j
	git clone https://github.com/openssl/openssl.git --depth=1 --branch openssl-3.3.0  openssl-3.3.0  && cd openssl-3.3.0  && ./config && make -j
