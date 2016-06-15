WOLFSSL_PATH=$(shell pwd)/libs/wolfssl-3.8.0/
INSTALL_PREFIX=$(shell pwd)/install
LIBDIR=install/lib

all: wolfssl-configure wolfssl client server attacker

wolfssl-configure:
	cd $(WOLFSSL_PATH); ./autogen.sh
	cd $(WOLFSSL_PATH); ./configure --prefix=$(INSTALL_PREFIX) --libdir=$(INSTALL_PREFIX)/lib --enable-opensslextra

wolfssl:
	$(MAKE) -C $(WOLFSSL_PATH) all
	$(MAKE) -C $(WOLFSSL_PATH) install

server:
	gcc -o src/server src/server.c -Iinstall/include -L$(LIBDIR) -lwolfssl -Wl,-rpath -Wl,$(LIBDIR)

client:
	gcc -o src/client src/client.c -Iinstall/include -L$(LIBDIR) -lwolfssl -Wl,-rpath -Wl,$(LIBDIR)

attacker:
	gcc -o src/attacker src/attacker.c -Iinstall/include -L$(LIBDIR) -lwolfssl -Wl,-rpath -Wl,$(LIBDIR)

run-server: server
	src/server "data/server.pem" "data/server.key" "data/client.pem"

run-client: client
	src/client "data/root.pem" "data/client.pem" "data/client.key"

run-attacker: attacker
	src/attacker "data/root.pem" "data/attacker.pem" "data/attacker.key"

clean:
	$(MAKE) -C $(WOLFSSL_PATH) clean
	rm -f src/server
	rm -f src/client
	rm -f src/attacker
