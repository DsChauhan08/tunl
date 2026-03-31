CC := gcc
CXX := g++
INSTALL := install
PKG_CONFIG ?= pkg-config

SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
OBJ_DIR := $(BUILD_DIR)/obj

TARGET := spf
INSTALL_PREFIX := /usr/local
INSTALL_BIN := $(INSTALL_PREFIX)/bin
DESTDIR ?=

C_SOURCES := \
	$(SRC_DIR)/config.c \
	$(SRC_DIR)/core.c \
	$(SRC_DIR)/metrics.c \
	$(SRC_DIR)/tls.c
CXX_SOURCES := $(filter-out $(SRC_DIR)/esp32.cpp, $(wildcard $(SRC_DIR)/*.cpp))

C_OBJECTS := $(C_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
CXX_OBJECTS := $(CXX_SOURCES:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)
OBJECTS := $(C_OBJECTS) $(CXX_OBJECTS)

DEPS := $(OBJECTS:.o=.d)

COMMON_CFLAGS := -Wall -Wextra -Wpedantic -Werror=implicit-function-declaration
COMMON_CXXFLAGS := -Wall -Wextra -Wpedantic -std=c++11

OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null)

DEBUG_CFLAGS := -g -O0 -DDEBUG
DEBUG_CXXFLAGS := -g -O0 -DDEBUG
DEBUG_LDFLAGS :=

RELEASE_CFLAGS := -O3 -march=native -flto -DNDEBUG
RELEASE_CXXFLAGS := -O3 -march=native -flto -DNDEBUG -fno-exceptions
RELEASE_LDFLAGS := -flto -s

LIBS := $(OPENSSL_LIBS) -lpthread
ifeq ($(strip $(OPENSSL_LIBS)),)
LIBS := -lssl -lcrypto -lpthread
endif

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    PLATFORM := linux
    LIBS += -lrt
endif
ifeq ($(UNAME_S),Darwin)
    PLATFORM := macos
endif
ifeq ($(UNAME_S),FreeBSD)
    PLATFORM := freebsd
endif

BUILD_MODE ?= release

ifeq ($(BUILD_MODE),debug)
    CFLAGS := $(COMMON_CFLAGS) $(DEBUG_CFLAGS)
    CXXFLAGS := $(COMMON_CXXFLAGS) $(DEBUG_CXXFLAGS)
    LDFLAGS := $(DEBUG_LDFLAGS)
    TARGET := $(TARGET)-debug
else
    CFLAGS := $(COMMON_CFLAGS) $(RELEASE_CFLAGS)
    CXXFLAGS := $(COMMON_CXXFLAGS) $(RELEASE_CXXFLAGS)
    LDFLAGS := $(RELEASE_LDFLAGS)
endif

CFLAGS += -MMD -MP $(OPENSSL_CFLAGS)
CXXFLAGS += -MMD -MP $(OPENSSL_CFLAGS)

.PHONY: all clean install uninstall check help debug release test-smoke test-cli install-man uninstall-man package-deb package-rpm package-all

all: $(BIN_DIR)/$(TARGET)

debug:
	@$(MAKE) BUILD_MODE=debug all

asan:
	@$(MAKE) BUILD_MODE=debug CC=clang CXX=clang++ CFLAGS="$(COMMON_CFLAGS) $(DEBUG_CFLAGS) -fsanitize=address -fno-omit-frame-pointer" CXXFLAGS="$(COMMON_CXXFLAGS) $(DEBUG_CXXFLAGS) -fsanitize=address -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" TARGET=spf

ubsan:
	@$(MAKE) BUILD_MODE=debug CC=clang CXX=clang++ CFLAGS="$(COMMON_CFLAGS) $(DEBUG_CFLAGS) -fsanitize=undefined -fno-omit-frame-pointer" CXXFLAGS="$(COMMON_CXXFLAGS) $(DEBUG_CXXFLAGS) -fsanitize=undefined -fno-omit-frame-pointer" LDFLAGS="-fsanitize=undefined" TARGET=spf

sanitizers: asan ubsan

release:
	@$(MAKE) BUILD_MODE=release all

$(BIN_DIR)/$(TARGET): $(OBJECTS) | $(BIN_DIR)
	@echo "Linking $@..."
	@$(CXX) $(OBJECTS) -o $@ $(LDFLAGS) $(LIBS)
	@echo "Build complete: $@"
	@ls -lh $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	@echo "Compiling $<..."
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR):
	@mkdir -p $@

install: $(BIN_DIR)/$(TARGET)
	@echo "Installing $(TARGET) to $(INSTALL_BIN)..."
	@$(INSTALL) -d "$(DESTDIR)$(INSTALL_BIN)"
	@$(INSTALL) -m 755 $(BIN_DIR)/$(TARGET) "$(DESTDIR)$(INSTALL_BIN)/$(TARGET)"
	@echo "Installed!"
	@$(MAKE) install-man

uninstall:
	@rm -f "$(DESTDIR)$(INSTALL_BIN)/$(TARGET)"
	@$(MAKE) uninstall-man
	@echo "Uninstalled!"

install-man:
	@$(INSTALL) -d "$(DESTDIR)$(INSTALL_PREFIX)/share/man/man1"
	@if [ -f docs/man/spf.1 ]; then \
		$(INSTALL) -m 644 docs/man/spf.1 "$(DESTDIR)$(INSTALL_PREFIX)/share/man/man1/spf.1"; \
	elif [ -f docs/man/tunl.1 ]; then \
		$(INSTALL) -m 644 docs/man/tunl.1 "$(DESTDIR)$(INSTALL_PREFIX)/share/man/man1/spf.1"; \
	fi

uninstall-man:
	@rm -f "$(DESTDIR)$(INSTALL_PREFIX)/share/man/man1/spf.1"

install-service: install
	@echo "Creating systemd service..."
	@echo "[Unit]" > /tmp/spf.service
	@echo "Description=SPF Network Forwarder" >> /tmp/spf.service
	@echo "After=network.target" >> /tmp/spf.service
	@echo "" >> /tmp/spf.service
	@echo "[Service]" >> /tmp/spf.service
	@echo "Type=simple" >> /tmp/spf.service
	@echo "User=spf" >> /tmp/spf.service
	@echo "ExecStart=$(INSTALL_BIN)/$(TARGET) --daemon --token=CHANGEME" >> /tmp/spf.service
	@echo "Restart=on-failure" >> /tmp/spf.service
	@echo "" >> /tmp/spf.service
	@echo "[Install]" >> /tmp/spf.service
	@echo "WantedBy=multi-user.target" >> /tmp/spf.service
	@sudo $(INSTALL) -m 644 /tmp/spf.service /etc/systemd/system/spf.service
	@rm /tmp/spf.service
	@echo "Service installed. Edit token then: sudo systemctl enable --now spf"

uninstall-service:
	@sudo systemctl stop spf 2>/dev/null || true
	@sudo systemctl disable spf 2>/dev/null || true
	@sudo rm -f /etc/systemd/system/spf.service
	@sudo systemctl daemon-reload

check-deps:
	@echo "Checking deps..."
	@which $(CC) >/dev/null 2>&1 || (echo "Need gcc" && exit 1)
	@which $(CXX) >/dev/null 2>&1 || (echo "Need g++" && exit 1)
	@$(PKG_CONFIG) --exists openssl 2>/dev/null || (echo "Need openssl dev package" && exit 1)
	@echo "All deps OK!"

install-deps-debian:
	sudo apt-get update
	sudo apt-get install -y build-essential libssl-dev pkg-config

install-deps-redhat:
	sudo dnf install -y gcc gcc-c++ make openssl-devel pkgconf-pkg-config || sudo yum install -y gcc gcc-c++ make openssl-devel pkgconfig

install-deps-fedora: install-deps-redhat

install-deps-rhel: install-deps-redhat

install-deps-suse:
	sudo zypper install -y gcc gcc-c++ make libopenssl-devel pkg-config

install-deps-alpine:
	sudo apk add --no-cache build-base openssl-dev pkgconf

install-deps-arch:
	sudo pacman -S --needed base-devel openssl

install-deps-macos:
	brew install openssl

test: $(BIN_DIR)/$(TARGET)
	@echo "Testing binary..."
	@test -f $(BIN_DIR)/$(TARGET) && echo "OK binary exists"
	@test -x $(BIN_DIR)/$(TARGET) && echo "OK executable"
	@if command -v ldd >/dev/null 2>&1; then ldd $(BIN_DIR)/$(TARGET) >/dev/null 2>&1 && echo "OK deps"; fi
	@$(MAKE) test-smoke
	@$(MAKE) test-cli
	@echo "Tests passed!"

test-smoke: $(BIN_DIR)/$(TARGET)
	@echo "Running integration smoke tests..."
	@python3 tests/integration_smoke.py

test-cli: $(BIN_DIR)/$(TARGET)
	@echo "Running real-world CLI tests..."
	@bash tests/cli_realworld.sh

fuzz-ctrl:
	@echo "Building control parser fuzz harness..."
	@clang -g -O1 -fsanitize=fuzzer,address,undefined -I$(SRC_DIR) $(OPENSSL_CFLAGS) tests/fuzz_ctrl_parser.c src/core.c -o bin/fuzz_ctrl_parser $(OPENSSL_LIBS) -lpthread -lrt
	@echo "Built bin/fuzz_ctrl_parser"

package-deb: $(BIN_DIR)/$(TARGET)
	@VERSION=$${VERSION:-$$(git describe --tags --always 2>/dev/null | sed 's/^v//')}; \
	[ -z "$$VERSION" ] && VERSION="2.0.0"; \
	rm -rf build/pkg-deb && mkdir -p build/pkg-deb/DEBIAN build/pkg-deb/usr/bin build/pkg-deb/usr/share/man/man1; \
	cp "$(BIN_DIR)/$(TARGET)" build/pkg-deb/usr/bin/spf; \
	chmod 755 build/pkg-deb/usr/bin/spf; \
	if [ -f docs/man/spf.1 ]; then cp docs/man/spf.1 build/pkg-deb/usr/share/man/man1/spf.1; else cp docs/man/tunl.1 build/pkg-deb/usr/share/man/man1/spf.1; fi; \
	gzip -f build/pkg-deb/usr/share/man/man1/spf.1; \
	printf '%s\n' \
	"Package: spf" \
	"Version: $$VERSION" \
	"Section: net" \
	"Priority: optional" \
	"Architecture: amd64" \
	"Depends: libc6, libssl3" \
	"Maintainer: SPF Project" \
	"Description: Secure Public Forwarder" \
	" Lightweight secure TCP forwarder with hardened admin control-plane." \
	> build/pkg-deb/DEBIAN/control; \
	if ! command -v dpkg-deb >/dev/null 2>&1; then echo "dpkg-deb not found" >&2; exit 1; fi; \
	dpkg-deb --build build/pkg-deb "spf_$${VERSION}_amd64.deb"; \
	echo "Built spf_$${VERSION}_amd64.deb"

package-rpm: $(BIN_DIR)/$(TARGET)
	@VERSION=$${VERSION:-$$(git describe --tags --always 2>/dev/null | sed 's/^v//')}; \
	[ -z "$$VERSION" ] && VERSION="2.0.0"; \
	RPM_VERSION=$${VERSION//-/~}; \
	rm -rf build/rpmbuild && mkdir -p build/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}; \
	cp "$(BIN_DIR)/$(TARGET)" build/rpmbuild/SOURCES/spf; \
	printf '%s\n' \
	"Name: spf" \
	"Version: $$RPM_VERSION" \
	"Release: 1%%{?dist}" \
	"Summary: Secure Public Forwarder" \
	"License: GPL-2.0" \
	"URL: https://github.com/DsChauhan08/tunl" \
	"" \
	"%%description" \
	"Lightweight secure TCP forwarder with hardened admin control-plane." \
	"" \
	"%%install" \
	"mkdir -p %%{buildroot}/usr/bin" \
	"install -m 755 %%{_sourcedir}/spf %%{buildroot}/usr/bin/spf" \
	"" \
	"%%files" \
	"/usr/bin/spf" \
	> build/rpmbuild/SPECS/spf.spec; \
	if ! command -v rpmbuild >/dev/null 2>&1; then echo "rpmbuild not found" >&2; exit 1; fi; \
	rpmbuild --define "_topdir $(CURDIR)/build/rpmbuild" -bb build/rpmbuild/SPECS/spf.spec; \
	find build/rpmbuild/RPMS -name '*.rpm' -exec cp {} ./ \;; \
	echo "Built RPM package(s) in project root"

package-all: package-deb package-rpm

clean:
	@rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "Cleaned!"

distclean: clean
	@rm -f $(DEPS)

cross-arm:
	@$(MAKE) CC=arm-linux-gnueabihf-gcc CXX=arm-linux-gnueabihf-g++ TARGET=spf-arm

cross-aarch64:
	@$(MAKE) CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++ TARGET=spf-arm64

cross-windows:
	@$(MAKE) CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ TARGET=spf.exe LIBS="-lws2_32 -lssl -lcrypto"

info:
	@echo "SPF Build Info"
	@echo "Platform: $(PLATFORM)"
	@echo "Mode: $(BUILD_MODE)"
	@echo "CC: $(CC)"
	@echo "CXX: $(CXX)"
	@echo "Sources: $(C_SOURCES) $(CXX_SOURCES)"

help:
	@echo "SPF v2.0 - Production Network Forwarder"
	@echo ""
	@echo "Build:"
	@echo "  make           - Build release"
	@echo "  make debug     - Build with sanitizers"
	@echo ""
	@echo "Install:"
	@echo "  make install         - Install to /usr/local/bin"
	@echo "  make install-service - Create systemd service"
	@echo "  make uninstall       - Remove binary"
	@echo ""
	@echo "Deps:"
	@echo "  make check-deps        - Check dependencies"
	@echo "  make install-deps-*    - Install for your distro"
	@echo "  make install-deps-suse - Install deps on openSUSE"
	@echo "  make install-deps-alpine - Install deps on Alpine"
	@echo ""
	@echo "Packaging:"
	@echo "  make package-deb      - Build local .deb package"
	@echo "  make package-rpm      - Build local .rpm package"
	@echo ""
	@echo "Cross:"
	@echo "  make cross-arm      - ARM 32bit"
	@echo "  make cross-aarch64  - ARM 64bit"
	@echo "  make cross-windows  - Windows"

-include $(DEPS)

.DEFAULT_GOAL := all
.SUFFIXES:
.DELETE_ON_ERROR:
