# tunl - IPv6-first self-hosting toolkit
# SPDX-License-Identifier: GPL-2.0

CC := gcc
CXX := g++

SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
OBJ_DIR := $(BUILD_DIR)/obj

TARGET := tunl

SOURCES := core.c config.c tls.c health.c dns.c acme.c check.c tui.c
OBJECTS := $(SOURCES:%.c=$(OBJ_DIR)/%.o)
OBJECTS += $(OBJ_DIR)/server.o

CFLAGS := -Wall -Wextra -std=c11 -Os -MMD -MP
CXXFLAGS := -Wall -Wextra -std=c++11 -Os -MMD -MP
LDFLAGS := 
LIBS := -lssl -lcrypto -lpthread

.PHONY: all clean

all: $(BIN_DIR)/$(TARGET)
	@echo "Build complete"
	@ls -lh $(BIN_DIR)/$(TARGET)

$(BIN_DIR)/$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS) $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/server.o: $(SRC_DIR)/server.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

-include $(OBJECTS:.o=.d)
