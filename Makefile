CC ?= cc
PKGS = libsodium libmnl
CPPFLAGS += -D_GNU_SOURCE -Iinclude $(shell pkg-config --cflags $(PKGS))
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror -Wformat=2 -Wshadow -Wstrict-prototypes
LDLIBS += $(shell pkg-config --libs $(PKGS))
BUILD ?= build
BIN ?= bin
COMMON = protocol crypto util config peer_table mac_table
OBJ = $(addprefix $(BUILD)/,$(addsuffix .o,$(COMMON)))
PROGRAMS = vnet-switch vnet-client vnet-keygen test_protocol test_malformed_packets test_overlay test_proxy test_namespace test_cleanup
all: $(addprefix $(BIN)/,$(PROGRAMS))
$(BUILD) $(BIN):
	mkdir -p $@
$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@
$(BUILD)/test_%.o: tests/test_%.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@
$(BIN)/vnet-switch: $(BUILD)/switch.o $(OBJ) | $(BIN)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@
$(BIN)/vnet-client: $(BUILD)/client.o $(BUILD)/tap.o $(BUILD)/netlink.o $(OBJ) | $(BIN)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@
$(BIN)/vnet-keygen: $(BUILD)/keygen.o $(OBJ) | $(BIN)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@
$(BIN)/test_cleanup: $(BUILD)/test_cleanup.o $(OBJ) | $(BIN)
	$(CC) $(LDFLAGS) -Wl,--wrap=close -Wl,--wrap=unlink $^ $(LDLIBS) -o $@
$(BIN)/test_%: $(BUILD)/test_%.o $(OBJ) | $(BIN)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@
test: all
	$(BIN)/test_protocol
	$(BIN)/test_malformed_packets
	$(BIN)/test_cleanup
sanitize:
	$(MAKE) BUILD=build-san BIN=bin-san CFLAGS='-O1 -g -std=c11 -Wall -Wextra -Wpedantic -Werror -Wformat=2 -Wshadow -Wstrict-prototypes -fsanitize=address,undefined -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address,undefined' test
integration: all
	sudo ./tests/run-integration.sh
clean:
	rm -rf build build-san bin bin-san
-include $(wildcard $(BUILD)/*.d)
.SECONDARY:
.PHONY: all test sanitize integration clean
