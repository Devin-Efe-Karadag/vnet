	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@
	$(CC) $(LDFLAGS) -Wl,--wrap=close -Wl,--wrap=unlink $^ $(LDLIBS) -o $@
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@
	$(BIN)/test_protocol
	$(BIN)/test_cleanup
	$(MAKE) BUILD=build-san BIN=bin-san CFLAGS='-O1 -g -std=c11 -Wall -Wextra -Wpedantic -Werror -Wformat=2 -Wshadow -Wstrict-prototypes -fsanitize=address,undefined -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address,undefined' test
	sudo ./tests/run-integration.sh
	rm -rf build build-san bin bin-san
.SECONDARY:
