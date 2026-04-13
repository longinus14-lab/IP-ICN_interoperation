APP = gateway
SRCS-y := main.c connection.c http.c tcp.c udp.c ipv4.c l2.c ndn.c ccn.c ccn_builder.c cs.c fib.c pit.c gw_pit.c

CFLAGS += -O3 -Wall -Wextra
CFLAGS += $(shell pkg-config --cflags libdpdk)
LDFLAGS += $(shell pkg-config --libs libdpdk)

$(APP): $(SRCS-y)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(APP)

.PHONY: clean
