APPS = 

DRIVERS = driver/dummy.o \
		  driver/loopback.o \

OBJS = util.o \
		net.o \
		 ip.o \
	   icmp.o \
	  ether.o \
	    arp.o \

TESTS = $(patsubst %.c, %.exe, $(shell find . -type f -name "step*.c"))

CFLAGS := $(CFLAGS) -g -W -Wall -Wno-unused-parameter -iquote .

ifeq ($(shell uname),Linux)
  # Linux specific settings
  BASE = platform/linux
  CFLAGS := $(CFLAGS) -pthread -iquote $(BASE)
  LDFLAGS := $(LDFLAGS)	-lrt
  DRIVERS := $(DRIVERS) $(BASE)/driver/ether_tap.o
  OBJS := $(OBJS) $(BASE)/intr.o
endif

ifeq ($(shell uname),Darwin)
  # macOS specific settings
endif

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(APPS) $(TESTS)

$(APPS): %.exe : %.o $(OBJS) $(DRIVERS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TESTS): %.exe : %.o $(OBJS) $(DRIVERS) test/test.h
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(APPS) $(APPS:.exe=.o) $(OBJS) $(DRIVERS) $(TESTS) $(TESTS:.exe=.o)

.PHONY: tap_setup
tap_setup:
	sudo ip tuntap add mode tap user $(USER) name tap0
	sudo ip addr add 192.0.2.1/24 dev tap0
	sudo ip link set tap0 up

.PHONY: ip_nat_setup
ip_nat_setup:
	sudo bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
	sudo iptables -A FORWARD -o tap0 -j ACCEPT
	sudo iptables -A FORWARD -i tap0 -j ACCEPT
	sudo iptables -t nat -A POSTROUTING -s 192.0.2.0/24 -o eth0 -j MASQUERADE

.PHONY: setup
setup:
	tap_setup
	ip_nat_setup
