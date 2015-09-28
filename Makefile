src = $(wildcard *.c)
obj = $(src:.c=.o)

LDFLAGS = -lz -lcrypto

bitflipper: $(obj)
	    $(CC) -O3 -Wall -Werror -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(obj) bitflipper
