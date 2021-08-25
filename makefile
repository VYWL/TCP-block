LDLIBS=-lpcap

all: tcp-block

tcp-block: main.o functions.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -g -o  $@

clean:
	rm -f tcp-block *.o
