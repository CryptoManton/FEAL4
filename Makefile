
export PRAKTROOT=${HOME}/Share
include $(PRAKTROOT)/include/Makefile.Settings

all: attack

clean:
	rm -f attack.o feal4.o fealclient.o attack core

attack.o: attack.c fealclient.h attack.c

attack: attack.o fealclient.o feal4.o
	$(CC) -o attack $(CFLAGS) attack.o fealclient.o feal4.o $(LFLAGS)
