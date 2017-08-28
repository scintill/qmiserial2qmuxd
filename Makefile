CFLAGS=-std=c99 -Wall -Wextra -Werror
LDFLAGS=-lutil -lpthread

all: qmiserial2socket

qmiserial2socket: qmiserial2socket.o
	$(CC) $(LDFLAGS) qmiserial2socket.o -o $@

clean:
	rm -f qmiserial2socket qmiserial2socket-android qmiserial2socket.o

qmiserial2socket.android:
	$(MAKE) $(MFLAGS) \
		CC=arm-linux-androideabi-gcc \
		CFLAGS="$(CFLAGS) -fPIE"\
		LDFLAGS="-fPIE -pie" \
		qmiserial2socket
