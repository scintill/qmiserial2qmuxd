CFLAGS=-std=c99 -Wall -Wextra -Werror
LDFLAGS=-lutil -lpthread

all: qmiserial2qmuxd

qmiserial2qmuxd: qmiserial2qmuxd.o
	$(CC) $(LDFLAGS) qmiserial2qmuxd.o -o $@

clean:
	rm -f qmiserial2qmuxd qmiserial2qmuxd-android qmiserial2qmuxd.o

qmiserial2qmuxd.android:
	$(MAKE) $(MFLAGS) \
		CC=arm-linux-androideabi-gcc \
		CFLAGS="$(CFLAGS) -fPIE"\
		LDFLAGS="-fPIE -pie" \
		qmiserial2qmuxd
