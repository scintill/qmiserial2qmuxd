/*
 * Copyright (C) 2017 Joey Hewitt <joey@joeyhewitt.com>
 *
 * This file is part of qmiserial2qmuxd.
 *
 * qmiserial2qmuxd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * qmiserial2qmuxd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with qmiserial2qmuxd.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedGlobalDeclarationInspection"
*/

#define _POSIX_SOURCE
#define _XOPEN_SOURCE 600
#define _GNU_SOURCE
#define _BSD_SOURCE
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <termio.h>

#ifndef __packed
#define __packed  __attribute__ ((__packed__))
#endif
#ifndef __unused
#define __unused __attribute__ ((__unused__))
#endif
typedef _Bool bool_t;
typedef int err_t;
#define strerr_t(n) strerror(n)

#define LOG(fmt, ...) do { printf("%s: " fmt "\n", __FUNCTION__, ##__VA_ARGS__); } while(0)

struct serial_hdr {
	uint16_t len;
	uint8_t flags;
	uint8_t service;
	uint8_t client;
} __packed;

struct qmi_ctl { // format is common between serial and socket
	uint8_t flags;
	uint8_t transaction;
	uint16_t message;
} __packed;

struct qmi_svc { // format is common between serial and socket
	uint8_t flags;
	uint16_t transaction;
	uint16_t message;
} __packed;

union qmi_ctl_or_svc {
	struct qmi_ctl ctl;
	struct qmi_svc svc;
} __packed;

struct qmuxd_hdr { // from Gobi API struct sQMUXDHeader
	// Gobi API has a comment, "In QMUXD this struct is not packed", so I've downsized some of these members from what
	// Gobi has, according to what I figure the actual size probably is.
	uint16_t len;
	uint8_t _unused4[2];
	uint32_t qmuxd_client; // qmuxd logs and Harald Welte's structs call this and the above member the "platform header"
	uint32_t message;
	uint32_t qmuxd_client_again;
	uint16_t transaction;
	uint8_t _unused1[2];
	int32_t sys_err;
	uint32_t qmi_err; // duplicate of TLV 0x02, per Gobi API
	uint32_t channel; // SMD channel, per Gobi API. TODO make configurable?
	uint8_t service;
	uint8_t _unused2[3];
	uint8_t qmi_client;
	uint8_t flags;
	uint8_t _unused3[2];
} __packed;

enum qmuxd_message_type {
	QMUXD_MSG_RAW_QMI_CTL = 11,
	QMUXD_MSG_WRITE_QMI_SDU = 0,
};

// Gobi and qmuxd have this limit on what they'll send/receive. I'll assume it's a reasonable limit going the other way.
#define MAX_QMI_MSG_SIZE 0x4100

int g_qmuxd_socket;
uint32_t g_qmuxd_client_id;
int g_serialfd;

bool_t writeall(int fd, const void *buf, size_t len) ;
bool_t writevall(int fd, const struct iovec *iov, int iovcnt) ;

err_t send_qmuxd_request(const struct serial_hdr *serial_hdr, const union qmi_ctl_or_svc *msg) {
	uint16_t transaction;
	uint16_t message;
	uint32_t qmuxd_msg;

#define EXTRACT(unionmember, qmuxdmsg) do { \
		transaction = msg->unionmember.transaction; \
		message = msg->unionmember.message; \
		qmuxd_msg = qmuxdmsg; \
	} while(0)

	if (serial_hdr->service == 0) {
		EXTRACT(ctl, QMUXD_MSG_RAW_QMI_CTL);
	} else {
		EXTRACT(svc, QMUXD_MSG_WRITE_QMI_SDU);
	}
#undef EXTRACT

	LOG("[%"PRIu16"]< %"PRIu16" %"PRIu16, transaction, serial_hdr->service, message);

	struct qmuxd_hdr qmuxd_hdr = {
			.len = serial_hdr->len - sizeof(*serial_hdr) + sizeof(qmuxd_hdr),
			.message = qmuxd_msg, .transaction = transaction,
			.qmuxd_client = g_qmuxd_client_id, .qmuxd_client_again = g_qmuxd_client_id,
			.service = serial_hdr->service, .qmi_client = serial_hdr->client,
	};

	const struct iovec iov[] = {
			{ .iov_base = &qmuxd_hdr, .iov_len = sizeof(qmuxd_hdr) },
			{ .iov_base = (void *) msg, .iov_len = qmuxd_hdr.len - sizeof(qmuxd_hdr) },
	};

	if (!writevall(g_qmuxd_socket, iov, sizeof(iov)/sizeof(iov[0]))) return errno;

	return 0;
}

err_t handle_qmuxd_response(const struct qmuxd_hdr *qmuxd_hdr, const void *msg) {
	LOG("[%"PRIu16", syserr=%"PRId32", qmierr=%"PRIu32", length=%zd]< %"PRIu16" %"PRIu16,
		qmuxd_hdr->transaction, qmuxd_hdr->sys_err, qmuxd_hdr->qmi_err, qmuxd_hdr->len - sizeof(qmuxd_hdr),
		qmuxd_hdr->message, qmuxd_hdr->service);

	if (qmuxd_hdr->sys_err != 0) {
		// XXX the message after the qmuxd hdr seems to be a bunch of 00, and I'm not sure of a useful way to pass it on to client.
		// QMI-level errors will be in the TLV data in the message body and will be forwarded below.
		LOG("qmuxd reports syserr; not forwarding to serial");
		//tcflow(g_serialfd, TCIOFF);
		// ^ This causes "QMI framing error detected" in qmicli - it's either sending a character,
		// or maybe qmicli's line mode is set to interpret it as a char.
		return 0;
	}

	struct serial_hdr serial_hdr = {
		.len = qmuxd_hdr->len - sizeof(*qmuxd_hdr) + sizeof(serial_hdr),
		.service = qmuxd_hdr->service, .client = qmuxd_hdr->qmi_client,
		.flags = 0x80 // oFono and GobiNet check for this value without naming it; probably means it's a response
	};

	// TODO writev() ?
	uint8_t frame = 1;
	if (!writeall(g_serialfd, &frame, sizeof(frame))) return errno;
	if (!writeall(g_serialfd, &serial_hdr, sizeof(serial_hdr))) return errno;
	if (!writeall(g_serialfd, msg, serial_hdr.len - sizeof(serial_hdr))) return errno;

	return 0;
}

bool_t readall(int fd, void *buf, size_t len) {
	// TODO loop until len bytes have been read
	ssize_t ret = read(fd, buf, len);
	if (ret < 0) return 0;
	if (((size_t)ret) != len) {
		errno = EAGAIN;
		return 0;
	}
	return 1;
}
bool_t writeall(int fd, const void *buf, size_t len) {
	ssize_t ret = write(fd, buf, len);
	if (ret < 0) return 0;
	if (((size_t)ret) != len) {
		errno = EAGAIN;
		return 0;
	}
	return 1;
}
bool_t writevall(int fd, const struct iovec *iov, int iovcnt) {
	size_t total = 0;
	for (int i = 0; i < iovcnt; i++) {
		total += iov[i].iov_len;
	}
	ssize_t ret = writev(fd, iov, iovcnt);
	if (ret < 0) return 0;
	if (((size_t)ret) != total) {
		errno = EAGAIN;
		return 0;
	}
	return 1;
}

err_t read_msg(int fd, bool_t expect_frame, void *msg, size_t msg_buf_size);

void serial_read_loop() {
	for (;;) {
		union {
			struct serial_hdr hdr;
			uint8_t buf[MAX_QMI_MSG_SIZE];
		} __packed packet;
		err_t err = read_msg(g_serialfd, 1, &packet, sizeof(packet));
		if (err) {
			LOG("error reading serial msg: %s", strerr_t(err));
			exit(1);
		}
		if (send_qmuxd_request(&packet.hdr, (const union qmi_ctl_or_svc *) (&packet.hdr + 1))) exit(1);
	}
}

void *qmuxd_read_loop(void *_unused __unused) {
	for (;;) {
		union {
			struct qmuxd_hdr hdr;
			uint8_t buf[MAX_QMI_MSG_SIZE];
		} __packed packet;
		err_t err = read_msg(g_qmuxd_socket, 0, &packet, sizeof(packet));
		if (err) {
			LOG("error reading qmuxd msg: %s", strerr_t(err));
			exit(1);
		}
		// even QMUXD_MSG_RAW_QMI_CTL comes back as an SDU message from service 0
		if (packet.hdr.message != QMUXD_MSG_WRITE_QMI_SDU) {
			LOG("unknown/unsupported qmuxd message %"PRIu32, packet.hdr.message);
			exit(1);
		}
		if (handle_qmuxd_response(&packet.hdr, &packet.hdr + 1)) exit(1);
	}
	return NULL;
}

// Read data, optionally prefixed by a frame byte (discarded), then by a uint16_t containing the length of the following data + 2
err_t read_msg(int fd, bool_t expect_frame, void *msg, size_t msg_buf_size) {
	if (expect_frame) {
		uint8_t frame;
		if (!readall(fd, &frame, sizeof(frame))) return errno;
		if (frame != 1) {
			LOG("got invalid frame value: %"PRIu8, frame);
			return EINVAL;
		}
	}

	uint16_t *msg_ui16 = msg;
	if (!readall(fd, msg_ui16, sizeof(*msg_ui16))) return errno;
	uint16_t len = *msg_ui16;
	if (len > msg_buf_size) {
		LOG("message too big for buffer");
		return EOVERFLOW;
	}
	if (!readall(fd, &msg_ui16[1], len - sizeof(msg_ui16[0]))) return errno;

	return 0;
}

#define SOCKPATH "/dev/socket/qmux_radio/" // TODO make configurable?

err_t open_qmuxd_socket() {
	int ret;
	ssize_t ret_len;
	err_t err;

	int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) return errno;

	struct sockaddr_un sockaddr = { .sun_family = AF_UNIX };
	snprintf(sockaddr.sun_path, sizeof(sockaddr.sun_path), "%sqmux_client_socket%7lu", SOCKPATH, (unsigned long)getpid());
	unlink(sockaddr.sun_path);
	ret = bind(sockfd, (const struct sockaddr*)&sockaddr, sizeof(sockaddr));
	if (ret < 0) goto close_and_return_errno;

	snprintf(sockaddr.sun_path, sizeof(sockaddr.sun_path), "%sqmux_connect_socket", SOCKPATH);
	ret = connect(sockfd, (const struct sockaddr*)&sockaddr, sizeof(sockaddr));
	if (ret < 0) goto close_and_return_errno;

	ret_len = recv(sockfd, &g_qmuxd_client_id, sizeof(g_qmuxd_client_id), 0);
	if (ret_len != sizeof(g_qmuxd_client_id)) goto close_and_return_errno;

	g_qmuxd_socket = sockfd;

	return 0;

close_and_return_errno:
	err = errno;
	close(sockfd);
	return err;
}

int main(__unused int argc, __unused char *argv[]) {
	err_t err;
	if ((err = open_qmuxd_socket())) {
		LOG("error opening/connecting to qmux: %s", strerr_t(err));
		return 1;
	}

	LOG("connected to qmuxd and received client id %"PRIu32, g_qmuxd_client_id);

	pthread_t socket_read_thread;
	pthread_create(&socket_read_thread, NULL, qmuxd_read_loop, NULL);

	g_serialfd = posix_openpt(O_RDWR | O_NOCTTY);
	if (g_serialfd < 0) {
		LOG("error opening pty: %s", strerror(errno));
		return 1;
	}

	// put pty in raw mode - without this the second request would come in ASCII caret notation, among other issues I'm sure
	struct termios termp;
	if (tcgetattr(g_serialfd, &termp) < 0 || !(cfmakeraw(&termp), 1) || tcsetattr(g_serialfd, TCSANOW, &termp) < 0) {
		LOG("error setting pty to raw mode: %s", strerror(errno));
		return 1;
	}
	/*
	 * XXX
	 * "Note  that  tcsetattr() returns success if any of the requested changes could be successfully carried out.
	 * Therefore, when making multiple changes it may be necessary to follow this call with a further call to tcgetattr()
	 * to check that all changes have been performed successfully." - man page
	 * That looks like a pain, so I'm not doing it for now...
	 */

	if (grantpt(g_serialfd) < 0 || unlockpt(g_serialfd) < 0) {
		LOG("error unlocking pty: %s", strerror(errno));
		return 1;
	}

	char serialdevname[256];
	if (ptsname_r(g_serialfd, serialdevname, sizeof(serialdevname))) {
		LOG("error getting pty name: %s", strerror(errno));
		return 1;
	}
	printf("%s\n", serialdevname);

	open(serialdevname, O_RDONLY); // so we don't get EIO when reading after a program closed it

	serial_read_loop();

	return 0;
}

//#pragma clang diagnostic pop
