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

// for lack of better name, "serial" is the type of interface exposed by qmi_wwan, and "socket" is the socket exposed by qmuxd.
// TODO check if stuff like indications work

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
	uint16_t payload_len;
} __packed;

struct qmi_svc { // format is common between serial and socket
	uint8_t flags;
	uint16_t transaction;
	uint16_t message;
	uint16_t payload_len;
} __packed;

union qmi_ctl_or_svc {
	struct qmi_ctl ctl;
	struct qmi_svc svc;
};

struct qmuxd_hdr { // from Gobi API struct sQMUXDHeader
	uint32_t len;
	uint32_t qmuxd_client; // qmuxd logs and Harald Welte's structs call this and the above member the "platform header"
	uint32_t message;
	uint32_t qmuxd_client_again;
	uint16_t transaction;
	uint8_t _unused1[2];
	uint32_t sys_err;
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

err_t read_qmuxd_msg(struct qmuxd_hdr *hdr, uint8_t *payload, size_t payload_buf_size);
err_t read_serial_msg(struct serial_hdr *hdr, union qmi_ctl_or_svc *msg, uint8_t *payload, size_t payload_buf_size);

bool_t writeall(int fd, const void *buf, size_t len) ;
bool_t writevall(int fd, const struct iovec *iov, int iovcnt) ;

err_t send_qmuxd_request(struct serial_hdr *serial_hdr, union qmi_ctl_or_svc *msg, uint8_t *msg_payload) {
	uint16_t transaction;
	uint16_t message;
	size_t msg_len;
	uint16_t payload_len;
	uint32_t qmuxd_msg;

#define EXTRACT(unionmember, qmuxdmsg) \
	transaction = msg->unionmember.transaction; \
	message = msg->unionmember.message; \
	msg_len = sizeof(msg->unionmember); \
	payload_len = msg->unionmember.payload_len; \
	qmuxd_msg = qmuxdmsg;

	if (serial_hdr->service == 0) {
		EXTRACT(ctl, QMUXD_MSG_RAW_QMI_CTL);
	} else {
		EXTRACT(svc, QMUXD_MSG_WRITE_QMI_SDU);
	}
#undef EXTRACT

	LOG("[%"PRIu16"]< %"PRIu16" %"PRIu16, transaction, serial_hdr->service, message);

	struct qmuxd_hdr qmuxd_hdr = {
			.len = sizeof(struct qmuxd_hdr) + msg_len + payload_len,
			.message = qmuxd_msg, .transaction = transaction,
			.qmuxd_client = g_qmuxd_client_id, .qmuxd_client_again = g_qmuxd_client_id,
			.service = serial_hdr->service, .qmi_client = serial_hdr->client,
	};

	const struct iovec iov[] = {
			{ .iov_base = &qmuxd_hdr, .iov_len = sizeof(qmuxd_hdr) },
			{ .iov_base = msg, .iov_len = msg_len},
			{ .iov_base = msg_payload, .iov_len = payload_len},
	};

	if (!writevall(g_qmuxd_socket, iov, sizeof(iov)/sizeof(iov[0]))) return errno;

	return 0;
}

err_t handle_qmuxd_response(struct qmuxd_hdr *qmuxd_hdr, const uint8_t *payload) {
	LOG("[%"PRIu16", syserr=%"PRIu32", qmierr=%"PRIu32"]< %"PRIu16" %"PRIu16, qmuxd_hdr->transaction, qmuxd_hdr->service, qmuxd_hdr->message,
		qmuxd_hdr->sys_err, qmuxd_hdr->qmi_err);

	struct serial_hdr serial_hdr = {
		.len = sizeof(serial_hdr) + (qmuxd_hdr->len - sizeof(*qmuxd_hdr)),
		.service = qmuxd_hdr->service, .client = qmuxd_hdr->qmi_client,
		.flags = 0x80 // oFono and GobiNet check for this value without naming it; probably means it's a response
	};

	size_t payload_len = qmuxd_hdr->len - sizeof(*qmuxd_hdr);

	// TODO writev() ?
	uint8_t frame = 1;
	if (!writeall(g_serialfd, &frame, sizeof(frame))) return errno;
	if (!writeall(g_serialfd, &serial_hdr, sizeof(serial_hdr))) return errno;
	if (payload_len) {
		if (!payload) {
			LOG("payload specified but not given");
			return EINVAL;
		}
		if (!writeall(g_serialfd, payload, payload_len)) return errno;
	}

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

void serial_read_loop() {
	for (;;) {
		struct serial_hdr hdr;
		union qmi_ctl_or_svc msg;
		uint8_t payload[MAX_QMI_MSG_SIZE];
		err_t err = read_serial_msg(&hdr, &msg, payload, sizeof(payload));
		if (err) {
			LOG("error reading serial msg: %s", strerr_t(err));
			return;
		}
		if (send_qmuxd_request(&hdr, &msg, payload)) return;
	}
}

void *qmuxd_read_loop(void *_unused __unused) {
	for (;;) {
		struct qmuxd_hdr hdr;
		uint8_t payload[MAX_QMI_MSG_SIZE];
		err_t err = read_qmuxd_msg(&hdr, payload, sizeof(payload));
		if (err) {
			LOG("error reading socket msg: %s", strerr_t(err));
			return NULL;
		}
		// even QMUXD_MSG_RAW_QMI_CTL comes back as an SDU message from service 0
		if (hdr.message == QMUXD_MSG_WRITE_QMI_SDU) {
			if (handle_qmuxd_response(&hdr, payload)) return NULL;
		} else {
			LOG("unknown/unsupported qmuxd message %"PRIu32, hdr.message);
			return NULL;
		}
	}
	return NULL;
}

err_t read_qmuxd_msg(struct qmuxd_hdr *hdr, uint8_t *payload, size_t payload_buf_size) {
	// TODO readv() ?
	if (!readall(g_qmuxd_socket, &hdr->len, sizeof(hdr->len))) return errno;
	if (hdr->len < sizeof(*hdr)) {
		LOG("short length given: %"PRIu32, hdr->len);
		return EINVAL;
	}
	if (!readall(g_qmuxd_socket, &(hdr->len) + 1, sizeof(*hdr) - sizeof(hdr->len))) return errno;
	if (hdr->len > sizeof(*hdr)) {
		if (!payload) {
			LOG("payload given, but no place to store it");
			return EOVERFLOW;
		}
		size_t sz = hdr->len - sizeof(*hdr);
		if (sz > payload_buf_size) {
			LOG("payload too big for buffer");
			return EOVERFLOW;
		}
		if (!readall(g_qmuxd_socket, payload, sz)) return errno;
	}

	return 0;
}

err_t read_serial_msg(struct serial_hdr *hdr, union qmi_ctl_or_svc *msg, uint8_t *payload, size_t payload_buf_size) {
	// TODO readv() ?
	uint8_t frame;
	if (!readall(g_serialfd, &frame, sizeof(frame))) return errno;
	if (frame != 1) {
		LOG("got invalid frame value: %"PRIu8, frame);
		return EINVAL;
	}

	if (!readall(g_serialfd, hdr, sizeof(*hdr))) return errno;
	size_t payload_len;
	if (hdr->service == 0) {
		if (!readall(g_serialfd, &msg->ctl, sizeof(msg->ctl))) return errno;
		payload_len = msg->ctl.payload_len;
	} else {
		if (!readall(g_serialfd, &msg->svc, sizeof(msg->svc))) return errno;
		payload_len = msg->svc.payload_len;
	}

	if (payload_len) {
		if (!payload) {
			LOG("payload given, but no place to store it");
			return EOVERFLOW;
		}
		if (payload_len > payload_buf_size) {
			LOG("payload too big for buffer");
			return EOVERFLOW;
		}
		if (!readall(g_serialfd, payload, payload_len)) return errno;
	}

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
