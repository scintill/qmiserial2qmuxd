/*
 * Copyright (C) 2017 Joey Hewitt <joey@joeyhewitt.com>
 *
 * This file is part of qmiserial2socket.
 *
 * qmiserial2socket is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * qmiserial2socket is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with qmiserial2socket.  If not, see <http://www.gnu.org/licenses/>.
 */

// for lack of better name, "serial" is the type of interface exposed by qmi_wwan, and "socket" is the socket exposed by qmuxd.
// the qmuxd transaction id is wider than the serial one, so we pass it through with casting, and don't need to have our own bookkeeping
// TODO probably change names to "serial" and "qmuxd". socket_qmuxd_ is long - on the other hand we need all the help we can get distinguishing "qmux" and "qmuxd"

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

#define freex(p) { free(p); (p) = NULL; }
#define truncate_to(t, i) ((t)(i)) /* marker macro indicating it's expected that we're casting to a smaller type */

#define LOG(fmt, ...) do { printf("%s: " fmt "\n", __FUNCTION__, ##__VA_ARGS__); } while(0)
#define CONST_NAME(c) #c

#define IOV(base, len) { .iov_base = (base), .iov_len = (len) }
#define IOV_IF(cond, base, len) { .iov_base = (base), .iov_len = (cond) ? (len) : 0 }

struct serial_qmux {
	uint16_t len;
	uint8_t flags;
	uint8_t service;
	uint8_t client;
} __packed;

struct serial_qmi_ctl {
	uint8_t flags;
#define serial_qmi_ctl_flag_response 0x01
#define serial_qmi_ctl_flag_indication 0x02
	uint8_t transaction;
	uint16_t message;
	uint16_t payload_len;
} __packed;

struct common_qmi_svc { // format is common between serial and socket
	uint8_t flags;
	uint16_t transaction;
	uint16_t message;
	uint16_t payload_len;
} __packed;

union serial_qmi_ctl_or_svc {
	struct serial_qmi_ctl ctl;
	struct common_qmi_svc svc;
};

struct socket_qmuxd_hdr { // from Gobi API struct sQMUXDHeader
	uint32_t len;
	uint32_t qmuxd_client; // qmuxd logs and Harald Welte's structs call this and the above members the "platform header"
	uint32_t message;
	uint32_t qmuxd_client_again;
	uint32_t transaction;
	uint32_t sys_err;
	uint32_t qmi_err; // duplicate of TLV 0x02, per Gobi API
	uint32_t channel; // SMD channel, per Gobi API. TODO make configurable?
	uint32_t service;
	uint8_t qmi_client;
	uint8_t flags;
	uint8_t _unused[2];
} __packed;

struct socket_qmuxd_qmiclient_alloc_req {
	uint32_t service;
} __packed;

struct socket_qmuxd_qmiclient_alloc_resp {
	uint32_t qmi_client;
	uint8_t service;
} __packed;

struct socket_qmuxd_release_req {
	uint32_t service;
	uint32_t qmi_client;
} __packed;

enum qmuxd_message_type {
	QMUXD_MSG_WRITE_QMI_SDU = 0,
	QMUXD_MSG_ALLOC_QMI_CLIENT_ID = 1,
	QMUXD_MSG_RELEASE_QMI_CLIENT_ID = 2,
};

enum qmi_ctl_message {
	QMI_CTL_GET_CLIENT_ID = 34,
};

int g_qmuxd_socket;
uint32_t g_qmuxd_client_id;
int g_serialfd;

void init_socket_request(struct socket_qmuxd_hdr *req, uint8_t service, uint8_t qmi_client, uint16_t message,
						 uint32_t transaction, uint16_t payload_len);
err_t write_socket_msg(const struct socket_qmuxd_hdr *msg, const struct iovec payloadvec[2]);
err_t read_socket_msg(struct socket_qmuxd_hdr *msg, uint8_t **ppayload);

void init_serial_ctl_response(struct serial_qmi_ctl *ctl, uint16_t message,
							  uint16_t transaction, uint16_t payload_len);
err_t write_serial_ctl_response(struct serial_qmi_ctl *ctl, const uint8_t *payload);
err_t read_serial_msg(struct serial_qmux *qmux, union serial_qmi_ctl_or_svc *msg, uint8_t **payload);

err_t write_serial_svc_response(uint8_t service, uint8_t client, const struct common_qmi_svc *svc, const uint8_t *payload) ;

err_t handle_control_req(struct serial_qmi_ctl *serial_req, const uint8_t *serial_req_payload) {
	LOG("[%"PRIu8"]< %"PRIu16, serial_req->transaction, serial_req->message);
	struct socket_qmuxd_hdr socket_req;

	switch (serial_req->message) {
		case QMI_CTL_GET_CLIENT_ID:
			// check format of request - 1-byte tlv 1
			if (serial_req->payload_len != 4 || serial_req_payload[0] != 1 || serial_req_payload[1] != 1 || serial_req_payload[2] != 0) {
				LOG("unknown client alloc request");
				return EINVAL;
			}
			struct socket_qmuxd_qmiclient_alloc_req alloc_req = { .service = serial_req_payload[3] };
			init_socket_request(&socket_req, 0, 0, QMUXD_MSG_ALLOC_QMI_CLIENT_ID, serial_req->transaction,
								sizeof(alloc_req));
			LOG("requesting client ID for service %"PRIu32, alloc_req.service);
			struct iovec payload[2] = {
				{ .iov_base = &alloc_req, .iov_len = sizeof(alloc_req) },
			};
			return write_socket_msg(&socket_req, payload);
			break;
		default:
			LOG("unknown/unsupported request %"PRIu16, serial_req->message);
			return EINVAL;
	}

	return 0;
}

// XXX endianness portability! needs to be done in general, but this one's more egregious...
#define write_uint16_t(a, o, w) a[(o)++] = (uint8_t) (w); (a)[(o)++] = (uint8_t)((w)>>8)

err_t handle_control_resp(const struct socket_qmuxd_hdr *socket_resp, const void *resp_payload) {
	// TODO check sys_err and qmi_err ?
	LOG("[%"PRIu32"]< %"PRIu32" sys_err=%"PRIu32" qmi_err=%"PRIu32"",
		socket_resp->transaction, socket_resp->message, socket_resp->sys_err, socket_resp->qmi_err);
	struct serial_qmi_ctl serial_resp;
	uint8_t serial_resp_body[12];
	int o = 0;

	switch (socket_resp->message) {
		case QMUXD_MSG_ALLOC_QMI_CLIENT_ID: ;
			const struct socket_qmuxd_qmiclient_alloc_resp *alloc_resp = resp_payload;
			LOG(CONST_NAME(QMUXD_MSG_ALLOC_QMI_CLIENT_ID) ": service=%"PRIu32", client_id=%"PRIu32, alloc_resp->service, alloc_resp->qmi_client);
			// TODO getting 0 as service, maybe that's messing up my qmicli test
			if (!alloc_resp->qmi_client || alloc_resp->qmi_client > UINT8_MAX) {
				// Gobi code treats the client ID as a 32-bit value, but we have to return it as 8-bit, so make sure it fits
				LOG("invalid client ID returned: %"PRIu32, alloc_resp->qmi_client);
				return EINVAL;
			}
			init_serial_ctl_response(&serial_resp, QMI_CTL_GET_CLIENT_ID,
								 truncate_to(uint16_t, socket_resp->transaction), sizeof(serial_resp_body));
			// send 4-byte tlv2 {result, error}, 2-byte tlv1, {service, cid}
			// XXX eww manual tlv. I hope to not need to do it much, but maybe I should do it righter than this...
			serial_resp_body[o++] = 2;
			serial_resp_body[o++] = 4;
			serial_resp_body[o++] = 0;
			serial_resp_body[o++] = 0;
			serial_resp_body[o++] = 0;
			write_uint16_t(serial_resp_body, o, socket_resp->qmi_err);
			serial_resp_body[o++] = 1;
			serial_resp_body[o++] = 2;
			serial_resp_body[o++] = 0;
			serial_resp_body[o++] = alloc_resp->service;
			serial_resp_body[o] = (uint8_t )alloc_resp->qmi_client;
			write_serial_ctl_response(&serial_resp, serial_resp_body);
			break;
		default:
			return EINVAL;
	}

	return 0;
}

err_t handle_service_req(struct serial_qmux *serial_qmux, struct common_qmi_svc *svc, uint8_t *service_payload) {
	LOG("[%"PRIu16"]< %"PRIu16" %"PRIu16, svc->transaction, serial_qmux->service, svc->message);

	struct socket_qmuxd_hdr qmuxd;
	init_socket_request(&qmuxd, serial_qmux->service, serial_qmux->client, QMUXD_MSG_WRITE_QMI_SDU, svc->transaction,
					sizeof(*svc) + svc->payload_len);
	struct iovec payloadvec[2] = {
		{ .iov_base = svc, .iov_len = sizeof(*svc) },
		{ .iov_base = service_payload, .iov_len = svc->payload_len },
	};
	return write_socket_msg(&qmuxd, payloadvec);
}

err_t handle_service_resp(struct socket_qmuxd_hdr *qmuxd, const uint8_t *combined_payload) {
	const struct common_qmi_svc *svc = (const struct common_qmi_svc *)combined_payload;
	const uint8_t *payload = &combined_payload[sizeof(*svc)];
	return write_serial_svc_response(truncate_to(uint8_t, qmuxd->service), qmuxd->qmi_client, svc, payload);
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
		struct serial_qmux qmux;
		union serial_qmi_ctl_or_svc serial_req;
		uint8_t *payload = NULL;
		err_t err = read_serial_msg(&qmux, &serial_req, &payload);
		if (err) {
			LOG("error reading serial msg: %s", strerr_t(err));
			return;
		}
		if (qmux.service == 0) {
			if (handle_control_req(&serial_req.ctl, payload)) {
				freex(payload);
				return;
			}
			freex(payload);
		} else {
			if (handle_service_req(&qmux, &serial_req.svc, payload)) return;
		}
	}
}

void *socket_read_loop(void *arg __unused) {
	for (;;) {
		struct socket_qmuxd_hdr socket_resp;
		uint8_t *payload = NULL;
		err_t err = read_socket_msg(&socket_resp, &payload);
		if (err) {
			LOG("error reading socket msg: %s", strerr_t(err));
			return NULL;
		}
		if (socket_resp.message == QMUXD_MSG_ALLOC_QMI_CLIENT_ID || socket_resp.message == QMUXD_MSG_RELEASE_QMI_CLIENT_ID) {
			if (handle_control_resp(&socket_resp, payload)) {
				freex(payload);
				return NULL;
			}
			freex(payload);
		} else if (socket_resp.message == QMUXD_MSG_WRITE_QMI_SDU) {
			if (handle_service_resp(&socket_resp, payload)) {
				freex(payload);
				return NULL;
			}
			freex(payload);
		} else {
			LOG("unknown/unsupported socket message %"PRIu32, socket_resp.message);
			freex(payload);
		}
	}
	return NULL;
}

void init_socket_request(struct socket_qmuxd_hdr *req, uint8_t service, uint8_t qmi_client, uint16_t message,
						 uint32_t transaction, uint16_t payload_len) {
	memset(req, 0, sizeof(*req));
	req->len = sizeof(struct socket_qmuxd_hdr) + payload_len;
	req->qmuxd_client = req->qmuxd_client_again = g_qmuxd_client_id;
	req->service = service;
	req->qmi_client = qmi_client;
	req->transaction = transaction;
	req->message = message;
}

err_t write_socket_msg(const struct socket_qmuxd_hdr *msg, const struct iovec payloadvec[static 2]) {
	static const uint32_t minsz = 944; /* XXX this is size that my phone's qmuxd requires at minimum - why? is it different on other devices? */
	// TODO verify it's actually needed, after I sorted the split write() situation
	// TODO verify it's specific to control messages
	static const uint8_t padbuf[944] = {0};

	LOG("[%"PRIu32"]>: %"PRIu32, msg->transaction, msg->message);

	if (msg->len < sizeof(*msg)) {
		LOG("invalid length %"PRIu32, msg->len);
		return EINVAL;
	}

	// qmuxd throws an error if we do individual write() calls.
	bool_t pad = (msg->message == QMUXD_MSG_ALLOC_QMI_CLIENT_ID && msg->len < minsz);
	uint32_t length = !pad ? msg->len : minsz;
	const struct iovec iov[] = {
		IOV( (void*)&length, sizeof(length) ),
		IOV( (void*)&msg->qmuxd_client, sizeof(*msg) - sizeof(msg->len) ),
		payloadvec[0],
		payloadvec[1],
		IOV_IF(pad, (void*)padbuf, minsz - msg->len),
	};

	if (!writevall(g_qmuxd_socket, iov, sizeof(iov)/sizeof(iov[0]))) return errno;

	return 0;
}

err_t read_socket_msg(struct socket_qmuxd_hdr *msg, uint8_t **ppayload) {
	if (!readall(g_qmuxd_socket, &msg->len, sizeof(msg->len))) return errno;
	if (msg->len < sizeof(*msg)) {
		LOG("short length given: %"PRIu32, msg->len);
		return EINVAL;
	}
	if (!readall(g_qmuxd_socket, &(msg->len) + 1, sizeof(*msg) - sizeof(msg->len))) return errno;
	if (msg->len > sizeof(*msg)) {
		if (!ppayload) {
			LOG("payload given, but no place to store it");
			return EOVERFLOW;
		}
		size_t sz = msg->len - sizeof(*msg);
		LOG("reading payload of size %zu", sz);
		*ppayload = malloc(sz);
		if (!readall(g_qmuxd_socket, *ppayload, sz)) {
			err_t err = errno;
			freex(*ppayload);
			return err;
		}
	} else {
		if (ppayload) *ppayload = NULL;
	}

	return 0;
}

void init_serial_ctl_response(struct serial_qmi_ctl *ctl, uint16_t message,
						  uint16_t transaction, uint16_t payload_len) {
	memset(ctl, 0, sizeof(*ctl));
	ctl->message = message;
	ctl->transaction = truncate_to(uint8_t, transaction); // we're giving them their same ID back, which was only 8-bit
	ctl->flags = serial_qmi_ctl_flag_response;
	ctl->payload_len = payload_len;
}

err_t write_serial_response_impl(struct serial_qmux *qmux, union serial_qmi_ctl_or_svc *msg, const uint8_t *payload, size_t payload_len) {
	// TODO writev() in one?
	uint8_t frame = 1;
	if (!writeall(g_serialfd, &frame, sizeof(frame))) return errno;
	if (!writeall(g_serialfd, qmux, sizeof(*qmux))) return errno;
	if (!writeall(g_serialfd, msg, qmux->len - sizeof(*qmux) - payload_len)) return errno;
	if (payload_len) {
		if (!payload) {
			LOG("payload specified but not given");
			return EINVAL;
		}
		if (!writeall(g_serialfd, payload, payload_len)) return errno;
	}

	return 0;
}

err_t write_serial_ctl_response(struct serial_qmi_ctl *ctl, const uint8_t *payload) {
	LOG("[%"PRIu16"]:> %"PRIu16, ctl->transaction, ctl->message);

	struct serial_qmux qmux = {
		.len = sizeof(struct serial_qmux) + sizeof(struct serial_qmi_ctl) + ctl->payload_len,
	};
	return write_serial_response_impl(&qmux, (union serial_qmi_ctl_or_svc *) ctl, payload, ctl->payload_len);
}

err_t write_serial_svc_response(uint8_t service, uint8_t client, const struct common_qmi_svc *svc, const uint8_t *payload) {
	LOG("[%"PRIu16"]:> %"PRIu16, svc->transaction, svc->message);

	struct serial_qmux qmux = {
		.len = sizeof(struct serial_qmux) + sizeof(struct common_qmi_svc) + svc->payload_len,
		.service = service, .client = client,
		.flags = 0x80 // XXX oFono's code seems to check for this, but I don't know what it means
	};
	return write_serial_response_impl(&qmux, (union serial_qmi_ctl_or_svc *) svc, payload, svc->payload_len);
}

err_t read_serial_msg(struct serial_qmux *qmux, union serial_qmi_ctl_or_svc *msg, uint8_t **payload) {
	uint8_t frame;
	if (!readall(g_serialfd, &frame, sizeof(frame))) return errno;
	if (frame != 1) {
		LOG("got invalid frame value: %"PRIu8, frame);
		return EINVAL;
	}

	if (!readall(g_serialfd, qmux, sizeof(*qmux))) return errno;
	size_t payload_len;
	if (qmux->service == 0) {
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
		LOG("reading payload of size %zu", payload_len);
		*payload = malloc(payload_len);
		if (!readall(g_serialfd, *payload, payload_len)) {
			err_t err = errno;
			freex(*payload);
			return err;
		}
	} else {
		if (payload) *payload = NULL;
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
	pthread_create(&socket_read_thread, NULL, socket_read_loop, NULL);

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

	//kill(getppid(), SIGUSR1);

	serial_read_loop();

	return 0;
}

//#pragma clang diagnostic pop
