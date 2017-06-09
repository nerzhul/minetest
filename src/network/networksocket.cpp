/*
Minetest
Copyright (C) 2017 nerzhul, Loic Blot <loic.blot@unix-experience.fr>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <sys/socket.h>
#include <netinet/in.h>
#include <debug.h>
#include <socket.h>
#include <unistd.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <sstream>
#include <functional>
#include "networksocket.h"
#include "util/serialize.h"
#include "networkpacket.h"

GenericSocket::GenericSocket(SocketProtocol proto, SocketFamily family, u16 port) :
	m_proto(proto),
	m_family(family),
	m_port(port)
{
}

#define MAX_VALID_PACKET_SIZE 10 * 1024 * 1024

class NetworkSessionMgr;

class NetworkSession
{
	friend class NetworkSessionMgr;
public:
	enum State: u8 {
		NETSESSION_STATE_OK,
		NETSESSION_STATE_READ_ERROR,
		NETSESSION_STATE_READ_ERROR_PKT_SIZE,
		NETSESSION_STATE_WAITING_DATA,
	};
	u64 get_session_id() const { return m_session_id; }

	NetworkSession::State push_recv_data(const u8 *data, size_t len)
	{
		size_t data_len = len;
		const u8 *data_ptr = data;

		/*
		 * m_packet_size <= 0: previous read was complete
		 *
		 * Read new packet size
		 */
		if (m_packet_size <= 0) {
			if (!read_size_header(data, len)) {
				return NETSESSION_STATE_READ_ERROR;
			}

			if (m_packet_size > MAX_VALID_PACKET_SIZE) {
				return NETSESSION_STATE_READ_ERROR_PKT_SIZE;
			}

			data_len = len - sizeof(int);
			if (!data_len) {
				return NETSESSION_STATE_WAITING_DATA;
			}

			data_ptr = &data[sizeof(int)];
		}

		m_recv_buf.resize(m_recv_buf.size() + data_len);
		memcpy(&m_recv_buf[m_recv_buf_offset], data_ptr, data_len);
		m_recv_buf_offset += data_len;

		return NETSESSION_STATE_OK;
	}

private:
	NetworkSession(u64 session_id, evutil_socket_t fd) :
		m_session_id(session_id),
		m_fd(fd)
	{}

	~NetworkSession() {}

	bool read_size_header(const u8 *data, size_t len)
	{
		if (len < sizeof(int)) {
			return false;
		}

		m_packet_size = readU32(data);
		return m_packet_size >= 0;
	}

	const u64 m_session_id = 0;
	std::vector<u8> m_recv_buf = {};
	u64 m_recv_buf_offset = 0;
	s32 m_packet_size = -1;
	evutil_socket_t m_fd;

	NetworkSession::State m_state = NETSESSION_STATE_OK;
};

class NetworkSessionMgr
{
public:
	NetworkSessionMgr() {}
	~NetworkSessionMgr() {}

	NetworkSession *create_new_session(evutil_socket_t fd)
	{
		NetworkSession *sess = new NetworkSession(m_new_session_next_id, fd);

		std::unique_lock<std::mutex> m_lock(m_mutex);
		m_sessions[m_new_session_next_id] = sess;
		m_new_session_next_id++;
		return sess;
	}

	void drop_session(NetworkSession *sess)
	{
		std::unique_lock<std::mutex> m_lock(m_mutex);

		m_sessions.erase(sess->get_session_id());
		// TODO: Send event to Server
		delete sess;
	}
private:
	std::unordered_map<u64, NetworkSession *> m_sessions = {};
	u64 m_new_session_next_id = 1;
	std::mutex m_mutex;
};

static NetworkSessionMgr sessionMgr;

static void on_read_callback(struct bufferevent *bev, void *ctx)
{
	u8 buf[4096];
	NetworkSession *sess = (NetworkSession *) ctx;

	// Move that to network session
	size_t rd_len = bufferevent_read(bev, buf, sizeof(buf));
	std::cout << "Read data: " << rd_len
			<< " for session " << sess->get_session_id() << std::endl;
	sess->push_recv_data(buf, rd_len);
}


static void on_event_callback(struct bufferevent *bev, short events, void *ctx)
{
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
		NetworkSession *sess = (NetworkSession *)ctx;
		std::cout << "Connection terminated for session " << sess->get_session_id() << std::endl;
		sessionMgr.drop_session(sess);
	}

	bufferevent_free(bev);
}

static void accept_error_cb(struct evconnlistener *listener, void *ctx)
{
	struct event_base *base = evconnlistener_get_base(listener);
	int err = EVUTIL_SOCKET_ERROR();
	std::stringstream ss;
	ss << "Got an error " << err << " (" << evutil_socket_error_to_string(err)
		<< ") on the SocketListenerThread." << std::endl;
	event_base_loopexit(base, NULL);
	throw SocketException(ss.str());
}

void SocketListenerThread::on_accept(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *ctx)
{
	/* We got a new connection! Set up a bufferevent for it. */
	struct event_base *base = evconnlistener_get_base(listener);
	struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

	bufferevent_setcb(bev, on_read_callback, NULL, on_event_callback,
		sessionMgr.create_new_session(fd));

	bufferevent_enable(bev, EV_READ | EV_WRITE);
}

void *SocketListenerThread::run()
{
	struct sockaddr_in listen_addr;

	sa_family_t sock_family;
	switch (m_family) {
		case SOCK_FAMILY_IPV4: sock_family = AF_INET; break;
		case SOCK_FAMILY_IPV6: sock_family = AF_INET6; break;
		default: FATAL_ERROR("Invalid socket family");
	}

	int sock_type, sock_proto;
	switch (m_proto) {
		case PROTOCOL_TCP:
			sock_type = SOCK_STREAM;
			sock_proto = IPPROTO_TCP;
			break;
		case PROTOCOL_UDP:
			sock_type = SOCK_DGRAM;
			sock_proto = IPPROTO_UDP;
			break;
		default: FATAL_ERROR("Invalid socket type");
	}

	int sockfd = socket(sock_family, sock_type, sock_proto);
	if (sockfd < 0) {
		throw SocketException("Failed to create socket on SocketListenerThread.");
	}

	memset(&listen_addr, 0, sizeof(listen_addr));
	listen_addr.sin_family = sock_family;
	listen_addr.sin_addr.s_addr = INADDR_ANY;
	listen_addr.sin_port = htons(m_port);

	setName("SocketListenerThread (0.0.0.0:" + std::to_string(m_port) + ")");

	std::unique_ptr<event_base, decltype(&event_base_free)>
		evbase_accept(event_base_new(), &event_base_free);
	if (!evbase_accept.get()) {
		close(sockfd);
		throw SocketException("Failed to create libevent base on SocketListenerThread");
	}

	evconnlistener *listener = evconnlistener_new_bind(evbase_accept.get(),
		&SocketListenerThread::on_accept, NULL,
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
		(struct sockaddr *) &listen_addr, sizeof(listen_addr));

	if (!listener) {
		throw SocketException("Failed to create libevent listener");
	}

	evconnlistener_set_error_cb(listener, accept_error_cb);

	/* Lets rock */
	event_base_dispatch(evbase_accept.get());

	return nullptr;
}
