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
#include "networksocket.h"

GenericSocket::GenericSocket(SocketProtocol proto, SocketFamily family, u16 port) :
	m_proto(proto),
	m_family(family),
	m_port(port)
{
}

class Session
{
public:
	Session() {}
	~Session() {}
};

static void on_read_callback(struct bufferevent *bev, void *arg)
{

}

static void on_accept(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *ctx)
{
	/* We got a new connection! Set up a bufferevent for it. */
	struct event_base *base = evconnlistener_get_base(listener);
	struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

	bufferevent_setcb(bev, on_read_callback, NULL, NULL, new Session());

	bufferevent_enable(bev, EV_READ | EV_WRITE);
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
		default: FATAL_ERROR("Invalid socket type"); break;
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

	struct event_base *evbase_accept;
	if (!(evbase_accept = event_base_new())) {
		close(sockfd);
		throw SocketException("Failed to create libevent base on SocketListenerThread");
	}

	evconnlistener *listener = evconnlistener_new_bind(evbase_accept, on_accept, NULL,
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
		(struct sockaddr *) &listen_addr, sizeof(listen_addr));

	if (!listener) {
		event_base_free(evbase_accept);
		throw SocketException("Failed to create libevent listener");
	}

	evconnlistener_set_error_cb(listener, accept_error_cb);

	/* Lets rock */
	event_base_dispatch(evbase_accept);
	event_base_free(evbase_accept);

	return nullptr;
}
