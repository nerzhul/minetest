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
#include <fcntl.h>
#include <unistd.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include "networksocket.h"

GenericSocket::GenericSocket(SocketProtocol proto, SocketFamily family, u16 port) :
	m_proto(proto),
	m_family(family),
	m_port(port)
{
}

#if defined(__linux__)
static int setnonblock(int fd) {
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags < 0) return flags;
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0) return -1;
	return 0;
}
#endif

static void on_accept(evutil_socket_t fd, short ev, void *arg) {

}

#define CONNECTION_BACKLOG 16

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

	if (bind(sockfd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
		throw SocketException("Failed to bind SocketListenerThread.");
	}

	if (listen(sockfd, CONNECTION_BACKLOG) < 0) {
		throw SocketException("Failed to listen SocketListenerThread.");
	}

	int reuseaddr = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));

	if (setnonblock(sockfd) < 0) {
		throw SocketException("Failed to set socket in non blocking mode.");
	}

	static struct event_base *evbase_accept;

	if ((evbase_accept = event_base_new()) == NULL) {
		close(sockfd);
		throw SocketException("Failed to create libevent base on SocketListenerThread");
	}

	struct event *ev_accept;

	ev_accept = event_new(evbase_accept, sockfd, EV_READ|EV_PERSIST,
			on_accept, nullptr);
			//on_accept, (void *)&workqueue);
	event_add(ev_accept, NULL);

	/* Start the event loop. */
	event_base_dispatch(evbase_accept);

	event_base_free(evbase_accept);
	evbase_accept = NULL;

	close(sockfd);

	return nullptr;
}
