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
#include "networksocket.h"

GenericSocket::GenericSocket(SocketProtocol proto, SocketFamily family, u16 port) :
	m_proto(proto),
	m_family(family),
	m_port(port)
{
}

void SocketListener::listen()
{
	int sockfd;
	struct sockaddr_in serv_addr;

	int sock_family;
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

	sockfd = socket(sock_family, sock_type, sock_proto);
	serv_addr.sin_family = sock_family;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(m_port);
}
