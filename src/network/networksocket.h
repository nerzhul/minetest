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

#pragma once

#include <event2/util.h>
#include "threading/thread.h"
#include "irrlichttypes.h"

enum SocketProtocol : u8
{
	PROTOCOL_TCP,
	PROTOCOL_UDP,
};

enum SocketFamily : u8
{
	SOCK_FAMILY_IPV4,
	SOCK_FAMILY_IPV6,
};

class GenericSocket
{
public:
	GenericSocket(SocketProtocol proto, SocketFamily family, u16 port = 0);
protected:
	SocketProtocol m_proto;
	SocketFamily m_family;
	u16 m_port = 0;
};

class SocketListenerThread : private GenericSocket, public Thread
{
public:
	SocketListenerThread(SocketProtocol proto, SocketFamily family, u16 port) :
		GenericSocket(proto, family, port),
		Thread()
	{}

	void *run();

private:
	static void on_accept(struct evconnlistener *listener, evutil_socket_t fd,
		struct sockaddr *address, int socklen, void *ctx);
};
