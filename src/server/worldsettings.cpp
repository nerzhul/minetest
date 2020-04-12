/*
Minetest
Copyright (C) 2010-2013 celeron55, Perttu Ahola <celeron55@gmail.com>
Copyright (C) 2013-2020 Minetest core developers & community

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

#include "worldsettings.h"
#include "filesys.h"

#define BACKEND_KEY "backend"
#define DEFAULT_BACKEND "sqlite3"
#define READONLY_BACKEND_KEY "readonly_backend"

#if USE_REDIS
#define REDIS_ADDR_KEY "redis_address"
#define REDIS_HASH_KEY "redis_hash"
#define REDIS_PASSWORD_KEY "redis_password"
#define REDIS_PORT_KEY "redis_port"
#endif
#if USE_POSTGRESQL
#define PGSQL_CONN_KEY "pgsql_connection"
#endif

WorldSettings::WorldSettings(const std::string &savedir) :
    m_conf_path(savedir + DIR_DELIM + "world.mt"),
    m_savedir(savedir)
{
}

bool WorldSettings::load(bool return_on_config_read)
{
    bool succeeded = readConfigFile(m_conf_path.c_str());
    // Now read env vars
    if (const char *world_backend = std::getenv("WORLD_BACKEND"))
        set(BACKEND_KEY, std::string(world_backend));

    if (const char *readonly_backend = std::getenv("WORLD_READONLY_BACKEND"))
        set(READONLY_BACKEND_KEY, std::string(readonly_backend));

#if USE_REDIS
    if (const char *redis_addr = std::getenv("WORLD_REDIS_ADDRESS"))
        set(REDIS_ADDR_KEY, std::string(redis_addr));
        
    if (const char *redis_hash = std::getenv("WORLD_REDIS_HASH"))
        set(REDIS_HASH_KEY, std::string(redis_hash));

    if (const char *redis_password = std::getenv("WORLD_REDIS_PASSWORD"))
        set(REDIS_PASSWORD_KEY, std::string(redis_password));

    if (const char *redis_port = std::getenv("WORLD_REDIS_PORT")) {
        setU16(REDIS_PORT_KEY, std::atoi(redis_port));
    }
#endif

#if USE_POSTGRESQL
    if (const char *pgsql_conn_str = std::getenv("WORLD_POSTGRESQL_CONNECTION"))
        set(PGSQL_CONN_KEY, std::string(pgsql_conn_str));
#endif

    if (return_on_config_read) {
        return succeeded;
    }

	if (!succeeded || !exists(BACKEND_KEY)) {
		// fall back to sqlite3
		set(BACKEND_KEY, DEFAULT_BACKEND);
	}

	m_backend = get(BACKEND_KEY);

    if (exists(READONLY_BACKEND_KEY)) {
        m_readonly_backend = get(READONLY_BACKEND_KEY);
    }

    return true;
}

std::string WorldSettings::getReadOnlyDir() const 
{
    return m_savedir + DIR_DELIM + "readonly";
}

#if USE_POSTGRESQL
std::string WorldSettings::getPostgreSQLConnectionString() const
{
    std::string connection_string;
    getNoEx(PGSQL_CONN_KEY, connection_string);
    return connection_string;
}
#endif