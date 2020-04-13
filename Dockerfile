FROM alpine:3.11

COPY .git /usr/src/minetest/.git
COPY CMakeLists.txt /usr/src/minetest/CMakeLists.txt
COPY README.md /usr/src/minetest/README.md
COPY minetest.conf.example /usr/src/minetest/minetest.conf.example
COPY builtin /usr/src/minetest/builtin
COPY cmake /usr/src/minetest/cmake
COPY doc /usr/src/minetest/doc
COPY fonts /usr/src/minetest/fonts
COPY lib /usr/src/minetest/lib
COPY misc /usr/src/minetest/misc
COPY po /usr/src/minetest/po
COPY src /usr/src/minetest/src
COPY textures /usr/src/minetest/textures

WORKDIR /usr/src/minetest

RUN apk add --no-cache git build-base irrlicht-dev cmake bzip2-dev libpng-dev \
		jpeg-dev libxxf86vm-dev mesa-dev sqlite-dev libogg-dev \
		libvorbis-dev openal-soft-dev curl-dev freetype-dev zlib-dev \
		gmp-dev jsoncpp-dev postgresql-dev ca-certificates && \
	mkdir build && \
	cd build && \
	cmake .. \
		-DCMAKE_INSTALL_PREFIX=/usr/local \
		-DCMAKE_BUILD_TYPE=Release \
		-DBUILD_SERVER=TRUE \
		-DBUILD_UNITTESTS=FALSE \
		-DBUILD_CLIENT=FALSE && \
	make -j2 && \
	make install

FROM alpine:3.11

COPY util/entrypoint.sh /entrypoint.sh

RUN apk add --no-cache sqlite-libs curl gmp libstdc++ libgcc libpq git && \
	adduser -D minetest --uid 30000 -h /var/lib/minetest && \
	mkdir -p /usr/local/share/minetest/games && \
	chown -R minetest:minetest /var/lib/minetest /usr/local/share/minetest/games && \
	chmod +x /entrypoint.sh

WORKDIR /var/lib/minetest

COPY --from=0 /usr/local/share/minetest /usr/local/share/minetest
COPY --from=0 /usr/local/bin/minetestserver /usr/local/bin/minetestserver
COPY --from=0 /usr/local/share/doc/minetest/minetest.conf.example /etc/minetest/minetest.conf

USER minetest:minetest

EXPOSE 30000/udp

CMD ["/entrypoint.sh"]
