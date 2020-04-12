FROM alpine:3.11

ENV MINETEST_GAME_VERSION master
ENV MOD_AWARD_VERSION ce58720493a70b3eff28b6a9f1afe1ebaee56a46
ENV MOD_MOREORES_VERSION e3d8f88e9cbfe2582056ec6987cff005e3e5c379
ENV MOD_MOREBLOCKS_VERSION 6f9b787f3e2badbb4646c19b37db9ba4b0546cf8
ENV MOD_3DARMOR_VERSION 47ecef46f75c977a3d256ac4bab2874c24b785af
ENV MOD_ITEMDROP_VERSION 8ef6ba3c0ffdeb47c20d7610680a1be152588827
ENV MOD_FACTORY_VERSION 51d5025a8fc7fcc5d2936db3ae50bdf5f19fdd3f

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
		gmp-dev jsoncpp-dev postgresql-dev && \
	git clone --depth=1 -b ${MINETEST_GAME_VERSION} https://github.com/minetest/minetest_game.git ./games/industry_game && \

	git clone https://gitlab.com/rubenwardy/awards.git ./games/industry_game/mods/awards && \
	cd ./games/industry_game/mods/awards && git checkout ${MOD_AWARD_VERSION} && cd - && \

	git clone https://github.com/minetest-mods/moreores.git ./games/industry_game/mods/moreores && \
	cd ./games/industry_game/mods/moreores && git checkout ${MOD_MOREORES_VERSION} && cd - && \

	git clone https://github.com/minetest-mods/moreblocks.git ./games/industry_game/mods/moreblocks && \
	cd ./games/industry_game/mods/moreblocks && git checkout ${MOD_MOREBLOCKS_VERSION} && cd - && \

	git clone https://github.com/stujones11/minetest-3d_armor.git ./games/industry_game/mods/3d_armor && \
	cd ./games/industry_game/mods/3d_armor && git checkout ${MOD_3DARMOR_VERSION} && cd - && \

	git clone https://github.com/minetest-mods/item_drop.git ./games/industry_game/mods/item_drop && \
	cd ./games/industry_game/mods/item_drop && git checkout ${MOD_ITEMDROP_VERSION} && cd - && \

	git clone --recursive https://github.com/theFox6/factory.git ./games/industry_game/mods/factory && \
	cd ./games/industry_game/mods/factory && git checkout ${MOD_FACTORY_VERSION} && cd - && \

	rm -fr ./games/industry_game/.git ./games/industry_game/mods/*/.git && \
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

RUN apk add --no-cache sqlite-libs curl gmp libstdc++ libgcc libpq && \
	adduser -D minetest --uid 30000 -h /var/lib/minetest && \
	chown -R minetest:minetest /var/lib/minetest

WORKDIR /var/lib/minetest

COPY --from=0 /usr/local/share/minetest /usr/local/share/minetest
COPY --from=0 /usr/src/minetest/games/industry_game /usr/local/share/minetest/games/industry_game
COPY --from=0 /usr/local/bin/minetestserver /usr/local/bin/minetestserver
COPY --from=0 /usr/local/share/doc/minetest/minetest.conf.example /etc/minetest/minetest.conf

USER minetest:minetest

EXPOSE 30000/udp

CMD ["/usr/local/bin/minetestserver", "--config", "/etc/minetest/minetest.conf"]
