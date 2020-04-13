#! /bin/sh

set -e

echo "Downloading game files"
cd /usr/local/share/minetest/games/
git clone --recursive https://gitlab.com/nerzhul/minetest_industry industry_game
cd /var/lib/minetest
echo "Launching server"
/usr/local/bin/minetestserver --config /etc/minetest/minetest.conf
