#! /bin/sh

set -e

echo "Updating game files"
cd /var/lib/minetest/game/industry_game
git pull origin master
git submodule update
/usr/local/bin/minetestserver --config /etc/minetest/minetest.conf