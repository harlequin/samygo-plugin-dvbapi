#!/bin/bash
# Copyright (c) 2016 harlequin
# https://github.com/harlequin/samygo-plugin-dvbapi
#
# This file is part of samygo-plugin-dvbapi.
#
# samygo-plugin-dvbapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
 
BUILD_DIR=".build"
GIT_URL="https://github.com/harlequin/samygo-plugin-dvbapi.git"

function clone2build {
	echo "Building "$1" TARGET"
	mkdir -p $BUILD_DIR"/"$1
	(cd $BUILD_DIR"/"$1;\
	git clone -b $3 --depth 1 $GIT_URL .;\
	CROSS=$2 make;\
	mv#.so "../samygo-plugin-dvbapi-"$3".so";\
	tar -zcvf "../samygo-plugin-dvbapi-"$3".tar.gz" "../samygo-plugin-dvbapi-"$3".so";\
	rm -rf "../samygo-plugin-dvbapi-"$3".so")
}

rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

clone2build samygo-plugin-dvbapi_D-MST mips-linux-gnu- D-MST-v0.1
clone2build samygo-plugin-dvbapi_H-T-MST arm-none-linux-gnueabi- H-MST-v0.1