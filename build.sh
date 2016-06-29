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

rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

export CROSS=mips-linux-gnu-
make PLATFORM=D-MST
mv *.so $BUILD_DIR
make clean

export CROSS=arm-none-linux-gnueabi-
make PLATFORM=H-MST
mv *.so $BUILD_DIR
make clean

export CROSS=arm-none-linux-gnueabi-
make PLATFORM=D
mv *.so $BUILD_DIR
make clean


(cd $BUILD_DIR; tar -czf libdvbapi-v0.2.tar.gz *; mv *.tar.gz ./..;)