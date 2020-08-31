# Copyright (C) 1996-2015 Free Software Foundation, Inc.

#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

CC = clang

CFLAGS := -std=c11 -Oz -s -fvisibility=hidden -Wno-parentheses -Wno-format-security
CFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables  -fmerge-all-constants
LOCAL_CFLAGS = 
DEFS = -DHAVE_CONFIG_H
LOCAL_DEFS = -DSHELL

CCFLAGS = $(DEFS) $(LOCAL_DEFS) $(LOCAL_CFLAGS) $(CFLAGS)
LDFLAGS = -shared -Wl,-soname,$@ -Wl,-icf=all,--gc-sections -flto -Wl,--plugin-opt=O3 -fuse-ld=lld

INC := -Ibash -Ibash/lib -Ibash/builtins -Ibash/include -Ibash/example
LIBS := -ldl

SRCS := $(wildcard *.c)
OUTS := $(SRCS:.c=)

all: $(OUTS)

#bash/Makefile: bash/configure
#	cd bash/ && ./configure
#
#bash/bash: bash/Makefile
#	$(MAKE) -C bash/

%: %.c bash/bash
	$(CC) -fPIC $(CCFLAGS) $(INC) $(LIBS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(OUTS) *.h.gch
	$(MAKE) -C bash/ clean

.PHONY: all clean
