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

CFLAGS = -O2 -Wno-parentheses -Wno-format-security
LOCAL_CFLAGS = 
DEFS = -DHAVE_CONFIG_H
LOCAL_DEFS = -DSHELL

CCFLAGS = $(DEFS) $(LOCAL_DEFS) $(LOCAL_CFLAGS) $(CFLAGS)
LDFLAGS = -shared -Wl,-soname,$@ 

INC := -Ibash -Ibash/lib -Ibash/builtins -Ibash/include -Ibash/example

SRCS := $(wildcard *.c)
OUTS := $(SRCS:.c=)

all: $(OUTS)

bash/config.h: bash/configure
	cd bash/ && ./configure

build_bash:
	$(MAKE) -C bash/

%: %.c bash/config.h build_bash loadables.h.gch
	$(CC) -fPIC $(CCFLAGS) $(INC) $(LDFLAGS) -o $@ $<

# Persudo recipe for vim linting
loadables.h.gch: loadables.h
	$(CC) $(CCFLAGS) $(INC) $<

clean:
	rm -f $(OUTS) *.h.gch
	$(MAKE) -C bash/ clean

.PHONY: all clean build_bash
