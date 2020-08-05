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
CFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables 
LOCAL_CFLAGS = 
DEFS = -DHAVE_CONFIG_H
LOCAL_DEFS = -DSHELL

CCFLAGS = $(DEFS) $(LOCAL_DEFS) $(LOCAL_CFLAGS) $(CFLAGS)
LDFLAGS = -shared -Wl,-soname,$@ -Wl,-icf=all

INC := -Ibash -Ibash/lib -Ibash/builtins -Ibash/include -Ibash/example

SRCS := $(wildcard *.c)
OUTS := $(SRCS:.c=)

all: $(OUTS)

bash/config.h: bash/configure
	cd bash/ && ./configure

%: %.c bash/config.h loadables.h.gch
	$(MAKE) -C bash/
	$(CC) -fPIC $(CCFLAGS) $(INC) $(LDFLAGS) -o $@ $<

# Persudo recipe for vim linting
loadables.h.gch: loadables.h
	$(MAKE) -C bash/
	$(CC) $(CCFLAGS) $(INC) $<

elean:
	rm -f $(OUTS) *.h.gch
	$(MAKE) -C bash/ clean

.PHONY: all clean
