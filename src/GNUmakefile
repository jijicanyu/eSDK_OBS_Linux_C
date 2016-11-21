# GNUmakefile
# 
# Copyright 2008 Bryan Ischo <bryan@ischo.com>
# 
# This file is part of libeSDKOBSS3.
# 
# libeSDKOBSS3 is free software: you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, version 3 of the License.
#
# In addition, as a special exception, the copyright holders give
# permission to link the code of this library and its programs with the
# OpenSSL library, and distribute linked combinations including the two.
#
# libeSDKOBSS3 is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# version 3 along with libeSDKOBSS3, in a file named COPYING.  If not, see
# <http://www.gnu.org/licenses/>.

# I tried to use the autoconf/automake/autolocal/etc (i.e. autohell) tools
# but I just couldn't stomach them.  Since this is a Makefile for POSIX
# systems, I will simply do away with autohell completely and use a GNU
# Makefile.  GNU make ought to be available pretty much everywhere, so I
# don't see this being a significant issue for portability.

# All commands assume a GNU compiler.  For systems which do not use a GNU
# compiler, write scripts with the same names as these commands, and taking
# the same arguments, and translate the arguments and commands into the
# appropriate non-POSIX ones as needed.  libeSDKOBSS3 assumes a GNU toolchain as
# the most portable way to build software possible.  Non-POSIX, non-GNU
# systems can do the work of supporting this build infrastructure.


# --------------------------------------------------------------------------
# Set libeSDKOBSS3 version number, unless it is already set.

LIBS3_VER_MAJOR ?= 2.1
LIBS3_VER_MINOR ?= 00
LIBS3_VER := $(LIBS3_VER_MAJOR).$(LIBS3_VER_MINOR)

#DEBUG=debug
# -----------------------------------------------------------------------------
# Determine verbosity.  VERBOSE_SHOW should be prepended to every command which
# should only be displayed if VERBOSE is set.  QUIET_ECHO may be used to
# echo text only if VERBOSE is not set.  Typically, a VERBOSE_SHOW command will
# be paired with a QUIET_ECHO command, to provide a command which is displayed
# in VERBOSE mode, along with text which is displayed in non-VERBOSE mode to
# describe the command.
#
# No matter what VERBOSE is defined to, it ends up as true if it's defined.
# This will be weird if you defined VERBOSE=false in the environment, and we
# switch it to true here; but the meaning of VERBOSE is, "if it's defined to
# any value, then verbosity is turned on".  So don't define VERBOSE if you
# don't want verbosity in the build process.
# -----------------------------------------------------------------------------

ifdef VERBOSE
        VERBOSE = true
        VERBOSE_ECHO = @ echo
        VERBOSE_SHOW =
        QUIET_ECHO = @ echo > /dev/null
else
        VERBOSE = false
        VERBOSE_ECHO = @ echo > /dev/null
        VERBOSE_SHOW = @
        QUIET_ECHO = @ echo
endif


# --------------------------------------------------------------------------
# BUILD directory
ifndef BUILD
    ifdef DEBUG
        BUILD := build-debug
    else
        BUILD := build
    endif

 endif


# --------------------------------------------------------------------------
# DESTDIR directory
ifndef DESTDIR
    DESTDIR := /usr
endif

# --------------------------------------------------------------------------
# LIBDIR directory
ifndef LIBDIR
    LIBDIR := ${DESTDIR}/lib
endif

# --------------------------------------------------------------------------
# Compiler CC handling
ifndef CC
    CC := gcc
endif

# --------------------------------------------------------------------------
# Acquire configuration information for libraries that libeSDKOBSS3 depends upon
export LD_LIBRARY_PATH=./../third_party/build/openssl-1.0.2j/lib/

ifndef CURL_LIBS
    CURL_LIBS := -L./../third_party/build/curl-7.49.1/lib/ -lcurl
endif

ifndef CURL_CFLAGS
    CURL_CFLAGS := -I./../third_party/build/curl-7.49.1/include
endif

ifndef LIBXML2_LIBS
    LIBXML2_LIBS := -L./../third_party/build/libxml2-2.9.4/lib -lxml2 -lm -ldl
endif

ifndef LIBXML2_CFLAGS
    LIBXML2_CFLAGS := -I./../third_party/build/libxml2-2.9.4/include
endif

ifndef LIBESDKLOGAPI_CFLAGS
    LIBESDKLOGAPI_CFLAGS := -I./../self_dev/eSDK_LogAPI_V2.1.00/include
endif

ifndef LIBESDKLOGAPI_LIBS
    LIBESDKLOGAPI_LIBS := -L./../self_dev/eSDK_LogAPI_V2.1.00/lib -leSDKLogAPI
endif

ifndef LIBOPENSSL_LIBS
     LIBOPENSSL_LIBS := -L./../third_party/build/openssl-1.0.2j/lib -lssl -lcrypto
endif

ifndef LIBOPENSSL_CFLAGS
     LIBOPENSSL_CFLAGS := -I./../third_party/build/openssl-1.0.2j/include
endif

ifndef LIBPCRE_LIBS
     LIBPCRE_LIBS := -L./../third_party/build/pcre-8.39/lib -lpcre
endif

ifndef LIBPCRE_CFLAGS
     LIBPCRE_CFLAGS := -I./../third_party/build/pcre-8.39/include/pcre
endif

ifndef LIBSSH2_LIBS
     LIBSSH2_LIBS := -L./../third_party/build/libssh2-1.7.0/lib -lssh2
endif

ifndef LIBSSH2_CFLAGS
     LIBSSH2_CFLAGS := -I./../third_party/build/libssh2-1.7.0/include
endif

# add libsecurec by jwx329074 2016.09.18
ifndef LIBSECUREC_LIBS
     LIBSECUREC_LIBS := -L./../self_dev/huaweisecurec/lib -lsecurec
endif

ifndef LIBSECUREC_CFLAGS
     LIBSECUREC_CFLAGS := -I./../self_dev/huaweisecurec/include
endif

# --------------------------------------------------------------------------
# These CFLAGS assume a GNU compiler.  For other compilers, write a script
# which converts these arguments into their equivalent for that particular
# compiler.

ifndef CFLAGS
    ifdef DEBUG
        CFLAGS := -g
    else
        CFLAGS := -O3
    endif
endif

CFLAGS += -Wall -Werror -Wshadow -Wextra -Iinc \
          $(CURL_CFLAGS) $(LIBXML2_CFLAGS) $(LIBESDKLOGAPI_CFLAGS) $(LIBOPENSSL_CFLAGS) $(LIBPCRE_CFLAGS) $(LIBSSH2_CFLAGS) $(LIBSECUREC_CFLAGS)\
          -DLIBS3_VER_MAJOR=\"$(LIBS3_VER_MAJOR)\" \
          -DLIBS3_VER_MINOR=\"$(LIBS3_VER_MINOR)\" \
          -DLIBS3_VER=\"$(LIBS3_VER)\" \
          -D__STRICT_ANSI__ \
          -D_ISOC99_SOURCE \
          -D_POSIX_C_SOURCE=200112L

LDFLAGS = $(CURL_LIBS) $(LIBXML2_LIBS) $(LIBESDKLOGAPI_LIBS) $(LIBOPENSSL_LIBS) $(LIBPCRE_LIBS) $(LIBSSH2_LIBS) $(LIBSECUREC_LIBS) -lpthread


# --------------------------------------------------------------------------
# Default targets are everything

.PHONY: all
all: exported


# --------------------------------------------------------------------------
# Exported targets are the library and driver program

.PHONY: exported
exported: libeSDKOBSS3 headers


# --------------------------------------------------------------------------
# Install target

.PHONY: install
install: exported
	# $(QUIET_ECHO) $(DESTDIR)/bin/s3: Installing executable
	# $(VERBOSE_SHOW) install -Dps -m u+rwx,go+rx $(BUILD)/bin/s3 \
                    # $(DESTDIR)/bin/s3
	# $(QUIET_ECHO) \
        # $(LIBDIR)/libs3.so.$(LIBS3_VER): Installing shared library
	# $(VERBOSE_SHOW) install -Dps -m u+rw,go+r \
               # $(BUILD)/lib/libs3.so.$(LIBS3_VER_MAJOR) \
               # $(LIBDIR)/libs3.so.$(LIBS3_VER)
	# $(QUIET_ECHO) \
        # $(LIBDIR)/libs3.so.$(LIBS3_VER_MAJOR): Linking shared library
	# $(VERBOSE_SHOW) ln -sf libs3.so.$(LIBS3_VER) \
               # $(LIBDIR)/libs3.so.$(LIBS3_VER_MAJOR)
	# $(QUIET_ECHO) $(LIBDIR)/libs3.so: Linking shared library
	# $(VERBOSE_SHOW) ln -sf libs3.so.$(LIBS3_VER_MAJOR) $(LIBDIR)/libs3.so
	# $(QUIET_ECHO) $(LIBDIR)/libs3.a: Installing static library
	# $(VERBOSE_SHOW) install -Dp -m u+rw,go+r $(BUILD)/lib/libs3.a \
                    # $(LIBDIR)/libs3.a
	# $(QUIET_ECHO) $(DESTDIR)/include/libs3.h: Installing header
	# $(VERBOSE_SHOW) install -Dp -m u+rw,go+r $(BUILD)/include/libs3.h \
                    # $(DESTDIR)/include/libs3.h


# --------------------------------------------------------------------------
# Uninstall target

 .PHONY: uninstall
 uninstall:
	# $(QUIET_ECHO) Installed files: Uninstalling
	# $(VERBOSE_SHOW) \
	    # rm -f $(DESTDIR)/bin/s3 \
              # $(DESTDIR)/include/libs3.h \
              # $(DESTDIR)/lib/libs3.a \
              # $(DESTDIR)/lib/libs3.so \
              # $(DESTDIR)/lib/libs3.so.$(LIBS3_VER_MAJOR) \
              # $(DESTDIR)/lib/libs3.so.$(LIBS3_VER)


# --------------------------------------------------------------------------
# Compile target patterns

$(BUILD)/obj/%.o: src/%.c
	$(QUIET_ECHO) $@: Compiling object
	@ mkdir -p $(dir $(BUILD)/dep/$<)
	@ $(CC) $(CFLAGS) -M -MG -MQ $@ -DCOMPILINGDEPENDENCIES \
        -o $(BUILD)/dep/$(<:%.c=%.d) -c $<
	@ mkdir -p $(dir $@)
	$(VERBOSE_SHOW) $(CC) $(CFLAGS) -fstack-protector 			\
									--param ssp-buffer-size=4	\
									-Wl,-z,relro,-z,now 		\
									-Wl,-z,noexecstack  		\
									-fPIC						\
									-o $@ -c $<

$(BUILD)/obj/%.do: src/%.c
	$(QUIET_ECHO) $@: Compiling dynamic object
	@ mkdir -p $(dir $(BUILD)/dep/$<)
	@ $(CC) $(CFLAGS) -M -MG -MQ $@ -DCOMPILINGDEPENDENCIES \
        -o $(BUILD)/dep/$(<:%.c=%.dd) -c $<
	@ mkdir -p $(dir $@)
	$(VERBOSE_SHOW) $(CC) $(CFLAGS) -fstack-protector 			\
									--param ssp-buffer-size=4	\
									-Wl,-z,relro,-z,now 		\
									-Wl,-z,noexecstack  		\
									-fPIC						\
									-o $@ -c $< 


# --------------------------------------------------------------------------
# libeSDKOBSS3 library targets

LIBS3_SHARED = $(BUILD)/lib/libeSDKOBSS3.so
LIBS3_STATIC = $(BUILD)/lib/libeSDKOBSS3.a

.PHONY: libeSDKOBSS3
libeSDKOBSS3: $(LIBS3_SHARED) $(LIBS3_STATIC)

LIBS3_SOURCES := acl.c bucket.c error_parser.c general.c \
                 object.c request.c request_context.c \
                 response_headers_handler.c service_access_logging.c \
                 service.c simplexml.c util.c log.c 

$(LIBS3_SHARED): $(LIBS3_SOURCES:%.c=$(BUILD)/obj/%.do)
	$(QUIET_ECHO) $@: Building shared library
	@ mkdir -p $(dir $@)
	$(VERBOSE_SHOW) $(CC) -shared -Wl,-soname,libeSDKOBSS3.so \
						-fstack-protector 			\
						--param ssp-buffer-size=4	\
						-Wl,-z,relro,-z,now 		\
						-Wl,-z,noexecstack  		\
						-fPIC						\
						-o $@ $^  $(LDFLAGS)

$(LIBS3_STATIC): $(LIBS3_SOURCES:%.c=$(BUILD)/obj/%.o)
	$(QUIET_ECHO) $@: Building static library
	@ mkdir -p $(dir $@)
	$(VERBOSE_SHOW) $(AR) cr $@ $^


# --------------------------------------------------------------------------
# libeSDKOBSS3 header targets

.PHONY: headers
headers: $(BUILD)/include/eSDKOBSS3.h

$(BUILD)/include/eSDKOBSS3.h: inc/eSDKOBSS3.h
	$(QUIET_ECHO) $@: Linking header
	@ mkdir -p $(dir $@)
	cp $< $@


# --------------------------------------------------------------------------
# Clean target

.PHONY: clean
clean:
	$(QUIET_ECHO) $(BUILD): Cleaning
	$(VERBOSE_SHOW) rm -rf $(BUILD)

.PHONY: distclean
distclean:
	$(QUIET_ECHO) $(BUILD): Cleaning
	$(VERBOSE_SHOW) rm -rf $(BUILD)


# --------------------------------------------------------------------------
# Clean dependencies target

.PHONY: cleandeps
cleandeps:
	$(QUIET_ECHO) $(BUILD)/dep: Cleaning dependencies
	$(VERBOSE_SHOW) rm -rf $(BUILD)/dep


# --------------------------------------------------------------------------
# Dependencies

ALL_SOURCES := $(LIBS3_SOURCES)

$(foreach i, $(ALL_SOURCES), $(eval -include $(BUILD)/dep/src/$(i:%.c=%.d)))
$(foreach i, $(ALL_SOURCES), $(eval -include $(BUILD)/dep/src/$(i:%.c=%.dd)))


# --------------------------------------------------------------------------

