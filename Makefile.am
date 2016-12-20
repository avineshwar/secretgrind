include $(top_srcdir)/Makefile.tool.am

#----------------------------------------------------------------------------
# Headers
#----------------------------------------------------------------------------

pkginclude_HEADERS = \
	secretgrind.h

noinst_HEADERS = \
	tnt_include.h \
	tnt_strings.h \
	tnt_malloc_wrappers.h \
	tnt_summary_names.h \
	tnt_subblock_helper.h \
	tnt_syswrap.h \
	tnt_libc.h \
	tnt_file_filter.h \
	tnt_asm.h \
	copy.h

#----------------------------------------------------------------------------
# secretgrind-<platform>
#----------------------------------------------------------------------------

noinst_PROGRAMS  = secretgrind-@VGCONF_ARCH_PRI@-@VGCONF_OS@
if VGCONF_HAVE_PLATFORM_SEC
noinst_PROGRAMS += secretgrind-@VGCONF_ARCH_SEC@-@VGCONF_OS@
endif

SECRETGRIND_SOURCES_COMMON = \
	tnt_syswrap.c \
	tnt_malloc_wrappers.c \
	tnt_main.c \
	tnt_translate.c \
	tnt_summary_names.c \
	tnt_mmap.c \
	tnt_libc.c \
	tnt_file_filter.c \
	tnt_asm.c \
	copy.c


secretgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_SOURCES      = $(SECRETGRIND_SOURCES_COMMON)
secretgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CPPFLAGS     = \
	$(AM_CPPFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
secretgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CFLAGS       = \
	$(AM_CFLAGS_@VGCONF_PLATFORM_PRI_CAPS@) -O2
secretgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_DEPENDENCIES = \
	$(TOOL_DEPENDENCIES_@VGCONF_PLATFORM_PRI_CAPS@)
secretgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDADD        = \
	$(TOOL_LDADD_@VGCONF_PLATFORM_PRI_CAPS@)
secretgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDFLAGS      = \
	$(TOOL_LDFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
secretgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LINK = \
        ../coregrind/link_tool_exe_@VGCONF_OS@ \
        @VALT_LOAD_ADDRESS_PRI@ \
        $(LINK) \
        $(secretgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CFLAGS) \
        $(secretgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDFLAGS)

if VGCONF_HAVE_PLATFORM_SEC
secretgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_SOURCES      = $(SECRETGRIND_SOURCES_COMMON)
secretgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CPPFLAGS     = \
	$(AM_CPPFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
secretgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CFLAGS       = \
	$(AM_CFLAGS_@VGCONF_PLATFORM_SEC_CAPS@) -O2
secretgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_DEPENDENCIES = \
	$(TOOL_DEPENDENCIES_@VGCONF_PLATFORM_SEC_CAPS@)
secretgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDADD        = \
	$(TOOL_LDADD_@VGCONF_PLATFORM_SEC_CAPS@)
secretgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDFLAGS      = \
	$(TOOL_LDFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
secretgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LINK = \
        ../coregrind/link_tool_exe_@VGCONF_OS@ \
        @VALT_LOAD_ADDRESS_SEC@ \
        $(LINK) \
        $(secretgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CFLAGS) \
        $(secretgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDFLAGS)
endif

tnt_main.o: CFLAGS += -fomit-frame-pointer

#----------------------------------------------------------------------------
# vgpreload_secretgrind-<platform>.so
#----------------------------------------------------------------------------

noinst_PROGRAMS += vgpreload_secretgrind-@VGCONF_ARCH_PRI@-@VGCONF_OS@.so
if VGCONF_HAVE_PLATFORM_SEC
noinst_PROGRAMS += vgpreload_secretgrind-@VGCONF_ARCH_SEC@-@VGCONF_OS@.so
endif

if VGCONF_OS_IS_DARWIN
noinst_DSYMS = $(noinst_PROGRAMS)
endif

VGPRELOAD_SECRETGRIND_SOURCES_COMMON = tnt_wraps.c

vgpreload_secretgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_so_SOURCES      = \
	$(VGPRELOAD_SECRETGRIND_SOURCES_COMMON)
vgpreload_secretgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_so_CPPFLAGS     = \
	$(AM_CPPFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
vgpreload_secretgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_so_CFLAGS       = \
	$(AM_CFLAGS_@VGCONF_PLATFORM_PRI_CAPS@) $(AM_CFLAGS_PIC) -O2
vgpreload_secretgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_so_DEPENDENCIES = \
	$(LIBREPLACEMALLOC_@VGCONF_PLATFORM_PRI_CAPS@)
vgpreload_secretgrind_@VGCONF_ARCH_PRI@_@VGCONF_OS@_so_LDFLAGS      = \
	$(PRELOAD_LDFLAGS_@VGCONF_PLATFORM_PRI_CAPS@) \
	$(LIBREPLACEMALLOC_LDFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
if VGCONF_HAVE_PLATFORM_SEC
vgpreload_secretgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_so_SOURCES      = \
	$(VGPRELOAD_SECRETGRIND_SOURCES_COMMON)
vgpreload_secretgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_so_CPPFLAGS     = \
	$(AM_CPPFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
vgpreload_secretgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_so_CFLAGS       = \
	$(AM_CFLAGS_@VGCONF_PLATFORM_SEC_CAPS@) $(AM_CFLAGS_PIC) -O2
vgpreload_secretgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_so_DEPENDENCIES = \
	$(LIBREPLACEMALLOC_@VGCONF_PLATFORM_SEC_CAPS@)
vgpreload_secretgrind_@VGCONF_ARCH_SEC@_@VGCONF_OS@_so_LDFLAGS      = \
	$(PRELOAD_LDFLAGS_@VGCONF_PLATFORM_SEC_CAPS@) \
	$(LIBREPLACEMALLOC_LDFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
endif

tnt_wraps.o: CFLAGS += -fno-omit-frame-pointer

