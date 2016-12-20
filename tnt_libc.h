#ifndef TNT_LIBC_H
#define TNT_LIBC_H

#include "pub_tool_basics.h"

#define EOK 0
#define ERANGE 1
extern int errno;
extern SizeT libc_strlcpy(char *dst, const char *src, SizeT len);
extern long libc_strtol(const char *nptr, char **endptr, int base);
extern unsigned long libc_strtoul(const char *nptr, char **endptr, int base);
extern char * libc_basename(char *path);
//extern char * libc_strncat(char *dst, const char *src, SizeT n);
extern SizeT libc_strlcat(char *dst, const char *src, SizeT len);
extern char *libc_realpath(const char * filename, char * resolved);
#endif // TNT_LIBC_H
