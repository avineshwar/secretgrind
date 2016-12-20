#include "pub_tool_libcbase.h"

#include "secretgrind.h"
#include "tnt_include.h"
#include "tnt_libc.h"
#include "pub_tool_stacktrace.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_mallocfree.h"

int errno = 0;

/* -------------------------------------------- */
/* ----------- libc functions i want ---------- */
/* -------------------------------------------- */


static inline int
isupper(char c)
{
    return (c >= 'A' && c <= 'Z');
}

static inline int
isalpha(char c)
{
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}


static inline int
isspace(char c)
{
    return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}

static inline int
isdigit(char c)
{
    return (c >= '0' && c <= '9');
}

/* -------------------------------------------- */
/* ----------------- strlcpy(l) ---------------- */
/* -------------------------------------------- */

SizeT libc_strlcpy(char *dst, const char *src, SizeT len)
{
	SizeT srcLen = VG_(strlen)(src);
	SizeT dstLen = 0;
	dst[0] = '\0';
	
	if (len) {
		VG_(strncpy)(dst, src, len-1);
		dst[VG_(strlen)(src)] = '\0';
	}
	
	dstLen = VG_(strlen)(dst);
	return max(dstLen, srcLen);
}

/* -------------------------------------------- */
/* ----------------- strlcat(l) ---------------- */
/* -------------------------------------------- */

SizeT libc_strlcat(char *dst, const char *src, SizeT len)
{
	SizeT srcLen = VG_(strlen)(src);
	SizeT dstLen = 0;
	
	if ( len ) {
		VG_(strncat)(dst, src, len-1);
		dst[VG_(strlen)(src)] = '\0';
	}

	dstLen = VG_(strlen)(dst);
	tl_assert ( dstLen <= (SizeT)(-1) - srcLen );
	return (dstLen + srcLen);	/* count does not include NUL */
}

/* -------------------------------------------- */
/* ----------------- strtol(l) ---------------- */
/* -------------------------------------------- */

// Note: copied from https://opensource.apple.com/source/xnu/xnu-1456.1.26/bsd/libkern/strtol.c

/*
 * Convert a string to a long integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
long
libc_strtol(nptr, endptr, base)
	const char *nptr;
	char **endptr;
	register int base;
{
	register const char *s = nptr;
	register unsigned long acc;
	register int c;
	register unsigned long cutoff;
	register int neg = 0, any, cutlim;
	errno = EOK;
	
	/*
	 * Skip white space and pick up leading +/- sign if any.
	 * If base is 0, allow 0x for hex and 0 for octal, else
	 * assume decimal; if base is already 16, allow 0x.
	 */
	do {
		c = *s++;
	} while (isspace(c));
	if (c == '-') {
		neg = 1;
		c = *s++;
	} else if (c == '+')
		c = *s++;
	if ((base == 0 || base == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	} else if ((base == 0 || base == 2) &&
	    c == '0' && (*s == 'b' || *s == 'B')) {
		c = s[1];
		s += 2;
		base = 2;
	}
	if (base == 0)
		base = c == '0' ? 8 : 10;

	/*
	 * Compute the cutoff value between legal numbers and illegal
	 * numbers.  That is the largest legal value, divided by the
	 * base.  An input number that is greater than this value, if
	 * followed by a legal input character, is too big.  One that
	 * is equal to this value may be valid or not; the limit
	 * between valid and invalid numbers is then based on the last
	 * digit.  For instance, if the range for longs is
	 * [-2147483648..2147483647] and the input base is 10,
	 * cutoff will be set to 214748364 and cutlim to either
	 * 7 (neg==0) or 8 (neg==1), meaning that if we have accumulated
	 * a value > 214748364, or equal but the next digit is > 7 (or 8),
	 * the number is too big, and we will return a range error.
	 *
	 * Set any if any `digits' consumed; make it negative to indicate
	 * overflow.
	 */
	cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
	cutlim = cutoff % (unsigned long)base;
	cutoff /= (unsigned long)base;
	for (acc = 0, any = 0;; c = *s++) {
		if (isdigit(c))
			c -= '0';
		else if (isalpha(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
		if (c >= base)
			break;
		if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
			any = -1;
		else {
			any = 1;
			acc *= base;
			acc += c;
		}
	}
	if (any < 0) {
		acc = neg ? LONG_MIN : LONG_MAX;
		errno = ERANGE;
	} else if (neg)
		acc = -acc;
	if (endptr != 0)
		*endptr = (char *)(any ? s - 1 : nptr);
	return (acc);
}

/*
 * Convert a string to an unsigned long integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
unsigned long
libc_strtoul(nptr, endptr, base)
	const char *nptr;
	char **endptr;
	register int base;
{
	register const char *s = nptr;
	register unsigned long acc;
	register int c;
	register unsigned long cutoff;
	register int neg = 0, any, cutlim;
	errno = EOK;
	
	/*
	 * See strtol for comments as to the logic used.
	 */
	do {
		c = *s++;
	} while (isspace(c));
	if (c == '-') {
		neg = 1;
		c = *s++;
	} else if (c == '+')
		c = *s++;
	if ((base == 0 || base == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	} else if ((base == 0 || base == 2) &&
	    c == '0' && (*s == 'b' || *s == 'B')) {
		c = s[1];
		s += 2;
		base = 2;
	}
	if (base == 0)
		base = c == '0' ? 8 : 10;
	cutoff = (unsigned long)ULONG_MAX / (unsigned long)base;
	cutlim = (unsigned long)ULONG_MAX % (unsigned long)base;
	for (acc = 0, any = 0;; c = *s++) {
		if (isdigit(c))
			c -= '0';
		else if (isalpha(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
		if (c >= base)
			break;
		if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
			any = -1;
		else {
			any = 1;
			acc *= base;
			acc += c;
		}
	}
	if (any < 0) {
		acc = ULONG_MAX;
		errno = ERANGE;
	} else if (neg)
		acc = -acc;
	if (endptr != 0)
		*endptr = (char *)(any ? s - 1 : nptr);
	return (acc);
}

/* -------------------------------------------- */
/* ----------------- basename(path) ----------- */
/* -------------------------------------------- */

char * libc_basename (path)
	char * path;
{
    /*char *s = VG_(strrchr) (path, '/');

    return (s == NULL) ? path : ++s;*/
    return (char*)VG_(basename)(path);
}

/* -------------------------------------------- */
/* ----------------- strncat ----------------- */
/* -------------------------------------------- */
// copy from https://opensource.apple.com/source/Libc/Libc-262/i386/gen/strncat.c

/*
 * Concatenate src on the end of dst.  At most strlen(dst)+n+1 bytes
 * are written at dst (at most n+1 bytes being appended).  Return dst.
 */
/*char *
libc_strncat(dst, src, n)
	char *dst;
	const char *src;
	register SizeT n;
{
	if (n != 0) {
		register char *d = dst;
		register const char *s = src;

		while (*d != 0)
			d++;
		do {
			if ((*d = *s++) == 0)
				break;
			d++;
		} while (--n != 0);
		*d = 0;
	}
	return (dst);
}*/


/* -------------------------------------------- */
/* ----------------- realpath ----------------- */
/* -------------------------------------------- */
/*
#if defined VGO_linux
#	include "vki/vki-linux.h"
#	define VKI_ELOOP	(40)	// not defined in vki-linux.h
#else
#	error OS unknown
#endif

#if defined VGA_amd64
#	include "vki/vki-amd64-linux.h"
#else
#	error arch unknown
#endif

// defined in tnt_syswrap.c
extern void resolve_filename(Int fd, HChar *path, SizeT max);
// defined in coregrind/m_syscall
extern SysRes VG_(do_syscall) ( UWord sysno, UWord a1, UWord a2, UWord a3,
                                      UWord a4, UWord a5, UWord a6,
                                      UWord a7, UWord a8 );
                                      
char *libc_realpath(const char * filename, char * resolved)
{
	Int fd;
	Int r;
	SysRes statres;
	struct vg_stat st1, st2;
	char buf[PATH_MAX];
	char tmp[PATH_MAX];

	if (!filename) {
		errno = VKI_EINVAL;
		return 0;
	}

	fd = VG_(fd_open)(filename, VKI_O_RDONLY|VKI_O_NONBLOCK, 0666);
	if (fd < 0) return 0;
	resolve_filename(fd, buf, sizeof(buf));
	LOG("buf:%s\n", buf);
	
	// I don't call as below because I want to test for the error
	//r = VG_(readlink)(buf, tmp, sizeof tmp - 1);
	SysRes res = VG_(do_syscall)(__NR_readlink, (UWord)buf, (UWord)tmp, sizeof tmp - 1, 0,0,0,0,0);
	if ( sr_isError(res) && sr_Err(res) == VKI_EINVAL ) {
		// it's not a symbolic link, just copy the original
		return resolved ? VG_(strcpy)(resolved, filename) : VG_(strdup)("realpath-dup", filename);
	}
	r = sr_isError(res) ? -1 : sr_Res(res);
	LOG("readlink:%u\n", sr_Err(res));
	if (r < 0) goto err;
	tmp[r] = 0;
	LOG("readlink:%s\n", tmp);

	VG_(fstat) (fd, &st1);
	statres = VG_(stat)( tmp, &st2 );
	LOG("stat error:%d\n", sr_isError(statres));
	if ( sr_isError(statres) || st1.dev != st2.dev || st1.ino != st2.ino) {
		if (!sr_Err(statres)) errno = VKI_ELOOP;
		goto err;
	}
	
	VG_(close)(fd);
	return resolved ? VG_(strcpy)(resolved, tmp) : VG_(strdup)("realpath-dup",tmp);

err:
	VG_(close)(fd);
	return 0;
}
* */

