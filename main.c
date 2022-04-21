/* Copyright (c) 2022 Griefer@Work                                            *
 *                                                                            *
 * This software is provided 'as-is', without any express or implied          *
 * warranty. In no event will the authors be held liable for any damages      *
 * arising from the use of this software.                                     *
 *                                                                            *
 * Permission is granted to anyone to use this software for any purpose,      *
 * including commercial applications, and to alter it and redistribute it     *
 * freely, subject to the following restrictions:                             *
 *                                                                            *
 * 1. The origin of this software must not be misrepresented; you must not    *
 *    claim that you wrote the original software. If you use this software    *
 *    in a product, an acknowledgement (see the following) in the product     *
 *    documentation is required:                                              *
 *    Portions Copyright (c) 2022 Griefer@Work                                *
 * 2. Altered source versions must be plainly marked as such, and must not be *
 *    misrepresented as being the original software.                          *
 * 3. This notice may not be removed or altered from any source distribution. *
 */
#ifndef GUARD_SREPLACE_MAIN_C
#define GUARD_SREPLACE_MAIN_C
#define _KOS_SOURCE 1
#define _GNU_SOURCE 1
#define _USE_64BIT_TIME_T 1
#define _TIME_T_BITS 64
#define _FILE_OFFSET_BITS 64
#define _CRT_SECURE_NO_WARNINGS 1

#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define TARGET_NT
#endif /* _WIN32 */


#ifdef TARGET_NT
#include <Windows.h>
#include <locale.h>
#include <wchar.h>
#define BADFD         INVALID_HANDLE_VALUE
#define fd_t          HANDLE
#define errno_t       DWORD
#define get_errno()   GetLastError()
#define set_errno(v)  SetLastError(v)
#define close(fd)     (CloseHandle(fd) ? 0 : -1)
#define printf        _printf_p
#define vprintf       _vprintf_p
#define fprintf       _fprintf_p
#define vfprintf      _vfprintf_p
#define STDIN_FILENO  GetStdHandle(STD_INPUT_HANDLE)
#define STDOUT_FILENO GetStdHandle(STD_OUTPUT_HANDLE)
#define STDERR_FILENO GetStdHandle(STD_ERROR_HANDLE)

#define DIRp           HANDLE
#define closedir(d)    (FindClose(d) ? 0 : -1)
#define struct_tdirent WIN32_FIND_DATAW
#define d_name         cFileName

#define TCSEP      L'\\'
#define TSSEP      L"\\"
#define tissep(ch) ((ch) == L'\\' || (ch) == L'/')

#define T(x)         L##x
#define PRIsT        "ls"
#define PRIcT        "lc"
#define tchar        WCHAR
#define tstrcat      wcscat
#define tstrcpy      wcscpy
#define tstrlen      wcslen
#define tmemcpy      wmemcpy
#define tstrcmp      wcscmp
#define tstrchr      wcschr
#define tstrrchr     wcsrchr
#define tmain        wmain
#define tatol        _wtol

#define struct_stat      BY_HANDLE_FILE_INFORMATION
#define fstat(fd, st)    (GetFileInformationByHandle(fd, st) ? 0 : -1)
#define unlink(name)     (DeleteFileW(name) ? 0 : -1)
#define rename(from, to) (MoveFileW(from, to) ? 0 : -1)

#define iosize_t DWORD
#define fd_read(fd, buf, size, p_readsize) \
	ReadFile(fd, buf, (DWORD)(size), p_readsize, NULL)
#define fd_write(fd, buf, size, p_writesize) \
	WriteFile(fd, buf, (DWORD)(size), p_writesize, NULL)
#else /* TARGET_NT */
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define HAVE_MEMMEM

#define TCSEP      '/'
#define TSSEP      "/"
#define tissep(ch) ((ch) == '/')

#define T(x)      x
#define PRIsT     "s"
#define PRIcT     "c"
#define tchar     char
#define tstrcat   strcat
#define tstrcpy   strcpy
#define tstrlen   strlen
#define tmemcpy   (char *)memcpy
#define tstrcmp   strcmp
#define tstrchr   strchr
#define tstrrchr  strrchr
#define tstrerror strerror
#define tmain     main
#define tatol     atol

#define struct_tdirent struct dirent
#define struct_stat    struct stat
#define DIRp           DIR *
#define BADFD          (-1)
#define fd_t           int
#define errno_t        int
#define get_errno()    errno
#define set_errno(v)   (errno = (v))
#define iosize_t       size_t
#define fd_read(fd, buf, size, p_readsize) \
	((ssize_t)(*(p_readsize) = (iosize_t)read(fd, buf, size)) >= 0)
#define fd_write(fd, buf, size, p_writesize) \
	((ssize_t)(*(p_writesize) = (iosize_t)write(fd, buf, size)) >= 0)

#if defined(__NO_has_include) || !defined(__has_include)
#define HAVE_REGEX_H
#elif __has_include(<regex.h>)
#define HAVE_REGEX_H
#endif
#endif /* !TARGET_NT */

#define byte_t unsigned char

#ifdef HAVE_REGEX_H
#include <regex.h>
#else /* HAVE_REGEX_H */
#define REG_NOTBOL 0x01
#define REG_NOTEOL 0x02
#endif /* !HAVE_REGEX_H */

#if defined(DT_DIR) && defined(DT_REG)
#define HAVE_DIRENT_D_TYPE
#endif /* DT_DIR && DT_REG */

#ifndef __USE_KOS
#define memmoveup   memmove
#define memmovedown memmove
#endif /* !__USE_KOS */

#ifdef __USE_KOS
#define HAVE_MEMCASECMP
#define HAVE_MEMCASEMEM
#endif /* !__USE_KOS */


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Program name */
static tchar const *opt_progname = T("sreplace");

static void warn(char const *format, ...) {
	va_list args;
	va_start(args, format);
	fprintf(stderr, "%" PRIsT ": ", opt_progname);
	vfprintf(stderr, format, args);
	va_end(args);
}

static void *xmalloc(size_t num_bytes) {
	void *result = malloc(num_bytes);
	if (!result) {
		if (!num_bytes)
			num_bytes = 1;
		result = malloc(num_bytes);
		if (!result) {
			warn("error: failed to allocate %lu bytes\n",
			     (unsigned long)num_bytes);
			exit(1);
		}
	}
	return result;
}

static void *xrealloc(void *ptr, size_t num_bytes) {
	void *result;
	if (!num_bytes)
		num_bytes = 1;
	result = realloc(ptr, num_bytes);
	if (!result) {
		warn("error: failed to reallocate %p to %lu bytes\n",
		     ptr, (unsigned long)num_bytes);
		exit(1);
	}
	return result;
}

static tchar *xtstrdup(tchar const *str) {
	size_t ssize  = (tstrlen(str) + 1) * sizeof(tchar);
	tchar *result = (tchar *)xmalloc(ssize);
	return (tchar *)memcpy(result, str, ssize);
}


#ifdef TARGET_NT
#define tstrerror(x) nt_strerror(x)
static WCHAR const *nt_strerror(errno_t err) {
	static WCHAR *p_oldreturn = NULL;
	WCHAR *result;
	if (p_oldreturn)
		LocalFree(p_oldreturn);
	if (!FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
	                    FORMAT_MESSAGE_FROM_SYSTEM,
	                    NULL, err,
	                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
	                    (LPWSTR)&result, 1, NULL))
		return L"unknown error";
	p_oldreturn = result;
	return result;
}


static size_t xwcrtomb(char *dst, WCHAR wc, mbstate_t *mb) {
	size_t result = wcrtomb(dst, wc, mb);
	if (result == (size_t)-1) {
		memset(mb, 0, sizeof(*mb));
		dst[0] = (char)(unsigned char)wc;
		result = 1;
	}
	return result;
}
static size_t xwcsntombs(char *buf, size_t buflen, WCHAR const *src, size_t srclen) {
	mbstate_t mbs;
	char *temp = (char *)xmalloc(MB_CUR_MAX);
	size_t result = 0;
	memset(&mbs, 0, sizeof(mbs));
	for (; srclen; --srclen, ++src) {
		size_t templen;
		templen = xwcrtomb(temp, *src, &mbs);
		result += templen;
		if (templen > buflen)
			templen = buflen;
		memcpy(buf, temp, templen * sizeof(char));
		buf += templen;
	}
	if (buflen)
		*buf = '\0';
	++result;
	free(temp);
	return result;
}

static char *xwcs2mbs(WCHAR const *str, size_t len, size_t *p_rlen) {
	size_t reqlen;
	size_t buflen = wcslen(str) + 1;
	char *buf = (char *)xmalloc(buflen * sizeof(char));
	for (;;) {
		reqlen = xwcsntombs(buf, buflen, str, len);
		buf    = (char *)xrealloc(buf, reqlen * sizeof(char));
		if (reqlen <= buflen)
			break;
		buflen = reqlen;
	}
	*p_rlen = reqlen - 1;
	return buf;
}
#endif /* TARGET_NT */




/* Commandline options */
static bool opt_icase      = false;
static bool opt_bound      = false;
static bool opt_recursive  = false;
static bool opt_escape     = false;
static bool opt_keep_mtime = false;
static bool opt_find       = false;
static tchar *opt_ext      = NULL; /* Elements don't have leading '.' */
static size_t opt_max      = (size_t)-1;
#ifdef HAVE_REGEX_H
static bool opt_regex = false;
#endif /* HAVE_REGEX_H */

static void tstrdel(tchar *pch, size_t n) {
	size_t len = tstrlen(pch);
	assert(len >= n);
	len -= n;
	memmovedown(pch, pch + n, len * sizeof(tchar));
	pch[len] = '\0';
}

static void setextlist(tchar const *list) {
	tchar *n;
	free(opt_ext);
	opt_ext = n = xtstrdup(list);
	/* Delete leading '.' from each element of `list' */
	while (*n) {
		if (*n == '.')
			tstrdel(n, 1);
		n = tstrchr(n,  T(':'));
		if (!n)
			break;
		++n;
	}
}

static bool tlistcontains(tchar const *list, tchar const *item) {
	size_t itemlen = tstrlen(item);
	while (*list) {
		if (memcmp(list, item, itemlen * sizeof(tchar)) == 0 &&
		    (list[itemlen] == T(':') || list[itemlen] == T('\0')))
			return true;
		list = tstrchr(list, T(':'));
		if (!list)
			break;
		++list;
	}
	return false;
}


struct find {
	tchar   *f_pattern; /* [1..1] Find-mattern */
	byte_t  *f_find;    /* [0..1][owned] String to find (or NULL if using a regular expression). */
	byte_t  *f_repl;    /* [0..1][owned] Replacement string (or NULL to retain existing text). */
#ifdef HAVE_REGEX_H
	regex_t *f_xfind;   /* [1..1][owned][valid_if(f_find == NULL)] Regular expression for string finding. */
#endif /* HAVE_REGEX_H */
	size_t   f_findlen; /* Length of `f_find', or `0' when `f_find == NULL' */
	size_t   f_repllen; /* Length of `f_repl', or `0' when `f_repl == NULL' */
};

/* [0..patterncnt][owned] List of patterns. */
static struct find *patternvec = NULL;

/* Number of defined patterns. */
static size_t patterncnt = 0;

static size_t min_find_len = (size_t)-1; /* Lowest value for `f_findlen' */
static size_t max_find_len = 0;          /* Greatest value for `f_findlen' */

/* Allocate a new find-descriptor */
static struct find *alloc_pattern(void) {
	struct find *result;
	result = (struct find *)xrealloc(patternvec,
	                                 (patterncnt + 1) *
	                                 sizeof(struct find));
	patternvec = result;
	result += patterncnt++;
	memset(result, 0, sizeof(*result));
#ifdef HAVE_REGEX_H
	if (opt_regex)
		result->f_xfind = (regex_t *)xmalloc(sizeof(regex_t));
#endif /* HAVE_REGEX_H */
	return result;
}


static size_t tunescape(tchar *str) {
	tchar *base = str;
	tchar ch, *dst = str;
	while ((ch = *str++) != T('\0')) {
		if (ch == T('\\')) {
			ch = *str++;
			switch (ch) {
			case T('a'): ch = 7; break;
			case T('b'): ch = 8; break;
			case T('t'): ch = 9; break;
			case T('n'): ch = 10; break;
			case T('v'): ch = 11; break;
			case T('f'): ch = 12; break;
			case T('r'): ch = 13; break;
			case T('e'): ch = 27; break;
			default:
				if (ch >= T('0') && ch <= T('7')) {
					byte_t b = ch - T('0');
					unsigned int n = 1;
					for (; n < 3; ++n, ++str) {
						ch = *str;
						if (!(ch >= T('0') && ch <= T('7')))
							break;
						b <<= 3;
						b |= ch - T('0');
					}
					ch = (tchar)b;
				}
				break;
			}
		}
		*dst++ = ch;
	}
	*dst = T('\0');
	return (size_t)(dst - base);
}





/* Output function for (possibly modified) file data. */
static void (*out)(void const *buf, size_t len) = NULL;

/* Set to true if `out' is about to be called with modified data. */
static bool out_changed = false;
#define setout(out_) (out_changed = false, out = (out_))


/* Accumulate line/column information. */
static tchar const *out2lc_file = NULL;  /* Filename. */
static unsigned int out2lc_line = 0;     /* Line number (0-based) */
static unsigned int out2lc_col  = 0;     /* Column number (0-based) */
static bool out2lc_afterCR      = false; /* Last character was CR */
static void out2lc_fun(void const *buf, size_t len) {
	byte_t ch;
	byte_t const *p   = (byte_t const *)buf;
	byte_t const *end = p + len;
	if (out2lc_afterCR) {
do_handle_cr:
		if (p < end) {
			out2lc_afterCR = false;
			ch = *p++;
			if (ch != (byte_t)'\n')
				goto handle_ch;
		}
	}
	while (p < end) {
		ch = *p++;
handle_ch:
		if (ch == (byte_t)'\r' || ch == (byte_t)'\n') {
			++out2lc_line;
			out2lc_col = 0;
			if (ch == (byte_t)'\r') {
				out2lc_afterCR = true;
				goto do_handle_cr;
			}
			continue;
		}
		++out2lc_col;
	}
}

static void out2lc_match(struct find *f, size_t match_len) {
	printf("%" PRIsT ":%u:%u:%lu:%" PRIsT "\n",
	       out2lc_file, out2lc_line + 1, out2lc_col + 1,
	       (unsigned long)match_len, f->f_pattern);
}


struct inbuf {
	byte_t *ib_buf; /* [0..ib_len+ib_avl][owned] Buffer base */
	size_t  ib_len; /* Used buffer size */
	size_t  ib_avl; /* Remaining (free) buffer size */
	int     ib_ref; /* Reg-ex flags (REG_NOTEOL is cleared on EOF) */
};

#ifdef HAVE_REGEX_H
static struct find *
regex_find(byte_t const *str, size_t len, regmatch_t *match, int flags) {
	size_t i;
	for (i = 0; i < patterncnt; ++i) {
		struct find *f = &patternvec[i];
		int status;
		match->rm_so = 0;
		match->rm_eo = len;
		status = regexec(f->f_xfind, (char const *)str, 1, match, flags);
		if (status == 0) {
			regmatch_t other_match;
			for (++i; i < patterncnt; ++i) {
				struct find *other_f = &patternvec[i];
				other_match.rm_so = 0;
				other_match.rm_eo = len;
				status = regexec(other_f->f_xfind, (char const *)str, 1, &other_match, flags);
				if (status != 0)
					continue;
				if (other_match.rm_so < match->rm_so) {
					match->rm_so = other_match.rm_so;
					match->rm_eo = other_match.rm_eo;
					f            = other_f;
				}
			}
			return f; /* Got a match! */
		}
	}
	return NULL;
}
#endif /* HAVE_REGEX_H */

#ifndef HAVE_MEMCASEMEM
#ifndef HAVE_MEMCASECMP
#define memcasecmp my_memcasecmp
static int memcasecmp(void const *s1, void const *s2, size_t n_bytes) {
	byte_t const *p1 = (byte_t const *)s1;
	byte_t const *p2 = (byte_t const *)s2;
	byte_t v1, v2;
	v1 = v2 = 0;
	while (n_bytes--) {
		v1 = *p1++;
		v2 = *p2++;
		if (v1 != v2) {
			v1 = (byte_t)tolower(v1);
			v2 = (byte_t)tolower(v2);
			if (v1 != v2)
				break;
		}
	}
	return (int)v1 - (int)v2;
}
#endif /* !HAVE_MEMCASECMP */

#define memcasemem my_memcasemem
static void *
memcasemem(void const *haystack, size_t haystacklen,
           void const *needle, size_t needlelen) {
	byte_t *candidate, marker;
	byte_t *hayend;
	if (!needlelen)
		return (byte_t *)haystack + haystacklen;
	if (needlelen > haystacklen)
		return NULL;
	haystacklen -= (needlelen - 1);
	marker       = (byte_t)tolower(*(byte_t *)needle);
	hayend       = (byte_t *)haystack + haystacklen;
	for (;;) {
		for (candidate = (byte_t *)haystack; candidate < hayend; ++candidate) {
			byte_t b = *candidate;
			if (b == marker || (byte_t)tolower(b) == marker)
				goto got_candidate;
		}
		break;
got_candidate:
		if (memcasecmp(candidate, needle, needlelen) == 0)
			return (void *)candidate;
		++candidate;
		haystacklen = ((byte_t *)haystack + haystacklen) - candidate;
		haystack    = (void const *)candidate;
	}
	return NULL;
}
#endif /* !HAVE_MEMCASEMEM */

#ifndef HAVE_MEMMEM
#define memmem my_memmem
static void *
memmem(void const *haystack, size_t haystacklen,
       void const *needle, size_t needlelen) {
	byte_t *candidate, marker;
	byte_t *hayend;
	if (!needlelen)
		return (byte_t *)haystack + haystacklen;
	if (needlelen > haystacklen)
		return NULL;
	haystacklen -= (needlelen - 1);
	marker = *(byte_t *)needle;
	hayend = (byte_t *)haystack + haystacklen;
	for (;;) {
		for (candidate = (byte_t *)haystack; candidate < hayend; ++candidate) {
			byte_t b = *candidate;
			if (b == marker)
				goto got_candidate;
		}
		break;
got_candidate:
		if (memcmp(candidate, needle, needlelen) == 0)
			return (void *)candidate;
		++candidate;
		haystacklen = ((byte_t *)haystack + haystacklen) - candidate;
		haystack    = (void const *)candidate;
	}
	return NULL;
}
#endif /* !HAVE_MEMMEM */


static struct find *
normal_find(byte_t const *str, size_t len, size_t match[2], int flags) {
	size_t i;
	struct find *result = NULL;
	for (i = 0; i < patterncnt; ++i) {
		struct find *f = &patternvec[i];
		byte_t *pos;
		byte_t const *used_str;
		size_t used_len;
		used_str = str;
		used_len = len;
again_search:
		pos = opt_icase ? (byte_t *)memcasemem(used_str, used_len, f->f_find, f->f_findlen)
		                : (byte_t *)memmem(used_str, used_len, f->f_find, f->f_findlen);
		if (pos) {
			size_t matchpos;
			if (opt_bound) {
				/* Ensure that the start/end of the match is at a word boundary.
				 * For  this case, we  consider a word  boundary as the position
				 * between  2 character with  differing isalnum() attributes, or
				 * the very first / very last character of the input file. */
				if (pos <= str) {
					if (flags & REG_NOTBOL)
						goto nomatch;
				} else {
					if (!!isalnum(pos[-1]) == !!isalnum(pos[0]))
						goto nomatch;
				}
				if ((pos + f->f_findlen) >= (str + len)) {
					if (flags & REG_NOTEOL)
						goto nomatch;
				} else {
					byte_t *epos = pos + f->f_findlen;
					if (!!isalnum(epos[-1]) == !!isalnum(epos[0]))
						goto nomatch;
				}
			}

			/* Found a match! */
			matchpos = (size_t)(pos - str);
			if (!result || matchpos < match[0]) {
				match[0] = matchpos;
				match[1] = match[0] + f->f_findlen;
				result   = f;
				/* Can limit our search to only those ranges that can produce better matches. */
				matchpos += max_find_len;
				if (len > matchpos)
					len = matchpos;
			}
			continue;
nomatch:
			++pos;
			used_len = (size_t)((str + len) - pos);
			used_str = pos;
			goto again_search;
		}
	}
	return result;
}


/* Read from `fd'. At  least 1 byte  is read, but  try to read  up
 * to `maxread'. Newly read data is appended at the end of `self'.
 * @return: true:  Data was read
 * @return: false: Nothing could be read (`maxread == 0', or `fd' is EOF) */
static bool inbuf_readfd(struct inbuf *self, fd_t fd, size_t maxread) {
	iosize_t readsize;
	size_t reqsize = 64 * 1024;
	if (!maxread || !(self->ib_ref & REG_NOTEOL))
		return false;
	if (reqsize > maxread)
		reqsize = maxread;
	if (reqsize > self->ib_avl) {
		if (self->ib_avl < 512) {
			byte_t *buf;
			size_t newsize = ((self->ib_len + self->ib_avl) << 1) | 1;
			size_t new_avl = 0;
			if (newsize > self->ib_len)
				new_avl = newsize - self->ib_len;
			if (new_avl < reqsize) {
				newsize = self->ib_len + reqsize;
				if (newsize < self->ib_len)
					newsize = (size_t)-1;
			}
			buf = (byte_t *)realloc(self->ib_buf, newsize);
			if (!buf) {
				newsize = self->ib_len + 1;
				buf = (byte_t *)xrealloc(self->ib_buf, newsize);
			}
			self->ib_buf = buf;
			self->ib_avl = newsize - self->ib_len;
		}
		reqsize = self->ib_avl;
	}
	assert(reqsize <= self->ib_avl);
	if (!fd_read(fd, self->ib_buf + self->ib_len, reqsize, &readsize)) {
#ifdef TARGET_NT
		if (get_errno() == ERROR_BROKEN_PIPE) {
			readsize = 0;
		} else
#endif /* TARGET_NT */
		{
			warn("failed to read data: %" PRIsT "\n", tstrerror(get_errno()));
			exit(1);
		}
	}
	if (readsize == 0) {
		if (reqsize)
			self->ib_ref &= ~REG_NOTEOL;
		return false;
	}
	assert((size_t)readsize <= reqsize);
	if ((size_t)readsize >= reqsize) {
		/* TODO: Check if more data can be read without blocking */
	}
	self->ib_len += (size_t)readsize;
	self->ib_avl -= (size_t)readsize;
	return true;
}


/* Read data from `infd', perform replacements, and `OUT()' modified data. */
static void dofd(fd_t infd) {
	struct inbuf ib;
	ib.ib_buf = NULL;
	ib.ib_len = 0;
	ib.ib_avl = 0;
#ifdef HAVE_REGEX_H
	ib.ib_ref = REG_STARTEND | REG_NOTEOL;
#else /* HAVE_REGEX_H */
	ib.ib_ref = REG_NOTEOL;
#endif /* !HAVE_REGEX_H */

	if (!opt_max)
		goto match_no_more;

#ifdef HAVE_REGEX_H
	if (opt_regex) {
		/* Read as much input data as we can. */
		while (inbuf_readfd(&ib, infd, (size_t)-1)) {
			regmatch_t match;
			struct find *f;
again_re_find:
			f = regex_find(ib.ib_buf, ib.ib_len, &match, ib.ib_ref);
			if (f) {
				/* Got a match! */
				(*out)(ib.ib_buf, (size_t)match.rm_so);
				if (out == &out2lc_fun) {
					size_t len = (size_t)match.rm_eo - (size_t)match.rm_so;
					out2lc_match(f, len);
					out2lc_fun(ib.ib_buf + (size_t)match.rm_so, len);
				} else {
					out_changed = true;
					(*out)(f->f_repl, f->f_repllen);
				}

				/* Consume text until end of match. */
				ib.ib_ref |= REG_NOTBOL; /* No longer at start of file */
				ib.ib_len -= match.rm_eo;
				memmovedown(ib.ib_buf, ib.ib_buf + match.rm_eo, ib.ib_len);
				ib.ib_avl += match.rm_eo;

				/* Handle `opt_max' */
				--opt_max;
				if (!opt_max)
					goto match_no_more;
				goto again_re_find;
			}
		}
	} else
#endif /* HAVE_REGEX_H */
	{
		size_t maxread = max_find_len + 1;
		if (maxread < 64 * 1024)
			maxread = 64 * 1024;
		while (inbuf_readfd(&ib, infd, maxread)) {
			size_t match[2];
			struct find *f;
			size_t skipsize;
again_normal_find:
			if (ib.ib_len < min_find_len)
				continue; /* Need more data! */
			f = normal_find(ib.ib_buf, ib.ib_len, match, ib.ib_ref);
			if (f) {
				/* Output text before the match. */
				(*out)(ib.ib_buf, match[0]);

				/* Output replacement. */
				if (out == &out2lc_fun) {
					size_t len = match[1] - match[0];
					out2lc_match(f, len);
					out2lc_fun(ib.ib_buf + match[0], len);
				} else {
					out_changed = true;
					(*out)(f->f_repl, f->f_repllen);
				}

				/* Consume text until end of match. */
				ib.ib_ref |= REG_NOTBOL; /* No longer at start of file */
				ib.ib_len -= match[1];
				memmovedown(ib.ib_buf, ib.ib_buf + match[1], ib.ib_len);
				ib.ib_avl += match[1];

				/* Handle `opt_max' */
				--opt_max;
				if (!opt_max)
					goto match_no_more;
				goto again_normal_find;
			}

			/* Forward unchanged data if we have more than may be used by the longest find-sequence. */
			if (ib.ib_len > max_find_len) {
				skipsize = ib.ib_len - (max_find_len - 1);
				assert(skipsize != 0);
				assert(ib.ib_len >= skipsize);
				(*out)(ib.ib_buf, skipsize);
				ib.ib_ref |= REG_NOTBOL; /* No longer at start of file */
				ib.ib_len -= skipsize;
				memmovedown(ib.ib_buf, ib.ib_buf + skipsize, ib.ib_len);
				ib.ib_avl += skipsize;
			}
		}
	}
	/* Output all remaining data beyond the last match. */
	(*out)(ib.ib_buf, ib.ib_len);
/*done:*/
	free(ib.ib_buf);
	return;
match_no_more:
	if (out == &out2lc_fun)
		return; /* Nothing left to do here! */
	/* Forward all remaining data unchanged. */
	do {
		if (ib.ib_len) {
			(*out)(ib.ib_buf, ib.ib_len);
			ib.ib_avl += ib.ib_len;
			ib.ib_len = 0;
		}
	} while (inbuf_readfd(&ib, infd, 64 * 1024));
}




static fd_t out2fd_fd = BADFD;
static void out2fd_fun(void const *buf, size_t len) {
	iosize_t ok;
	if (!len)
		return;
	for (;;) {
		if (!fd_write(out2fd_fd, buf, len, &ok)) {
/*			warn("write failed: %" PRIsT "\n", tstrerror(get_errno()));
			exit(1);*/
			break;
		}
		if ((size_t)ok >= len || ok == 0)
			break;
		len -= ok;
		buf = (byte_t *)buf + len;
	}
}



/* Output-to-memory buffer */
static void *out2mem_buf  = NULL; /* [0..out2mem_use+out2mem_avl][owned] Buffer */
static size_t out2mem_use = 0;    /* Used leading bytes */
static size_t out2mem_avl = 0;    /* Available free space */

static fd_t out2mem_infd               = BADFD; /* Input file handle. */
static tchar const *out2mem_infilename = NULL;  /* [1..1] Input filename. */
static tchar *out2mem_outfilename      = NULL;  /* [0..1] Output filename. */
static void out2mem_fun(void const *buf, size_t len) {
	/* Append `buf...+=len' to the in-memory buffer. */
	if (len > out2mem_avl) {
		size_t newlen = ((out2mem_use + out2mem_avl) << 1) | 1;
		size_t newavl = 0;
		if (newlen > out2mem_use)
			newavl = newlen - out2mem_use;
		if (len > newavl)
			newlen = out2mem_use + len;
		out2mem_buf = xrealloc(out2mem_buf, newlen);
		out2mem_avl = newlen - out2mem_use;
		assert(len <= out2mem_avl);
	}
	memcpy((byte_t *)out2mem_buf + out2mem_use, buf, len);
	out2mem_use += len;
	out2mem_avl -= len;
	if (out_changed) {
		/* Special case: something changed, so we have to create a new file. */
		struct_stat st;
		fd_t outfd;
		size_t inlen   = tstrlen(out2mem_infilename);
		size_t outlen  = inlen + 4; /* ".new" */
		tchar *outname = (tchar *)xmalloc((outlen + 1) * sizeof(tchar));
		memcpy(outname, out2mem_infilename, inlen * sizeof(tchar));
		out2mem_outfilename = outname;
		outname += inlen;
		tstrcpy(outname, T(".new"));
		if (fstat(out2mem_infd, &st) != 0) {
			warn("failed to stat input file '%" PRIsT "': %" PRIsT "\n",
			     out2mem_infilename, tstrerror(get_errno()));
			exit(1);
		}

		/* Open the new output file. */
#ifdef TARGET_NT
		outfd = CreateFileW(out2mem_outfilename, FILE_GENERIC_WRITE, FILE_SHARE_READ, NULL,
		                    CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		if (outfd == NULL || outfd == INVALID_HANDLE_VALUE)
#else /* TARGET_NT */
		outfd = open(out2mem_outfilename,
		             O_WRONLY | O_CREAT | O_EXCL,
		             st.st_mode & 0777);
		if (outfd < 0)
#endif /* !TARGET_NT */
		{
			warn("failed to create output file '%" PRIsT "': %" PRIsT "\n",
			     out2mem_outfilename, tstrerror(get_errno()));
			exit(1);
		}

		/* Redirect output to the newly opened file. */
		out2fd_fd = outfd;
		out = &out2fd_fun;

		/* Write all already-parsed data to the output file. */
		out2fd_fun(out2mem_buf, out2mem_use);

		/* Free the old memory-buffer. */
		free(out2mem_buf);
		out2mem_buf = NULL;
		out2mem_use = 0;
		out2mem_avl = 0;
	}
}





/* Do inplace replacements with `filename' (opened read-only in `infd') */
static void dofilename_with_fd(/*inherit*/ fd_t infd, tchar const *filename,
                               struct_stat *infd_stat) {
	/* Special case: find matches and print their locations */
	if (opt_find) {
		out2lc_afterCR = false;
		out2lc_file    = filename;
		out2lc_line    = 0;
		out2lc_col     = 0;
		setout(&out2lc_fun);
		dofd(infd);
		close(infd);
		return;
	}

	/* We want to output unmodified input data to memory until input  data
	 * has changed. At that point, we open a temporary file and write  all
	 * already-read data to that file, as well as the first modified data-
	 * piece.
	 * Once all input has been read, we check if changes were made, in
	 * which case  we replace  the input  file with  the output  file. */
	out2mem_infd        = infd;
	out2mem_infilename  = filename;
	out2mem_outfilename = NULL;
	out2mem_buf         = NULL;
	out2mem_use         = 0;
	out2mem_avl         = 0;
	setout(&out2mem_fun);

	/* Process input. */
	dofd(infd);

	/* Check if the output file was created. */
	if (out2mem_outfilename) {
		struct_stat st;
		/* Output file was created, so we have to replace the input file. */
		assert(out == &out2fd_fun);
		if (!infd_stat) {
			if (fstat(infd, &st) != 0) {
				errno_t error = get_errno();
				(void)close(infd);
				(void)close(out2fd_fd);
				(void)unlink(out2mem_outfilename);
				warn("failed to stat input file '%" PRIsT "': %" PRIsT "\n",
				     filename, tstrerror(error));
				exit(1);
			}
			infd_stat = &st;
		}
		if (opt_keep_mtime) {
			/* Copy last-modified time from `infd' to `out2fd_fd' */
#ifdef TARGET_NT
			if (!SetFileTime(out2fd_fd, NULL, NULL, &infd_stat->ftLastWriteTime))
#else /* TARGET_NT */
			struct timespec ut[2];
			ut[0].tv_sec  = infd_stat->st_atime;
			ut[0].tv_nsec = UTIME_OMIT;
			ut[1].tv_sec  = infd_stat->st_mtime;
#ifdef st_mtime /* Assume: '#define st_mtime st_mtim.tv_sec' */
			ut[1].tv_nsec = infd_stat->st_mtim.tv_nsec;
#else /* st_mtime */
			ut[1].tv_nsec = infd_stat->st_mtimensec;
#endif /* !st_mtime */
			if (futimens(out2fd_fd, ut) != 0)
#endif /* !TARGET_NT */
			{
				errno_t error = get_errno();
				(void)close(infd);
				(void)close(out2fd_fd);
				(void)unlink(out2mem_outfilename);
				warn("failed to set last-modified time of '%" PRIsT "': %" PRIsT "\n",
				     out2mem_outfilename, tstrerror(error));
				exit(1);
			}
		}

#ifndef TARGET_NT
		if (fchown(out2fd_fd, infd_stat->st_uid, infd_stat->st_gid) != 0) {
			errno_t error = get_errno();
			(void)close(infd);
			(void)close(out2fd_fd);
			(void)unlink(out2mem_outfilename);
			warn("failed to set owner/group of '%" PRIsT "': %" PRIsT "\n",
			     out2mem_outfilename, tstrerror(error));
			exit(1);
		}
#endif /* !TARGET_NT */

		(void)close(infd);
		(void)close(out2fd_fd);
		if (unlink(filename) != 0 ||
		    rename(out2mem_outfilename, filename) != 0) {
			errno_t error = get_errno();
			(void)unlink(out2mem_outfilename);
			warn("failed to replace file '%" PRIsT "': %" PRIsT "\n",
			     filename, tstrerror(error));
			exit(1);
		}
		free(out2mem_outfilename);
	} else {
		close(infd);
		assert(out == &out2mem_fun);
	}
	free(out2mem_buf);
}


static fd_t open_file_readonly(tchar const *filename) {
#ifdef TARGET_NT
	fd_t result = CreateFileW(filename, GENERIC_READ,
	                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
	                          NULL, OPEN_EXISTING,
	                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (result == NULL || result == INVALID_HANDLE_VALUE)
#else /* TARGET_NT */
	fd_t result = open(filename, O_RDONLY);
	if (result < 0)
#endif /* !TARGET_NT */
	{
		warn("failed to open '%" PRIsT "': %" PRIsT "\n",
		     filename, tstrerror(get_errno()));
		exit(1);
	}
	return result;
}

/* Do inplace replacements with `filename' */
static void dofilename(tchar const *filename) {
	fd_t infd = open_file_readonly(filename);
	dofilename_with_fd(infd, filename, NULL);
}


static void dodir(tchar const *dirpath);
static void dodirent(tchar const *dirpath, struct_tdirent *ent) {
#ifndef TARGET_NT
#ifndef HAVE_DIRENT_D_TYPE
	struct_stat fullname_st;
#endif /* !HAVE_DIRENT_D_TYPE */
#endif /* !TARGET_NT */
	bool isreg;
	size_t dirpath_len;
	size_t entname_len;
	tchar *fullname, *p;
#ifdef TARGET_NT
	if (ent->dwFileAttributes & (FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_REPARSE_POINT))
		return;
	isreg = !(ent->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
#elif defined(HAVE_DIRENT_D_TYPE)
	if (ent->d_type != DT_REG && ent->d_type != DT_DIR)
		return;
	isreg = ent->d_type == DT_REG;
#endif /* HAVE_DIRENT_D_TYPE */

	dirpath_len = tstrlen(dirpath);
	while (dirpath_len && tissep(dirpath[dirpath_len - 1]))
		--dirpath_len;
	entname_len = tstrlen(ent->d_name);
	fullname = (tchar *)xmalloc((dirpath_len + 1 + entname_len + 1) * sizeof(tchar));
	p = (tchar *)memcpy(fullname, dirpath, dirpath_len * sizeof(tchar));
	p += dirpath_len;
	while (p > fullname && tissep(p[-1]))
		--p;
	*p++ = TCSEP;
	p = (tchar *)memcpy(p, ent->d_name, entname_len * sizeof(tchar));
	p += entname_len;
	*p++ = T('\0');

#ifndef TARGET_NT
#ifndef HAVE_DIRENT_D_TYPE
	if (stat(fullname, &fullname_st) != 0) {
		warn("failed to stat '%" PRIsT "': %" PRIsT "\n",
		     fullname, tstrerror(get_errno()));
		exit(1);
	}
	if (!S_ISDIR(fullname_st.st_mode) && !S_ISREG(fullname_st.st_mode))
		goto done;
	isreg = S_ISREG(fullname_st.st_mode);
#endif /* !HAVE_DIRENT_D_TYPE */
#endif /* !TARGET_NT */

	/* If it's a directory, do a recursive scan. */
	if (!isreg) {
		dodir(fullname);
		goto done;
	}

	/* If we're working with an extension whitelist,
	 * check  if  `ent->d_name'  has  one  of  them! */
	if (opt_ext != NULL) {
		tchar const *ext = tstrrchr(ent->d_name, T('.'));
		if (ext == NULL)
			ext = T("");
		else {
			++ext;
		}
		if (!tlistcontains(opt_ext, ext))
			goto done;
	}

	/* Process the file. */
	dofilename(fullname); /* TODO: pass fullname_st */
done:
	free(fullname);
}

#ifndef TARGET_NT
static void dodir_withdir(tchar const *dirpath, DIR *dir) {
	for (;;) {
		struct_tdirent *ent;
		set_errno(0);
		ent = readdir(dir);
		if (!ent)
			break;
		if (tstrcmp(ent->d_name, T(".")) == 0)
			continue;
		if (tstrcmp(ent->d_name, T("..")) == 0)
			continue;
		dodirent(dirpath, ent);
		if (!opt_max)
			return;
	}
	if (get_errno() != 0) {
		warn("failed to read directory '%" PRIsT "': %" PRIsT "\n",
		     dirpath, tstrerror(get_errno()));
		exit(1);
	}
}

static void dodir_withfd(fd_t dirfd, tchar const *dirpath) {
	DIR *dir = fdopendir(dirfd);
	if (!dir) {
		warn("failed to open directory '%" PRIsT "': %" PRIsT "\n",
		     dirpath, tstrerror(get_errno()));
		exit(1);
	}
	dodir_withdir(dirpath, dir);
	(void)closedir(dir);
}
#endif /* !TARGET_NT */

static void dodir(tchar const *dirpath) {
#ifdef TARGET_NT
	size_t dirpath_len = tstrlen(dirpath);
	tchar *dirpath_find = (tchar *)xmalloc((dirpath_len + 4) * sizeof(tchar));
	tchar *ptr = (tchar *)memcpy(dirpath_find, dirpath, dirpath_len * sizeof(tchar));
	struct_tdirent ent;
	DIRp dir;
	ptr += dirpath_len;
	*ptr++ = T('\\');
	*ptr++ = T('*');
	*ptr++ = T('\0');
	dir = FindFirstFileW(dirpath_find, &ent);
	if (dir == INVALID_HANDLE_VALUE) {
		errno_t error = get_errno();
		free(dirpath_find);
		if (error != ERROR_NO_MORE_FILES) {
			warn("failed to open directory '%" PRIsT "': %" PRIsT "\n",
			     dirpath, tstrerror(error));
			exit(1);
		}
		return;
	}
	free(dirpath_find);
	for (;;) {
		if (tstrcmp(ent.d_name, T(".")) == 0)
			goto nextent;
		if (tstrcmp(ent.d_name, T("..")) == 0)
			goto nextent;
		dodirent(dirpath, &ent);
		if (!opt_max)
			break;
nextent:
		if (!FindNextFileW(dir, &ent)) {
			errno_t error = get_errno();
			if (error != ERROR_NO_MORE_FILES) {
				warn("failed to read directory '%" PRIsT "': %" PRIsT "\n",
				     dirpath, tstrerror(error));
				exit(1);
			}
			break;
		}
	}
	(void)closedir(dir);
#else /* TARGET_NT */
	DIR *dir = opendir(dirpath);
	if (!dir) {
		warn("failed to open directory '%" PRIsT "': %" PRIsT "\n",
		     dirpath, tstrerror(get_errno()));
		exit(1);
	}
	dodir_withdir(dirpath, dir);
	(void)closedir(dir);
#endif /* !TARGET_NT */
}


static void dorecursive(tchar const *file_or_path) {
	struct_stat st;
	fd_t infd = open_file_readonly(file_or_path);
	if (fstat(infd, &st) != 0) {
		warn("failed to stat input file '%" PRIsT "': %" PRIsT "\n",
		     file_or_path, strerror(get_errno()));
		exit(1);
	}
#ifdef TARGET_NT
	if (st.dwFileAttributes & (FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_REPARSE_POINT)) {
		/* Ignore... */
		(void)close(infd);
	} else if (st.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
		/* Traverse directory. */
		(void)close(infd);
		dodir(file_or_path);
	} else {
		/* Handle a file. */
		dofilename_with_fd(infd, file_or_path, &st);
	}
#else /* TARGET_NT */
	if (S_ISREG(st.st_mode)) {
		/* Handle a file. */
		dofilename_with_fd(infd, file_or_path, &st);
	} else if (S_ISDIR(st.st_mode)) {
		/* Traverse directory. */
		dodir_withfd(infd, file_or_path);
	}
#endif /* !TARGET_NT */
}




/* Print program usage */
static void usage(void) {
	printf("usage: %1$" PRIsT " [OPTIONS] [--] FIND REPLACE [FIND REPLACE...]\n"
	       "       %1$" PRIsT " [OPTIONS] [--] FIND REPLACE [FIND REPLACE...] FILE\n"
	       "       %1$" PRIsT " [OPTIONS] [--] FIND REPLACE [FIND REPLACE...] -- FILES...\n"
	       "       %1$" PRIsT " [OPTIONS] -f [--] FIND\n"
	       "       %1$" PRIsT " [OPTIONS] -f [--] FIND [FIND...] -- FILES...\n"
	       "Find and inplace-replace strings in files or stdin\n"
	       "Available options are:\n"
	       "         --help        Display this help\n"
	       "   -f    --find        Find matches and print 'file:line:col:nchars:pattern\\n'\n"
	       "                       'line' and 'col' are 1-based; 'pattern' is the original FIND\n"
	       "   -i    --icase       Ignore casing during matching\n"
	       "   -b    --bound       Match whole words\n"
#ifdef HAVE_REGEX_H
	       "   -r    --regex       FIND are regular expressions\n"
#endif /* HAVE_REGEX_H */
	       "   -e    --escape      Process C-style backslash-escape sequences in FIND and REPLACE\n"
	       "   -t    --keep-mtime  Preserve last-modified timestamps\n"
	       "   -R    --recursive   Accept directories and recursively scan them for files\n"
	       "         --ext=list    Skip files with extension not in 'list' (whose contents are ':'-separated)\n"
	       "   -n N  --max=N       Stop after N matches\n"
	       "", opt_progname);
}

int tmain(int argc, tchar *argv[]) {
	if (argc) {
		/* Skip program name. */
		opt_progname = *argv++;
		--argc;
	}

#ifdef TARGET_NT
	/* Needed so `wcrtomb()' converts to utf-8
	 * NOTE: Because  this specifies how  find/replace patterns are encoded,
	 *       and thus specifies the byte-sequences we search for and  insert
	 *       into files, this also sets the encoding we expect files to use. */
	setlocale(LC_ALL, ".UTF8");
#endif /* TARGET_NT */

	/* Parse options. */
	for (; argc; --argc, ++argv) {
		tchar *arg = *argv;
		if (arg[0] != T('-') || tstrcmp(arg, T("--")) == 0)
			break;
		++arg; /* Skip leading '-' */
		if (*arg == T('-')) {
			/* Long options. */
			++arg; /* Skip second '-' */
			if (tstrcmp(arg, T("help")) == 0) {
				usage();
				return 0;
			} else if (tstrcmp(arg, T("icase")) == 0) {
				opt_icase = true;
			} else if (tstrcmp(arg, T("bound")) == 0) {
				opt_bound = true;
#ifdef HAVE_REGEX_H
			} else if (tstrcmp(arg, T("regex")) == 0) {
				opt_regex = true;
#endif /* HAVE_REGEX_H */
			} else if (tstrcmp(arg, T("recursive")) == 0) {
				opt_recursive = true;
			} else if (tstrcmp(arg, T("escape")) == 0) {
				opt_escape = true;
			} else if (tstrcmp(arg, T("keep-mtime")) == 0) {
				opt_keep_mtime = true;
			} else if (tstrcmp(arg, T("find")) == 0) {
				opt_find = true;
			} else if (memcmp(arg, T("ext="), 4 * sizeof(tchar)) == 0) {
				arg += 4;
				if (!*arg) {
					warn("empty extension list. If you want to scan files without extensions, use '--ext=:'\n");
					return 1;
				}
				setextlist(arg);
			} else if (memcmp(arg, T("max="), 4 * sizeof(tchar)) == 0) {
				opt_max = (size_t)tatol(arg + 4);
			} else {
				warn("unknown argument: '%" PRIsT "'\n", arg - 2);
				return 1;
			}
			continue;
		}
		do {
			switch (*arg) {
			case T('i'): opt_icase = true; break;
			case T('b'): opt_bound = true; break;
#ifdef HAVE_REGEX_H
			case T('r'): opt_regex = true; break;
#endif /* HAVE_REGEX_H */
			case T('R'): opt_recursive = true; break;
			case T('e'): opt_escape = true; break;
			case T('t'): opt_keep_mtime = true; break;
			case T('f'): opt_find = true; break;
			case T('n'):
				if (arg[1] || argc < 2 || argv[1][0] == T('-'))
					goto warn_unknown_flag;
				/* Consume the next argument as max-count-value. */
				--argc;
				opt_max = (size_t)tatol(*++argv);
				break;
			default:
warn_unknown_flag:
				warn("unknown flag: '%" PRIcT "'\n", *arg);
				return 1;
			}
		} while (*++arg != T('\0'));
	}

	/* Consume "--" marker. */
	if (argc && tstrcmp(argv[0], T("--")) == 0) {
		--argc;
		++argv;
	}

	/* Parse find+replace patterns */
	while (argc >= (opt_find ? 1 : 2)) {
		struct find *pat;
		tchar *arg = *argv;
		tchar *used_arg;
		size_t used_arg_len;
		if (tstrcmp(arg, T("--")) == 0)
			break;

		/* Consume the find-pattern argument */
		--argc;
		++argv;

		/* If requested, unescape escape sequences from the find-pattern */
		used_arg     = arg;
		used_arg_len = tstrlen(used_arg);
		if (opt_escape) {
			used_arg     = xtstrdup(arg);
			used_arg_len = tunescape(used_arg);
		}

		/* Allocate+initialize a find-pattern descriptor */
		pat = alloc_pattern();
		pat->f_pattern = arg;
#ifdef HAVE_REGEX_H
		if (opt_regex) {
			int error, flags;
			flags = REG_EXTENDED | REG_NEWLINE;
			if (opt_icase)
				flags |= REG_ICASE;
			if (opt_bound) {
				/* Replace 'used_arg' with '\b{}\b' to force whole-word matching */
				tchar *new_used_arg = (tchar *)xmalloc((used_arg_len + 5) * sizeof(tchar));
				tchar *ptr = new_used_arg;
				*ptr++ = T('\\');
				*ptr++ = T('b');
				ptr = (tchar *)memcpy(ptr, used_arg, used_arg_len * sizeof(tchar));
				ptr += used_arg_len;
				*ptr++ = T('\\');
				*ptr++ = T('b');
				*ptr++ = T('\0');
				if (used_arg != arg)
					free(used_arg);
				used_arg = new_used_arg;
			}
			error = regcomp(pat->f_xfind, used_arg, flags);
			if (error != 0) {
				/* Invalid regular expression... */
				size_t rlen;
				tchar *rbuf;
				rlen = regerror(error, pat->f_xfind, NULL, 0) + 1;
				rbuf = (tchar *)xmalloc(rlen * sizeof(tchar));
				regerror(error, pat->f_xfind, rbuf, rlen + 1);
				warn("regex error in '%s': %s\n", used_arg, rbuf);
				return 1;
			}
		} else
#endif /* HAVE_REGEX_H */
		{
#ifdef TARGET_NT
			pat->f_find = (byte_t *)xwcs2mbs(used_arg, used_arg_len, &pat->f_findlen);
#else /* TARGET_NT */
			pat->f_find    = (byte_t *)used_arg;
			pat->f_findlen = used_arg_len;
#endif /* !TARGET_NT */
			if (min_find_len > pat->f_findlen)
				min_find_len = pat->f_findlen;
			if (max_find_len < pat->f_findlen)
				max_find_len = pat->f_findlen;
		}
		if (opt_find)
			continue; /* No replacement patterns are provided. */

		/* Parse replacement pattern. */
		if (!argc || tstrcmp(argv[0], T("--")) == 0) {
			warn("no replacement given for '%" PRIsT "'\n", arg);
			return 1;
		}

		/* If requested, unescape escape sequences in the replace-pattern
		 * Note that in this case, we also  do this if find was a  regex! */
		used_arg     = argv[0];
		used_arg_len = tstrlen(used_arg);
#ifdef HAVE_REGEX_H
		if (opt_escape || opt_regex)
#else /* HAVE_REGEX_H */
		if (opt_escape)
#endif /* !HAVE_REGEX_H */
		{
			used_arg_len = tunescape(used_arg);
		}
#ifdef TARGET_NT
		pat->f_repl = (byte_t *)xwcs2mbs(used_arg, used_arg_len, &pat->f_repllen);
#else /* TARGET_NT */
		pat->f_repl    = used_arg;
		pat->f_repllen = used_arg_len;
#endif /* !TARGET_NT */
		--argc;
		++argv;
	}

	/* Special case: when matching whole words, all patterns
	 * have an  implicit  leading/trailing  semi-whitespace! */
	if (opt_bound)
		max_find_len += 2;

	/* Consume "--" marker. */
	if (argc && tstrcmp(argv[0], T("--")) == 0) {
		--argc;
		++argv;
	}

	if (argc == 0) {
		/* Special case: process+replace text from stdin */
		if (opt_find) {
			out2lc_afterCR = false;
			out2lc_file    = T("{stdin}");
			out2lc_line    = 0;
			out2lc_col     = 0;
			setout(&out2lc_fun);
		} else {
			out2fd_fd = STDOUT_FILENO;
			setout(&out2fd_fun);
		}
		dofd(STDIN_FILENO);
	} else if (!opt_recursive) {
		/* Without recursion, simply treat all given files as regular files.
		 * If one of them  ends up being a  directory, us trying to  read(2)
		 * from it will simply fail with an error! */
		for (; argc; --argc, ++argv) {
			if (!opt_max)
				break;
			dofilename(*argv);
		}
	} else {
		/* Because of recursion we have to do special treatment of directories. */
		for (; argc; --argc, ++argv) {
			if (!opt_max)
				break;
			dorecursive(*argv);
		}
	}

	return 0;
}


#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* !GUARD_SREPLACE_MAIN_C */
