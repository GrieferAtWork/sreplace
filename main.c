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

#include <sys/stat.h>

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(DT_DIR) && defined(DT_REG)
#define HAVE_DIRENT_D_TYPE
#endif /* DT_DIR && DT_REG */

#ifndef __USE_KOS
#define memmoveup   memmove
#define memmovedown memmove
#endif /* !__USE_KOS */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Program name */
static char const *opt_progname = "sreplace";

static void warn(char const *format, ...) {
	va_list args;
	va_start(args, format);
	fprintf(stderr, "%s: ", opt_progname);
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

static char *xstrdup(char const *str) {
	size_t ssize = (strlen(str) + 1) * sizeof(char);
	char *result = (char *)xmalloc(ssize);
	return (char *)memcpy(result, str, ssize);
}




/* Commandline options */
static bool opt_icase     = false;
static bool opt_bound     = false;
static bool opt_regex     = false;
static bool opt_recursive = false;
static bool opt_escape    = false;
static bool opt_keep_mtime  = false;
static bool opt_find      = false;
static char *opt_ext      = NULL; /* Elements don't have leading '.' */
static size_t opt_max     = (size_t)-1;

static void strdel(char *pch, size_t n) {
	size_t len = strlen(pch);
	assert(len >= n);
	len -= n;
	memmovedown(pch, pch + n, len * sizeof(char));
	pch[len] = '\0';
}

static void setextlist(char const *list) {
	char *n;
	free(opt_ext);
	opt_ext = n = xstrdup(list);
	/* Delete leading '.' from each element of `list' */
	while (*n) {
		if (*n == '.')
			strdel(n, 1);
		n = strchr(n, ':');
		if (!n)
			break;
		++n;
	}
}

static bool listcontains(char const *list, char const *item) {
	size_t itemlen = strlen(item);
	while (*list) {
		if (memcmp(list, item, itemlen * sizeof(char)) == 0 &&
		    (list[itemlen] == ':' || list[itemlen] == '\0'))
			return true;
		list = strchr(list, ':');
		if (!list)
			break;
		++list;
	}
	return false;
}


struct find {
	char    *f_pattern; /* [1..1] Find-mattern */
	char    *f_find;    /* [0..1][owned] String to find (or NULL if using a regular expression). */
	char    *f_repl;    /* [0..1][owned] Replacement string (or NULL to retain existing text). */
	regex_t *f_xfind;   /* [1..1][owned][valid_if(f_find == NULL)] Regular expression for string finding. */
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
	if (opt_regex)
		result->f_xfind = (regex_t *)xmalloc(sizeof(regex_t));
	return result;
}


static void unescape(char *str) {
	char ch, *dst = str;
	while ((ch = *str++) != '\0') {
		if (ch == '\\') {
			ch = *str++;
			switch (ch) {
			case 'a': ch = 7; break;
			case 'b': ch = 8; break;
			case 't': ch = 9; break;
			case 'n': ch = 10; break;
			case 'v': ch = 11; break;
			case 'f': ch = 12; break;
			case 'r': ch = 13; break;
			case 'e': ch = 27; break;
			default:
				if (ch >= '0' && ch <= '7') {
					unsigned char b = ch - '0';
					unsigned int n = 1;
					for (; n < 3; ++n, ++str) {
						ch = *str;
						if (!(ch >= '0' && ch <= '7'))
							break;
						b <<= 3;
						b |= ch - '0';
					}
					ch = (char)b;
				}
				break;
			}
			*dst++ = ch;
			continue;
		}
		*dst++ = ch;
	}
}





/* Output function for (possibly modified) file data. */
static void (*out)(void const *buf, size_t len) = NULL;

/* Set to true if `out' is about to be called with modified data. */
static bool out_changed = false;
#define setout(out_) (out_changed = false, out = (out_))


/* Accumulate line/column information. */
static char const *out2lc_file  = NULL;  /* Filename. */
static unsigned int out2lc_line = 0;     /* Line number (0-based) */
static unsigned int out2lc_col  = 0;     /* Column number (0-based) */
static bool out2lc_afterCR      = false; /* Last character was CR */
static void out2lc_fun(void const *buf, size_t len) {
	unsigned char ch;
	unsigned char const *p   = (unsigned char const *)buf;
	unsigned char const *end = p + len / sizeof(char);
	if (out2lc_afterCR) {
do_handle_cr:
		if (p < end) {
			out2lc_afterCR = false;
			ch = *p++;
			if (ch != '\n')
				goto handle_ch;
		}
	}
	while (p < end) {
		ch = *p++;
handle_ch:
		if (ch == '\r' || ch == '\n') {
			++out2lc_line;
			out2lc_col = 0;
			if (ch == '\r') {
				out2lc_afterCR = true;
				goto do_handle_cr;
			}
			continue;
		}
		++out2lc_col;
	}
}

static void out2lc_match(struct find *f, size_t match_len) {
	printf("%s:%u:%u:%lu:%s\n",
	       out2lc_file, out2lc_line + 1, out2lc_col + 1,
	       (unsigned long)match_len, f->f_pattern);
}


struct inbuf {
	char  *ib_buf; /* [0..ib_len+ib_avl][owned] Buffer base */
	size_t ib_len; /* Used buffer size */
	size_t ib_avl; /* Remaining (free) buffer size */
	int    ib_ref; /* Reg-ex flags (REG_NOTEOL is cleared on EOF) */
};

static struct find *regex_find(char const *str, size_t len, regmatch_t *match, int flags) {
	size_t i;
	for (i = 0; i < patterncnt; ++i) {
		struct find *f = &patternvec[i];
		int status;
		match->rm_so = 0;
		match->rm_eo = len;
		status = regexec(f->f_xfind, str, 1, match, flags);
		if (status == 0) {
			regmatch_t other_match;
			for (++i; i < patterncnt; ++i) {
				struct find *other_f = &patternvec[i];
				other_match.rm_so = 0;
				other_match.rm_eo = len;
				status = regexec(other_f->f_xfind, str, 1, &other_match, flags);
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

#ifndef __USE_KOS
#ifndef __USE_KOS
#define memcasecmp my_memcasecmp
static int memcasecmp(void const *s1, void const *s2, size_t n_bytes) {
	unsigned char const *p1 = (unsigned char const *)s1;
	unsigned char const *p2 = (unsigned char const *)s2;
	unsigned char v1, v2;
	v1 = v2 = 0;
	while (n_bytes--) {
		v1 = *p1++;
		v2 = *p2++;
		if (v1 != v2) {
			v1 = (unsigned char)tolower(v1);
			v2 = (unsigned char)tolower(v2);
			if (v1 != v2)
				break;
		}
	}
	return (int)v1 - (int)v2;
}
#endif /* !__USE_KOS */

#define memcasemem my_memcasemem
static void *memcasemem(void const *haystack, size_t haystacklen,
                        void const *needle, size_t needlelen) {
	unsigned char *candidate, marker;
	unsigned char *hayend;
	if (!needlelen)
		return (unsigned char *)haystack + haystacklen;
	if (needlelen > haystacklen)
		return NULL;
	haystacklen -= (needlelen - 1);
	marker       = (unsigned char)tolower(*(unsigned char *)needle);
	hayend       = (unsigned char *)haystack + haystacklen;
	for (;;) {
		for (candidate = (unsigned char *)haystack; candidate < hayend; ++candidate) {
			unsigned char b = *candidate;
			if (b == marker || (unsigned char)tolower(b) == marker)
				goto got_candidate;
		}
		break;
got_candidate:
		if (memcasecmp(candidate, needle, needlelen) == 0)
			return (void *)candidate;
		++candidate;
		haystacklen = ((unsigned char *)haystack + haystacklen) - candidate;
		haystack    = (void const *)candidate;
	}
	return NULL;
}
#endif /* !__USE_KOS */


static struct find *normal_find(char const *str, size_t len, size_t match[2], int flags) {
	size_t i;
	struct find *result = NULL;
	for (i = 0; i < patterncnt; ++i) {
		struct find *f = &patternvec[i];
		char *pos;
		char const *used_str;
		size_t used_len;
		used_str = str;
		used_len = len;
again_search:
		pos = opt_icase ? (char *)memcasemem(used_str, used_len, f->f_find, f->f_findlen)
		                      : (char *)memmem(used_str, used_len, f->f_find, f->f_findlen);
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
					char *epos = pos + f->f_findlen;
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
static bool inbuf_readfd(struct inbuf *self, int fd, size_t maxread) {
	bool read_something = false;
	while (maxread && (self->ib_ref & REG_NOTEOL)) {
		ssize_t readsize;
		size_t reqsize = 64 * 1024;
		if (reqsize > maxread)
			reqsize = maxread;
		if (reqsize > self->ib_avl) {
			if (self->ib_avl < 512) {
				char *buf;
				size_t newsize = ((self->ib_len + self->ib_avl) << 1) | 1;
				size_t new_avl = 0;
				if (newsize > self->ib_len)
					new_avl = newsize - self->ib_len;
				if (new_avl < reqsize) {
					newsize = self->ib_len + reqsize;
					if (newsize < self->ib_len)
						newsize = (size_t)-1;
				}
				buf = (char *)realloc(self->ib_buf, newsize);
				if (!buf) {
					newsize = self->ib_len + 1;
					buf = (char *)xrealloc(self->ib_buf, newsize);
				}
				self->ib_buf = buf;
				self->ib_avl = newsize - self->ib_len;
			}
			reqsize = self->ib_avl;
		}
		assert(reqsize <= self->ib_avl);
		readsize = read(fd, self->ib_buf + self->ib_len, reqsize);
		if (readsize <= 0) {
			if (readsize == 0) {
				if (reqsize)
					self->ib_ref &= ~REG_NOTEOL;
				break;
			}
			warn("failed to read data: %s\n", strerror(errno));
			exit(1);
		}
		self->ib_len += (size_t)readsize;
		self->ib_avl -= (size_t)readsize;
		read_something = true;
	}
	return read_something;
}


/* Read data from `infd', perform replacements, and `OUT()' modified data. */
static void dofd(int infd) {
	struct inbuf ib;
	ib.ib_buf = NULL;
	ib.ib_len = 0;
	ib.ib_avl = 0;
	ib.ib_ref = REG_STARTEND | REG_NOTEOL;

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
				/* TODO: Handle `opt_max' */

				/* Consume text until end of match. */
				ib.ib_ref |= REG_NOTBOL; /* No longer at start of file */
				ib.ib_len -= match.rm_eo;
				memmovedown(ib.ib_buf, ib.ib_buf + match.rm_eo,
				            ib.ib_len * sizeof(char));
				ib.ib_avl += match.rm_eo;
				goto again_re_find;
			}
		}
	} else {
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
				/* TODO: Handle `opt_max' */

				/* Consume text until end of match. */
				ib.ib_ref |= REG_NOTBOL; /* No longer at start of file */
				ib.ib_len -= match[1];
				memmovedown(ib.ib_buf, ib.ib_buf + match[1],
				            ib.ib_len * sizeof(char));
				ib.ib_avl += match[1];
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
				memmovedown(ib.ib_buf, ib.ib_buf + skipsize,
				            ib.ib_len * sizeof(char));
				ib.ib_avl += skipsize;
			}
		}
	}
	/* Output all remaining data beyond the last match. */
	(*out)(ib.ib_buf, ib.ib_len);
/*done:*/
	free(ib.ib_buf);
}




static int out2fd_fd = -1;
static void out2fd_fun(void const *buf, size_t len) {
	ssize_t ok;
	if (!len)
		return;
	while ((ok = write(out2fd_fd, buf, len)) >= 0) {
		if ((size_t)ok >= len)
			break;
		len -= ok;
		buf = (unsigned char *)buf + len;
	}
	/*if (ok < 0) {
		warn("write failed: %s\n", strerror(errno));
		exit(1);
	}*/
}



/* Output-to-memory buffer */
static void *out2mem_buf  = NULL; /* [0..out2mem_use+out2mem_avl][owned] Buffer */
static size_t out2mem_use = 0;    /* Used leading bytes */
static size_t out2mem_avl = 0;    /* Available free space */

static int out2mem_infd               = -1;   /* Input file handle. */
static char const *out2mem_infilename = NULL; /* [1..1] Input filename. */
static char *out2mem_outfilename      = NULL; /* [0..1] Output filename. */
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
	memcpy((unsigned char *)out2mem_buf + out2mem_use, buf, len);
	out2mem_use += len;
	out2mem_avl -= len;
	if (out_changed) {
		/* Special case: something changed, so we have to create a new file. */
		struct stat st;
		int outfd;
		size_t inlen  = strlen(out2mem_infilename);
		size_t outlen = inlen + 4; /* ".new" */
		char *outname = (char *)xmalloc((outlen + 1) * sizeof(char));
		memcpy(outname, out2mem_infilename, inlen * sizeof(char));
		out2mem_outfilename = outname;
		outname += inlen;
		strcpy(outname, ".new");
		if (fstat(out2mem_infd, &st) != 0) {
			warn("failed to stat input file '%s': %s\n",
			     out2mem_infilename, strerror(errno));
			exit(1);
		}

		/* Open the new output file. */
		outfd = open(out2mem_outfilename,
		             O_WRONLY | O_CREAT | O_EXCL,
		             st.st_mode & 0777);
		if (outfd < 0) {
			warn("failed to create output file '%s': %s\n",
			     out2mem_outfilename, strerror(errno));
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
static void dofilename_with_fd(/*inherit*/ int infd, char const *filename,
                               struct stat *infd_stat) {
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
		/* Output file was created, so we have to replace the input file. */
		assert(out == &out2fd_fun);
		if (opt_keep_mtime) {
			/* Copy last-modified time from `infd' to `out2fd_fd' */
			struct stat st;
			struct timespec ut[2];
			if (!infd_stat) {
				if (fstat(infd, &st) != 0) {
					int error = errno;
					close(infd);
					close(out2fd_fd);
					unlink(out2mem_outfilename);
					warn("failed to stat input file '%s': %s\n",
					     filename, strerror(error));
					exit(1);
				}
				infd_stat = &st;
			}
			ut[0].tv_sec  = infd_stat->st_atime;
			ut[0].tv_nsec = UTIME_OMIT;
			ut[1].tv_sec  = infd_stat->st_mtime;
#ifdef st_mtime /* Assume: '#define st_mtime st_mtim.tv_sec' */
			ut[1].tv_nsec = infd_stat->st_mtim.tv_nsec;
#else /* st_mtime */
			ut[1].tv_nsec = infd_stat->st_mtimensec;
#endif /* !st_mtime */
			if (futimens(out2fd_fd, ut) != 0) {
				int error = errno;
				close(infd);
				close(out2fd_fd);
				unlink(out2mem_outfilename);
				warn("failed to set last-modified time of '%s': %s\n",
				     out2mem_outfilename, strerror(error));
				exit(1);
			}
		}
		close(infd);
		close(out2fd_fd);
		if (unlink(filename) != 0 ||
		    rename(out2mem_outfilename, filename) != 0) {
			int error = errno;
			unlink(out2mem_outfilename);
			warn("failed to replace file '%s': %s\n",
			     filename, strerror(error));
			exit(1);
		}
		free(out2mem_outfilename);
	} else {
		close(infd);
		assert(out == &out2mem_fun);
	}
	free(out2mem_buf);
}


static int open_file_readonly(char const *filename) {
	int result = open(filename, O_RDONLY);
	if (result < 0) {
		warn("failed to open '%s': '%s'\n", filename, strerror(errno));
		exit(1);
	}
	return result;
}

/* Do inplace replacements with `filename' */
static void dofilename(char const *filename) {
	int infd = open_file_readonly(filename);
	dofilename_with_fd(infd, filename, NULL);
}


static void dodir(char const *dirpath);
static void dodirent(char const *dirpath, struct dirent *ent) {
#ifndef HAVE_DIRENT_D_TYPE
	struct stat fullname_st;
#endif /* !HAVE_DIRENT_D_TYPE */
	bool isreg;
	size_t dirpath_len;
	size_t entname_len;
	char *fullname, *p;
#ifdef HAVE_DIRENT_D_TYPE
	if (ent->d_type != DT_REG && ent->d_type != DT_DIR)
		return;
	isreg = ent->d_type == DT_REG;
#endif /* HAVE_DIRENT_D_TYPE */

	dirpath_len = strlen(dirpath);
	while (dirpath_len && dirpath[dirpath_len - 1] == '/')
		--dirpath_len;
	entname_len = strlen(ent->d_name);
	fullname = (char *)xmalloc((dirpath_len + 1 + entname_len + 1) * sizeof(char));
	p = (char *)memcpy(fullname, dirpath, dirpath_len * sizeof(char));
	p += dirpath_len;
	*p++ = '/';
	p = (char *)memcpy(p, ent->d_name, entname_len * sizeof(char));
	p += entname_len;
	*p++ = '\0';

#ifndef HAVE_DIRENT_D_TYPE
	if (stat(fullname, &fullname_st) != 0) {
		warn("failed to stat '%s': %s\n",
		     fullname, strerror(errno));
		exit(1);
	}
	if (!S_ISDIR(fullname_st.st_mode) && !S_ISREG(fullname_st.st_mode))
		goto done;
	isreg = S_ISREG(fullname_st.st_mode);
#endif /* !HAVE_DIRENT_D_TYPE */

	/* If it's a directory, do a recursive scan. */
	if (!isreg) {
		dodir(fullname);
		goto done;
	}

	/* If we're working with an extension whitelist,
	 * check  if  `ent->d_name'  has  one  of  them! */
	if (opt_ext != NULL) {
		char const *ext = strrchr(ent->d_name, '.');
		if (ext == NULL)
			ext = "";
		else {
			++ext;
		}
		if (!listcontains(opt_ext, ext))
			goto done;
	}

	/* Process the file. */
	dofilename(fullname);
done:
	free(fullname);
}

static void dodir_withdir(char const *dirpath, DIR *dir) {
	for (;;) {
		struct dirent *ent;
		errno = 0;
		ent   = readdir(dir);
		if (!ent)
			break;
		if (strcmp(ent->d_name, ".") == 0)
			continue;
		if (strcmp(ent->d_name, "..") == 0)
			continue;
		dodirent(dirpath, ent);
	}
	if (errno != 0) {
		warn("failed to read directory '%s': %s\n",
		     dirpath, strerror(errno));
		exit(1);
	}
}

static void dodir_withfd(int dirfd, char const *dirpath) {
	DIR *dir = fdopendir(dirfd);
	if (!dir) {
		warn("failed to open directory '%s': %s\n",
		     dirpath, strerror(errno));
		exit(1);
	}
	dodir_withdir(dirpath, dir);
	closedir(dir);
}

static void dodir(char const *dirpath) {
	DIR *dir = opendir(dirpath);
	if (!dir) {
		warn("failed to open directory '%s': %s\n",
		     dirpath, strerror(errno));
		exit(1);
	}
	dodir_withdir(dirpath, dir);
	closedir(dir);
}


static void dorecursive(char const *file_or_path) {
	struct stat st;
	int infd = open_file_readonly(file_or_path);
	if (fstat(infd, &st) != 0) {
		warn("failed to stat input file '%s': %s\n",
		     file_or_path, strerror(errno));
		exit(1);
	}
	if (S_ISREG(st.st_mode)) {
		/* Handle a file. */
		dofilename_with_fd(infd, file_or_path, &st);
	} else if (S_ISDIR(st.st_mode)) {
		/* Traverse directory. */
		dodir_withfd(infd, file_or_path);
	}
}




/* Print program usage */
static void usage(void) {
	printf("usage: %1$s [OPTIONS] [--] FIND REPLACE [FIND REPLACE...]\n"
	       "       %1$s [OPTIONS] [--] FIND REPLACE [FIND REPLACE...] FILE\n"
	       "       %1$s [OPTIONS] [--] FIND REPLACE [FIND REPLACE...] -- FILES...\n"
	       "       %1$s [OPTIONS] -f [--] FIND\n"
	       "       %1$s [OPTIONS] -f [--] FIND [FIND...] -- FILES...\n"
	       "Find and inplace-replace strings in files or stdin\n"
	       "Available options are:\n"
	       "         --help        Display this help\n"
	       "   -f    --find        Find matches and print 'file:line:col:nchars:pattern\\n'\n"
	       "                       'line' and 'col' are 1-based; 'pattern' is the original FIND\n"
	       "   -i    --icase       Ignore casing during matching\n"
	       "   -b    --bound       Match whole words\n"
	       "   -r    --regex       FIND are regular expressions\n"
	       "   -e    --escape      Process C-style backslash-escape sequences in FIND and REPLACE\n"
	       "   -t    --keep-mtime  Preserve last-modified timestamps\n"
	       "   -R    --recursive   Accept directories and recursively scan them for files\n"
	       "         --ext=list    Skip files with extension not in 'list' (whose contents are ':'-separated)\n"
	       "   -n N  --max=N       Stop after N matches\n"
	       "", opt_progname);
}

int main(int argc, char *argv[]) {
	if (argc) {
		/* Skip program name. */
		opt_progname = *argv++;
		--argc;
	}

	/* Parse options. */
	for (; argc; --argc, ++argv) {
		char *arg = *argv;
		if (arg[0] != '-' || strcmp(arg, "--") == 0)
			break;
		++arg; /* Skip leading '-' */
		if (*arg == '-') {
			/* Long options. */
			++arg; /* Skip second '-' */
			if (strcmp(arg, "help") == 0) {
				usage();
				return 0;
			} else if (strcmp(arg, "icase") == 0) {
				opt_icase = true;
			} else if (strcmp(arg, "bound") == 0) {
				opt_bound = true;
			} else if (strcmp(arg, "regex") == 0) {
				opt_regex = true;
			} else if (strcmp(arg, "recursive") == 0) {
				opt_recursive = true;
			} else if (strcmp(arg, "escape") == 0) {
				opt_escape = true;
			} else if (strcmp(arg, "keep-mtime") == 0) {
				opt_keep_mtime = true;
			} else if (strcmp(arg, "find") == 0) {
				opt_find = true;
			} else if (memcmp(arg, "ext=", 4 * sizeof(char)) == 0) {
				arg += 4;
				if (!*arg) {
					warn("empty extension list. If you want to scan files without extensions, use '--ext=:'\n");
					return 1;
				}
				setextlist(arg);
			} else if (memcmp(arg, "max=", 4 * sizeof(char)) == 0) {
				opt_max = (size_t)atol(arg + 4);
			} else {
				warn("unknown argument: '%s'\n", arg - 2);
				return 1;
			}
			continue;
		}
		do {
			switch (*arg) {
			case 'i': opt_icase = true; break;
			case 'b': opt_bound = true; break;
			case 'r': opt_regex = true; break;
			case 'R': opt_recursive = true; break;
			case 'e': opt_escape = true; break;
			case 't': opt_keep_mtime = true; break;
			case 'f': opt_find = true; break;
			case 'n':
				if (arg[1] || argc < 2 || argv[1][0] == '-')
					goto warn_unknown_flag;
				/* Consume the next argument as max-count-value. */
				--argc;
				opt_max = (size_t)atol(*++argv);
				break;
			default:
warn_unknown_flag:
				warn("unknown flag: '%c'\n", *arg);
				return 1;
			}
		} while (*++arg != '\0');
	}

	/* Consume "--" marker. */
	if (argc && strcmp(argv[0], "--") == 0) {
		--argc;
		++argv;
	}

	/* Parse find+replace patterns */
	while (argc >= (opt_find ? 1 : 2)) {
		struct find *pat;
		char *arg = *argv;
		char *used_arg;
		if (strcmp(arg, "--") == 0)
			break;

		/* Consume the find-pattern argument */
		--argc;
		++argv;

		/* If requested, unescape escape sequences from the find-pattern */
		used_arg = arg;
		if (opt_escape) {
			used_arg = xstrdup(arg);
			unescape(used_arg);
		}

		/* Allocate+initialize a find-pattern descriptor */
		pat = alloc_pattern();
		pat->f_pattern = arg;
		if (opt_regex) {
			int error, flags;
			flags = REG_EXTENDED | REG_NEWLINE;
			if (opt_icase)
				flags |= REG_ICASE;
			if (opt_bound) {
				/* Replace 'used_arg' with '\b{}\b' to force whole-word matching */
				size_t used_arg_len = strlen(used_arg);
				char *new_used_arg = (char *)xmalloc((used_arg_len + 5) * sizeof(char));
				char *ptr = new_used_arg;
				*ptr++ = '\\';
				*ptr++ = 'b';
				ptr = (char *)memcpy(ptr, used_arg, used_arg_len * sizeof(char));
				ptr += used_arg_len;
				*ptr++ = '\\';
				*ptr++ = 'b';
				*ptr++ = '\0';
				if (used_arg != arg)
					free(used_arg);
				used_arg = new_used_arg;
			}
			error = regcomp(pat->f_xfind, used_arg, flags);
			if (error != 0) {
				/* Invalid regular expression... */
				size_t rlen;
				char *rbuf;
				rlen = regerror(error, pat->f_xfind, NULL, 0) + 1;
				rbuf = (char *)xmalloc(rlen * sizeof(char));
				regerror(error, pat->f_xfind, rbuf, rlen + 1);
				warn("regex error in '%s': %s\n", used_arg, rbuf);
				return 1;
			}
		} else {
			pat->f_find    = used_arg;
			pat->f_findlen = strlen(used_arg);
			if (min_find_len > pat->f_findlen)
				min_find_len = pat->f_findlen;
			if (max_find_len < pat->f_findlen)
				max_find_len = pat->f_findlen;
		}
		if (opt_find)
			continue; /* No replacement patterns are provided. */

		/* Parse replacement pattern. */
		if (!argc || strcmp(argv[0], "--") == 0) {
			warn("not replacement given for '%s'\n", arg);
			return 1;
		}

		/* If requested, unescape escape sequences in the replace-pattern
		 * Note that in this case, we also  do this if find was a  regex! */
		if (opt_escape || opt_regex)
			unescape(argv[0]);
		pat->f_repl    = argv[0];
		pat->f_repllen = strlen(pat->f_repl);
		--argc;
		++argv;
	}

	/* Special case: when matching whole words, all patterns
	 * have an  implicit  leading/trailing  semi-whitespace! */
	if (opt_bound)
		max_find_len += 2;

	/* Consume "--" marker. */
	if (argc && strcmp(argv[0], "--") == 0) {
		--argc;
		++argv;
	}

	if (argc == 0) {
		/* Special case: process+replace text from stdin */
		out2fd_fd = STDOUT_FILENO;
		setout(&out2fd_fun);
		dofd(STDIN_FILENO);
	} else if (!opt_recursive) {
		/* Without recursion, simply treat all given files as regular files.
		 * If one of them  ends up being a  directory, us trying to  read(2)
		 * from it will simply fail with an error! */
		for (; argc; --argc, ++argv)
			dofilename(*argv);
	} else {
		/* Because of recursion we have to do special treatment of directories. */
		for (; argc; --argc, ++argv)
			dorecursive(*argv);
	}

	// filename

	return 0;
}


#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* !GUARD_SREPLACE_MAIN_C */
