/*
 * Copyright (C) 2001-2008  Marco d'Itri
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* for crypt, snprintf and strcasecmp */
#define _XOPEN_SOURCE
/*
 * _BSD_SOURCE is deprecated as of GLIBC 2.20; _DEFAULT_SOURCE should be used
 * instead. (https://lwn.net/Articles/611162/)
 */
#define _DEFAULT_SOURCE
#define _BSD_SOURCE

/* System library */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "config.h"
#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#endif
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#ifdef HAVE_XCRYPT
#include <xcrypt.h>
#include <sys/stat.h>
#endif
#ifdef HAVE_LINUX_CRYPT_GENSALT
#define _OW_SOURCE
#include <crypt.h>
#endif
#ifdef HAVE_GETTIMEOFDAY
#include <sys/time.h>
#endif

/* glibc without crypt() */
#ifndef _XOPEN_CRYPT
#include <crypt.h>
#endif

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <assert.h>

/* Application-specific */
#include "utils.h"

static const char ascii_dollar[] = { 0x24, 0x00 };
static const unsigned char cov_2char[64] = {
    /* from crypto/des/fcrypt.c */
    0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44,
    0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
    0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54,
    0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x61, 0x62,
    0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
    0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72,
    0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A
};

/* Global variables */
#ifdef HAVE_GETOPT_LONG
static const struct option longopts[] = {
    {"method",		optional_argument,	NULL, 'm'},
    /* for backward compatibility with versions < 4.7.25 (< 20080321): */
    {"hash",		optional_argument,	NULL, 'H'},
    {"help",		no_argument,		NULL, 'h'},
    {"password-fd",	required_argument,	NULL, 'P'},
    {"stdin",		no_argument,		NULL, 's'},
    {"salt",		required_argument,	NULL, 'S'},
    {"rounds",		required_argument,	NULL, 'R'},
    {"version",		no_argument,		NULL, 'V'},
    {NULL,		0,			NULL, 0  }
};
#else
extern char *optarg;
extern int optind;
#endif

static const char valid_salts[] = "abcdefghijklmnopqrstuvwxyz"
"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

typedef enum {
    passwd_unset = 0,
    passwd_md5,
    passwd_apr1,
    passwd_sha256,
    passwd_sha512,
    passwd_aixmd5
} passwd_modes;

struct crypt_method {
    const char *method;		/* short name used by the command line option */
    const char *prefix;		/* salt prefix */
    const unsigned int minlen;	/* minimum salt length */
    const unsigned int maxlen;	/* maximum salt length */
    const unsigned int rounds;	/* supports a variable number of rounds */
    const char *desc;		/* long description for the methods list */
    passwd_modes mode;
};

static const struct crypt_method methods[] = {
    /* method		prefix	minlen,	maxlen	rounds description */
    { "des",		"",	2,	2,	0,
	N_("standard 56 bit DES-based crypt(3)") , passwd_unset},
    { "md5",		"$1$",	8,	8,	0, "MD5" , passwd_md5},
#if defined OpenBSD || defined FreeBSD || (defined __SVR4 && defined __sun)
    { "bf",		"$2a$", 22,	22,	1, "Blowfish" , passwd_unset},
#endif
#if defined HAVE_LINUX_CRYPT_GENSALT
    { "bf",		"$2a$", 22,	22,	1, "Blowfish, system-specific on 8-bit chars" , passwd_unset},
    /* algorithm 2y fixes CVE-2011-2483 */
    { "bfy",		"$2y$", 22,	22,	1, "Blowfish, correct handling of 8-bit chars" , passwd_unset},
#endif
#if defined FreeBSD
    { "nt",		"$3$",  0,	0,	0, "NT-Hash" , passwd_unset},
#endif
    /* http://people.redhat.com/drepper/SHA-crypt.txt */
    { "sha-256",	"$5$",	8,	16,	1, "SHA-256" ,passwd_sha256},
    { "sha-512",	"$6$",	8,	16,	1, "SHA-512" ,passwd_sha512},
    /* http://www.crypticide.com/dropsafe/article/1389 */
    /*
     * Actually the maximum salt length is arbitrary, but Solaris by default
     * always uses 8 characters:
     * http://cvs.opensolaris.org/source/xref/onnv/onnv-gate/ \
     *   usr/src/lib/crypt_modules/sunmd5/sunmd5.c#crypt_gensalt_impl
     */
#if defined __SVR4 && defined __sun
    { "sunmd5",		"$md5$", 8,	8,	1, "SunMD5" , passwd_unset},
#endif
    { NULL,		NULL,	0,	0,	0, NULL }
};

void generate_salt(char *const buf, const unsigned int len);
void *get_random_bytes(const int len);
void display_help(int error);
void display_version(void);
void display_methods(void);
char *md5crypt(const char *passwd, const char *magic, const char *salt);
char *shacrypt(const char *passwd, const char *magic, const char *salt);

int main(int argc, char *argv[])
{
    int ch, i;
    int password_fd = -1;
    unsigned int salt_minlen = 0;
    unsigned int salt_maxlen = 0;
    unsigned int rounds_support = 0;
    const char *salt_prefix = NULL;
    const char *salt_arg = NULL;
    passwd_modes mode = passwd_unset;
    unsigned int rounds = 0;
    char *salt = NULL;
    char rounds_str[30];
    char *password = NULL;

#ifdef ENABLE_NLS
    setlocale(LC_ALL, "");
    bindtextdomain(NLS_CAT_NAME, LOCALEDIR);
    textdomain(NLS_CAT_NAME);
#endif

    /* prepend options from environment */
    argv = merge_args(getenv("MKPASSWD_OPTIONS"), argv, &argc);

    while ((ch = GETOPT_LONGISH(argc, argv, "hH:m:5P:R:sS:V", longopts, 0))
	    > 0) {
	switch (ch) {
	case '5':
	    optarg = (char *) "md5";
	    /* fall through */
	case 'm':
	case 'H':
	    if (!optarg || strcaseeq("help", optarg)) {
		display_methods();
		exit(0);
	    }
	    for (i = 0; methods[i].method != NULL; i++)
		if (strcaseeq(methods[i].method, optarg)) {
			salt_prefix = methods[i].prefix;
		    salt_minlen = methods[i].minlen;
		    salt_maxlen = methods[i].maxlen;
		    rounds_support = methods[i].rounds;
		    mode = methods[i].mode;
		    break;
		}
	    if (!salt_prefix) {
		fprintf(stderr, _("Invalid method '%s'.\n"), optarg);
		exit(1);
	    }
	    break;
	case 'P':
	    {
		char *p;
		password_fd = strtol(optarg, &p, 10);
		if (p == NULL || *p != '\0' || password_fd < 0) {
		    fprintf(stderr, _("Invalid number '%s'.\n"), optarg);
		    exit(1);
		}
	    }
	    break;
	case 'R':
	    {
		char *p;
		rounds = strtol(optarg, &p, 10);
		if (p == NULL || *p != '\0' || rounds < 0) {
		    fprintf(stderr, _("Invalid number '%s'.\n"), optarg);
		    exit(1);
		}
	    }
	    break;
	case 's':
	    password_fd = 0;
	    break;
	case 'S':
	    salt_arg = optarg;
	    break;
	case 'V':
	    display_version();
	    exit(0);
	case 'h':
	    display_help(EXIT_SUCCESS);
	default:
	    fprintf(stderr, _("Try '%s --help' for more information.\n"),
		    argv[0]);
	    exit(1);
	}
    }
    argc -= optind;
    argv += optind;

    if (argc == 2 && !salt_arg) {
	password = argv[0];
	salt_arg = argv[1];
    } else if (argc == 1) {
	password = argv[0];
    } else if (argc == 0) {
    } else {
	display_help(EXIT_FAILURE);
    }

    /* default: DES password */
    if (!salt_prefix) {
	salt_minlen = methods[0].minlen;
	salt_maxlen = methods[0].maxlen;
	salt_prefix = methods[0].prefix;
	mode = methods[0].mode;
    }

    if (streq(salt_prefix, "$2a$") || streq(salt_prefix, "$2y$")) {
	/* OpenBSD Blowfish and derivatives */
	if (rounds <= 5)
	    rounds = 5;
	/* actually for 2a/2y it is the logarithm of the number of rounds */
	snprintf(rounds_str, sizeof(rounds_str), "%02u$", rounds);
    } else if (rounds_support && rounds)
	snprintf(rounds_str, sizeof(rounds_str), "rounds=%u$", rounds);
    else
	rounds_str[0] = '\0';

    if (salt_arg) {
	unsigned int c = strlen(salt_arg);
	if (c < salt_minlen || c > salt_maxlen) {
	    if (salt_minlen == salt_maxlen)
		fprintf(stderr, ngettext(
			"Wrong salt length: %d byte when %d expected.\n",
			"Wrong salt length: %d bytes when %d expected.\n", c),
			c, salt_maxlen);
	    else
		fprintf(stderr, ngettext(
			"Wrong salt length: %d byte when %d <= n <= %d"
			" expected.\n",
			"Wrong salt length: %d bytes when %d <= n <= %d"
			" expected.\n", c),
			c, salt_minlen, salt_maxlen);
	    exit(1);
	}
	while (c-- > 0) {
	    if (strchr(valid_salts, salt_arg[c]) == NULL) {
		fprintf(stderr, _("Illegal salt character '%c'.\n"),
			salt_arg[c]);
		exit(1);
	    }
	}

	salt = NOFAIL(malloc(strlen(salt_prefix) + strlen(rounds_str)
		+ strlen(salt_arg) + 1));
	*salt = '\0';
	strcat(salt, salt_prefix);
	strcat(salt, rounds_str);
	strcat(salt, salt_arg);
    } else {
#ifdef HAVE_SOLARIS_CRYPT_GENSALT
#error "This code path is untested on Solaris. Please send a patch."
	salt = crypt_gensalt(salt_prefix, NULL);
	if (!salt)
		perror(stderr, "crypt_gensalt");
#elif defined HAVE_LINUX_CRYPT_GENSALT
	void *entropy = get_random_bytes(64);

	salt = crypt_gensalt(salt_prefix, rounds, entropy, 64);
	if (!salt) {
		fprintf(stderr, "crypt_gensalt failed.\n");
		exit(2);
	}
	free(entropy);
#else
	unsigned int salt_len = salt_maxlen;

	if (salt_minlen != salt_maxlen) { /* salt length can vary */
	    srand(time(NULL) + getpid());
	    salt_len = rand() % (salt_maxlen - salt_minlen + 1) + salt_minlen;
	}

	salt = NOFAIL(malloc(strlen(salt_prefix) + strlen(rounds_str)
		+ salt_len + 1));
	*salt = '\0';
	strcat(salt, salt_prefix);
	strcat(salt, rounds_str);
	generate_salt(salt + strlen(salt), salt_len);
#endif
    }

    if (password) {
    } else if (password_fd != -1) {
	FILE *fp;
	char *p;

	if (isatty(password_fd))
	    fprintf(stderr, _("Password: "));
	password = NOFAIL(malloc(128));
	fp = fdopen(password_fd, "r");
	if (!fp) {
	    perror("fdopen");
	    exit(2);
	}
	if (!fgets(password, 128, fp)) {
	    perror("fgets");
	    exit(2);
	}

	p = strpbrk(password, "\n\r");
	if (p)
	    *p = '\0';
    } else {
	password = getpass(_("Password: "));
	if (!password) {
	    perror("getpass");
	    exit(2);
	}
    }

    {
	const char *result;
	result = crypt(password, salt);
	/* xcrypt returns "*0" on errors */
	if (!result || result[0] == '*') {
	    fprintf(stderr, "crypt failed.\n");
	    exit(2);
	}
	/* yes, using strlen(salt_prefix) on salt. It's not
	 * documented whether crypt_gensalt may change the prefix */
	if (!strneq(result, salt, strlen(salt_prefix))) {
		if (mode != passwd_unset) {
			salt+=strlen(salt_prefix);
			char *hash = NULL;
			/* now compute password hash */
		    if (mode == passwd_md5 || mode == passwd_apr1)
		        hash = md5crypt(password, (mode == passwd_md5 ? "1" : "apr1"), salt);
		    if (mode == passwd_aixmd5)
		        hash = md5crypt(password, "", salt);
		    if (mode == passwd_sha256 || mode == passwd_sha512)
		        hash = shacrypt(password, (mode == passwd_sha256 ? "5" : "6"), salt);
		    assert(hash != NULL);
		    result = hash;
		} else {
		    fprintf(stderr, _("Method not supported by crypt(3).\n"));
		    exit(2);
		}
	}
	printf("%s\n", result);
    }

    exit(0);
}

#ifdef RANDOM_DEVICE
void* get_random_bytes(const int count)
{
    char *buf;
    int fd;

    buf = NOFAIL(malloc(count));
    fd = open(RANDOM_DEVICE, O_RDONLY);
    if (fd < 0) {
	perror("open(" RANDOM_DEVICE ")");
	exit(2);
    }
    if (read(fd, buf, count) != count) {
	if (count < 0)
	    perror("read(" RANDOM_DEVICE ")");
	else
	    fprintf(stderr, "Short read of %s.\n", RANDOM_DEVICE);
	exit(2);
    }
    close(fd);

    return buf;
}
#endif

#ifdef RANDOM_DEVICE

void generate_salt(char *const buf, const unsigned int len)
{
    unsigned int i;

    unsigned char *entropy = get_random_bytes(len * sizeof(unsigned char));
    for (i = 0; i < len; i++)
	buf[i] = valid_salts[entropy[i] % (sizeof valid_salts - 1)];
    buf[i] = '\0';
}

#else /* RANDOM_DEVICE */

void generate_salt(char *const buf, const unsigned int len)
{
    unsigned int i;

# ifdef HAVE_GETTIMEOFDAY
    struct timeval tv;

    gettimeofday(&tv, NULL);
    srand(tv.tv_sec ^ tv.tv_usec);

# else /* HAVE_GETTIMEOFDAY */
#  warning "This system lacks a strong enough random numbers generator!"

    /*
     * The possible values of time over one year are 31536000, which is
     * two orders of magnitude less than the allowed entropy range (2^32).
     */
    srand(time(NULL) + getpid());

# endif /* HAVE_GETTIMEOFDAY */

    for (i = 0; i < len; i++)
	buf[i] = valid_salts[rand() % (sizeof valid_salts - 1)];
    buf[i] = '\0';
}

#endif /* RANDOM_DEVICE */

void display_help(int error)
{
    fprintf((EXIT_SUCCESS == error) ? stdout : stderr,
	    _("Usage: mkpasswd [OPTIONS]... [PASSWORD [SALT]]\n"
	    "Crypts the PASSWORD using crypt(3).\n\n"));
    fprintf(stderr, _(
"      -m, --method=TYPE     select method TYPE\n"
"      -5                    like --method=md5\n"
"      -S, --salt=SALT       use the specified SALT\n"
"      -R, --rounds=NUMBER   use the specified NUMBER of rounds\n"
"      -P, --password-fd=NUM read the password from file descriptor NUM\n"
"                            instead of /dev/tty\n"
"      -s, --stdin           like --password-fd=0\n"
"      -h, --help            display this help and exit\n"
"      -V, --version         output version information and exit\n"
"\n"
"If PASSWORD is missing then it is asked interactively.\n"
"If no SALT is specified, a random one is generated.\n"
"If TYPE is 'help', available methods are printed.\n"
"\n"
"Report bugs to %s.\n"), "<md+whois@linux.it>");
    exit(error);
}

void display_version(void)
{
    printf("mkpasswd %s\n\n", VERSION);
    puts("Copyright (C) 2001-2008 Marco d'Itri\n"
"This is free software; see the source for copying conditions.  There is NO\n"
"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.");
}

void display_methods(void)
{
    unsigned int i;

    printf(_("Available methods:\n"));
    for (i = 0; methods[i].method != NULL; i++)
	printf("%s\t%s\n", methods[i].method, methods[i].desc);
}

/*
 * SHA based password algorithm, describe by Ulrich Drepper here:
 * https://www.akkadia.org/drepper/SHA-crypt.txt
 * (note that it's in the public domain)
 */
char *shacrypt(const char *passwd, const char *magic, const char *salt)
{
    /* Prefix for optional rounds specification.  */
    static const char rounds_prefix[] = "rounds=";
    /* Maximum salt string length.  */
# define SALT_LEN_MAX 16
    /* Default number of rounds if not explicitly specified.  */
# define ROUNDS_DEFAULT 5000
    /* Minimum number of rounds.  */
# define ROUNDS_MIN 1000
    /* Maximum number of rounds.  */
# define ROUNDS_MAX 999999999

    /* "$6$rounds=<N>$......salt......$...shahash(up to 86 chars)...\0" */
    static char out_buf[3 + 17 + 17 + 86 + 1];
    unsigned char buf[SHA512_DIGEST_LENGTH];
    unsigned char temp_buf[SHA512_DIGEST_LENGTH];
    size_t buf_size = 0;
    char ascii_magic[2];
    char ascii_salt[17];          /* Max 16 chars plus '\0' */
    char *ascii_passwd = NULL;
    size_t n;
    EVP_MD_CTX *md = NULL, *md2 = NULL;
    const EVP_MD *sha = NULL;
    size_t passwd_len, salt_len, magic_len;
    unsigned int rounds = ROUNDS_DEFAULT;        /* Default */
    char rounds_custom = 0;
    char *p_bytes = NULL;
    char *s_bytes = NULL;
    char *cp = NULL;

    passwd_len = strlen(passwd);
    magic_len = strlen(magic);

    /* assert it's "5" or "6" */
    if (magic_len != 1)
        return NULL;

    switch (magic[0]) {
    case '5':
        sha = EVP_sha256();
        buf_size = 32;
        break;
    case '6':
        sha = EVP_sha512();
        buf_size = 64;
        break;
    default:
        return NULL;
    }

    if (strncmp(salt, rounds_prefix, sizeof(rounds_prefix) - 1) == 0) {
        const char *num = salt + sizeof(rounds_prefix) - 1;
        char *endp;
        unsigned long int srounds = strtoul (num, &endp, 10);
        if (*endp == '$') {
            salt = endp + 1;
            if (srounds > ROUNDS_MAX)
                rounds = ROUNDS_MAX;
            else if (srounds < ROUNDS_MIN)
                rounds = ROUNDS_MIN;
            else
                rounds = (unsigned int)srounds;
            rounds_custom = 1;
        } else {
            return NULL;
        }
    }

    OPENSSL_strlcpy(ascii_magic, magic, sizeof(ascii_magic));
#ifdef CHARSET_EBCDIC
    if ((magic[0] & 0x80) != 0)    /* High bit is 1 in EBCDIC alnums */
        ebcdic2ascii(ascii_magic, ascii_magic, magic_len);
#endif

    /* The salt gets truncated to 16 chars */
    OPENSSL_strlcpy(ascii_salt, salt, sizeof(ascii_salt));
    salt_len = strlen(ascii_salt);
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(ascii_salt, ascii_salt, salt_len);
#endif

#ifdef CHARSET_EBCDIC
    ascii_passwd = OPENSSL_strdup(passwd);
    if (ascii_passwd == NULL)
        return NULL;
    ebcdic2ascii(ascii_passwd, ascii_passwd, passwd_len);
    passwd = ascii_passwd;
#endif

    out_buf[0] = 0;
    OPENSSL_strlcat(out_buf, ascii_dollar, sizeof(out_buf));
    OPENSSL_strlcat(out_buf, ascii_magic, sizeof(out_buf));
    OPENSSL_strlcat(out_buf, ascii_dollar, sizeof(out_buf));
    if (rounds_custom) {
        char tmp_buf[80]; /* "rounds=999999999" */
        sprintf(tmp_buf, "rounds=%u", rounds);
#ifdef CHARSET_EBCDIC
        /* In case we're really on a ASCII based platform and just pretend */
        if (tmp_buf[0] != 0x72)  /* ASCII 'r' */
            ebcdic2ascii(tmp_buf, tmp_buf, strlen(tmp_buf));
#endif
        OPENSSL_strlcat(out_buf, tmp_buf, sizeof(out_buf));
        OPENSSL_strlcat(out_buf, ascii_dollar, sizeof(out_buf));
    }
    OPENSSL_strlcat(out_buf, ascii_salt, sizeof(out_buf));

    /* assert "$5$rounds=999999999$......salt......" */
    if (strlen(out_buf) > 3 + 17 * rounds_custom + salt_len)
        goto err;

    md = EVP_MD_CTX_new();
    if (md == NULL
        || !EVP_DigestInit_ex(md, sha, NULL)
        || !EVP_DigestUpdate(md, passwd, passwd_len)
        || !EVP_DigestUpdate(md, ascii_salt, salt_len))
        goto err;

    md2 = EVP_MD_CTX_new();
    if (md2 == NULL
        || !EVP_DigestInit_ex(md2, sha, NULL)
        || !EVP_DigestUpdate(md2, passwd, passwd_len)
        || !EVP_DigestUpdate(md2, ascii_salt, salt_len)
        || !EVP_DigestUpdate(md2, passwd, passwd_len)
        || !EVP_DigestFinal_ex(md2, buf, NULL))
        goto err;

    for (n = passwd_len; n > buf_size; n -= buf_size) {
        if (!EVP_DigestUpdate(md, buf, buf_size))
            goto err;
    }
    if (!EVP_DigestUpdate(md, buf, n))
        goto err;

    n = passwd_len;
    while (n) {
        if (!EVP_DigestUpdate(md,
                              (n & 1) ? buf : (const unsigned char *)passwd,
                              (n & 1) ? buf_size : passwd_len))
            goto err;
        n >>= 1;
    }
    if (!EVP_DigestFinal_ex(md, buf, NULL))
        return NULL;

    /* P sequence */
    if (!EVP_DigestInit_ex(md2, sha, NULL))
        goto err;

    for (n = passwd_len; n > 0; n--)
        if (!EVP_DigestUpdate(md2, passwd, passwd_len))
            goto err;

    if (!EVP_DigestFinal_ex(md2, temp_buf, NULL))
        return NULL;

    if ((p_bytes = OPENSSL_zalloc(passwd_len)) == NULL)
        goto err;
    for (cp = p_bytes, n = passwd_len; n > buf_size; n -= buf_size, cp += buf_size)
        memcpy(cp, temp_buf, buf_size);
    memcpy(cp, temp_buf, n);

    /* S sequence */
    if (!EVP_DigestInit_ex(md2, sha, NULL))
        goto err;

    for (n = 16 + buf[0]; n > 0; n--)
        if (!EVP_DigestUpdate(md2, ascii_salt, salt_len))
            goto err;

    if (!EVP_DigestFinal_ex(md2, temp_buf, NULL))
        return NULL;

    if ((s_bytes = OPENSSL_zalloc(salt_len)) == NULL)
        goto err;
    for (cp = s_bytes, n = salt_len; n > buf_size; n -= buf_size, cp += buf_size)
        memcpy(cp, temp_buf, buf_size);
    memcpy(cp, temp_buf, n);

    for (n = 0; n < rounds; n++) {
        if (!EVP_DigestInit_ex(md2, sha, NULL))
            goto err;
        if (!EVP_DigestUpdate(md2,
                              (n & 1) ? (const unsigned char *)p_bytes : buf,
                              (n & 1) ? passwd_len : buf_size))
            goto err;
        if (n % 3) {
            if (!EVP_DigestUpdate(md2, s_bytes, salt_len))
                goto err;
        }
        if (n % 7) {
            if (!EVP_DigestUpdate(md2, p_bytes, passwd_len))
                goto err;
        }
        if (!EVP_DigestUpdate(md2,
                              (n & 1) ? buf : (const unsigned char *)p_bytes,
                              (n & 1) ? buf_size : passwd_len))
                goto err;
        if (!EVP_DigestFinal_ex(md2, buf, NULL))
                goto err;
    }
    EVP_MD_CTX_free(md2);
    EVP_MD_CTX_free(md);
    md2 = NULL;
    md = NULL;
    OPENSSL_free(p_bytes);
    OPENSSL_free(s_bytes);
    p_bytes = NULL;
    s_bytes = NULL;

    cp = out_buf + strlen(out_buf);
    *cp++ = ascii_dollar[0];

# define b64_from_24bit(B2, B1, B0, N)                                   \
    do {                                                                \
        unsigned int w = ((B2) << 16) | ((B1) << 8) | (B0);             \
        int i = (N);                                                    \
        while (i-- > 0)                                                 \
            {                                                           \
                *cp++ = cov_2char[w & 0x3f];                            \
                w >>= 6;                                                \
            }                                                           \
    } while (0)

    switch (magic[0]) {
    case '5':
        b64_from_24bit (buf[0], buf[10], buf[20], 4);
        b64_from_24bit (buf[21], buf[1], buf[11], 4);
        b64_from_24bit (buf[12], buf[22], buf[2], 4);
        b64_from_24bit (buf[3], buf[13], buf[23], 4);
        b64_from_24bit (buf[24], buf[4], buf[14], 4);
        b64_from_24bit (buf[15], buf[25], buf[5], 4);
        b64_from_24bit (buf[6], buf[16], buf[26], 4);
        b64_from_24bit (buf[27], buf[7], buf[17], 4);
        b64_from_24bit (buf[18], buf[28], buf[8], 4);
        b64_from_24bit (buf[9], buf[19], buf[29], 4);
        b64_from_24bit (0, buf[31], buf[30], 3);
        break;
    case '6':
        b64_from_24bit (buf[0], buf[21], buf[42], 4);
        b64_from_24bit (buf[22], buf[43], buf[1], 4);
        b64_from_24bit (buf[44], buf[2], buf[23], 4);
        b64_from_24bit (buf[3], buf[24], buf[45], 4);
        b64_from_24bit (buf[25], buf[46], buf[4], 4);
        b64_from_24bit (buf[47], buf[5], buf[26], 4);
        b64_from_24bit (buf[6], buf[27], buf[48], 4);
        b64_from_24bit (buf[28], buf[49], buf[7], 4);
        b64_from_24bit (buf[50], buf[8], buf[29], 4);
        b64_from_24bit (buf[9], buf[30], buf[51], 4);
        b64_from_24bit (buf[31], buf[52], buf[10], 4);
        b64_from_24bit (buf[53], buf[11], buf[32], 4);
        b64_from_24bit (buf[12], buf[33], buf[54], 4);
        b64_from_24bit (buf[34], buf[55], buf[13], 4);
        b64_from_24bit (buf[56], buf[14], buf[35], 4);
        b64_from_24bit (buf[15], buf[36], buf[57], 4);
        b64_from_24bit (buf[37], buf[58], buf[16], 4);
        b64_from_24bit (buf[59], buf[17], buf[38], 4);
        b64_from_24bit (buf[18], buf[39], buf[60], 4);
        b64_from_24bit (buf[40], buf[61], buf[19], 4);
        b64_from_24bit (buf[62], buf[20], buf[41], 4);
        b64_from_24bit (0, 0, buf[63], 2);
        break;
    default:
        goto err;
    }
    *cp = '\0';
#ifdef CHARSET_EBCDIC
    ascii2ebcdic(out_buf, out_buf, strlen(out_buf));
#endif

    return out_buf;

 err:
    EVP_MD_CTX_free(md2);
    EVP_MD_CTX_free(md);
    OPENSSL_free(p_bytes);
    OPENSSL_free(s_bytes);
    OPENSSL_free(ascii_passwd);
    return NULL;
}

/*
 * MD5-based password algorithm (should probably be available as a library
 * function; then the static buffer would not be acceptable). For magic
 * string "1", this should be compatible to the MD5-based BSD password
 * algorithm. For 'magic' string "apr1", this is compatible to the MD5-based
 * Apache password algorithm. (Apparently, the Apache password algorithm is
 * identical except that the 'magic' string was changed -- the laziest
 * application of the NIH principle I've ever encountered.)
 */
char *md5crypt(const char *passwd, const char *magic, const char *salt)
{
    /* "$apr1$..salt..$.......md5hash..........\0" */
    static char out_buf[6 + 9 + 24 + 2];
    unsigned char buf[MD5_DIGEST_LENGTH];
    char ascii_magic[5];         /* "apr1" plus '\0' */
    char ascii_salt[9];          /* Max 8 chars plus '\0' */
    char *ascii_passwd = NULL;
    char *salt_out;
    int n;
    unsigned int i;
    EVP_MD_CTX *md = NULL, *md2 = NULL;
    size_t passwd_len, salt_len, magic_len;

    passwd_len = strlen(passwd);

    out_buf[0] = 0;
    magic_len = strlen(magic);
    OPENSSL_strlcpy(ascii_magic, magic, sizeof(ascii_magic));
#ifdef CHARSET_EBCDIC
    if ((magic[0] & 0x80) != 0)    /* High bit is 1 in EBCDIC alnums */
        ebcdic2ascii(ascii_magic, ascii_magic, magic_len);
#endif

    /* The salt gets truncated to 8 chars */
    OPENSSL_strlcpy(ascii_salt, salt, sizeof(ascii_salt));
    salt_len = strlen(ascii_salt);
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(ascii_salt, ascii_salt, salt_len);
#endif

#ifdef CHARSET_EBCDIC
    ascii_passwd = OPENSSL_strdup(passwd);
    if (ascii_passwd == NULL)
        return NULL;
    ebcdic2ascii(ascii_passwd, ascii_passwd, passwd_len);
    passwd = ascii_passwd;
#endif

    if (magic_len > 0) {
        OPENSSL_strlcat(out_buf, ascii_dollar, sizeof(out_buf));

        if (magic_len > 4)    /* assert it's  "1" or "apr1" */
            goto err;

        OPENSSL_strlcat(out_buf, ascii_magic, sizeof(out_buf));
        OPENSSL_strlcat(out_buf, ascii_dollar, sizeof(out_buf));
    }

    OPENSSL_strlcat(out_buf, ascii_salt, sizeof(out_buf));

    if (strlen(out_buf) > 6 + 8) /* assert "$apr1$..salt.." */
        goto err;

    salt_out = out_buf;
    if (magic_len > 0)
        salt_out += 2 + magic_len;

    if (salt_len > 8)
        goto err;

    md = EVP_MD_CTX_new();
    if (md == NULL
        || !EVP_DigestInit_ex(md, EVP_md5(), NULL)
        || !EVP_DigestUpdate(md, passwd, passwd_len))
        goto err;

    if (magic_len > 0)
        if (!EVP_DigestUpdate(md, ascii_dollar, 1)
            || !EVP_DigestUpdate(md, ascii_magic, magic_len)
            || !EVP_DigestUpdate(md, ascii_dollar, 1))
          goto err;

    if (!EVP_DigestUpdate(md, ascii_salt, salt_len))
        goto err;

    md2 = EVP_MD_CTX_new();
    if (md2 == NULL
        || !EVP_DigestInit_ex(md2, EVP_md5(), NULL)
        || !EVP_DigestUpdate(md2, passwd, passwd_len)
        || !EVP_DigestUpdate(md2, ascii_salt, salt_len)
        || !EVP_DigestUpdate(md2, passwd, passwd_len)
        || !EVP_DigestFinal_ex(md2, buf, NULL))
        goto err;

    for (i = passwd_len; i > sizeof(buf); i -= sizeof(buf)) {
        if (!EVP_DigestUpdate(md, buf, sizeof(buf)))
            goto err;
    }
    if (!EVP_DigestUpdate(md, buf, i))
        goto err;

    n = passwd_len;
    while (n) {
        if (!EVP_DigestUpdate(md, (n & 1) ? "\0" : passwd, 1))
            goto err;
        n >>= 1;
    }
    if (!EVP_DigestFinal_ex(md, buf, NULL))
        return NULL;

    for (i = 0; i < 1000; i++) {
        if (!EVP_DigestInit_ex(md2, EVP_md5(), NULL))
            goto err;
        if (!EVP_DigestUpdate(md2,
                              (i & 1) ? (const unsigned char *)passwd : buf,
                              (i & 1) ? passwd_len : sizeof(buf)))
            goto err;
        if (i % 3) {
            if (!EVP_DigestUpdate(md2, ascii_salt, salt_len))
                goto err;
        }
        if (i % 7) {
            if (!EVP_DigestUpdate(md2, passwd, passwd_len))
                goto err;
        }
        if (!EVP_DigestUpdate(md2,
                              (i & 1) ? buf : (const unsigned char *)passwd,
                              (i & 1) ? sizeof(buf) : passwd_len))
                goto err;
        if (!EVP_DigestFinal_ex(md2, buf, NULL))
                goto err;
    }
    EVP_MD_CTX_free(md2);
    EVP_MD_CTX_free(md);
    md2 = NULL;
    md = NULL;

    {
        /* transform buf into output string */
        unsigned char buf_perm[sizeof(buf)];
        int dest, source;
        char *output;

        /* silly output permutation */
        for (dest = 0, source = 0; dest < 14;
             dest++, source = (source + 6) % 17)
            buf_perm[dest] = buf[source];
        buf_perm[14] = buf[5];
        buf_perm[15] = buf[11];
# ifndef PEDANTIC              /* Unfortunately, this generates a "no
                                 * effect" warning */
        assert(16 == sizeof(buf_perm));
# endif

        output = salt_out + salt_len;
        assert(output == out_buf + strlen(out_buf));

        *output++ = ascii_dollar[0];

        for (i = 0; i < 15; i += 3) {
            *output++ = cov_2char[buf_perm[i + 2] & 0x3f];
            *output++ = cov_2char[((buf_perm[i + 1] & 0xf) << 2) |
                                  (buf_perm[i + 2] >> 6)];
            *output++ = cov_2char[((buf_perm[i] & 3) << 4) |
                                  (buf_perm[i + 1] >> 4)];
            *output++ = cov_2char[buf_perm[i] >> 2];
        }
        assert(i == 15);
        *output++ = cov_2char[buf_perm[i] & 0x3f];
        *output++ = cov_2char[buf_perm[i] >> 6];
        *output = 0;
        assert(strlen(out_buf) < sizeof(out_buf));
#ifdef CHARSET_EBCDIC
        ascii2ebcdic(out_buf, out_buf, strlen(out_buf));
#endif
    }

    return out_buf;

 err:
    OPENSSL_free(ascii_passwd);
    EVP_MD_CTX_free(md2);
    EVP_MD_CTX_free(md);
    return NULL;
}