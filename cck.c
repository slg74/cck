/*
 * cck — SSL/TLS Certificate Checker
 *
 * Checks X.509 certificates from PEM files or live TLS hostnames.
 * Reports expired, expiring-soon, and valid certs.
 *
 * Usage:
 *   cck cert.pem [cert2.pem ...]          # check cert files
 *   cck -h example.com                    # check live TLS cert
 *   cck -h example.com:8443               # custom port
 *   cck -w 30 cert.pem                    # warn if expiring within 30 days
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

/* ── ANSI colors ─────────────────────────────────────────────────── */
#define RED    "\033[1;31m"
#define GREEN  "\033[1;32m"
#define YELLOW "\033[1;33m"
#define CYAN   "\033[1;36m"
#define BOLD   "\033[1m"
#define RESET  "\033[0m"

/* ── exit codes ───────────────────────────────────────────────────── */
#define EXIT_OK      0
#define EXIT_EXPIRED 1
#define EXIT_ERROR   2

/* ── defaults ─────────────────────────────────────────────────────── */
#define DEFAULT_PORT        "443"
#define DEFAULT_WARN_DAYS   30
#define DEFAULT_TIMEOUT     10    /* seconds before giving up on a TLS connect */

/* ── globals set by CLI flags ─────────────────────────────────────── */
static int  g_warn_days  = DEFAULT_WARN_DAYS;
static int  g_quiet      = 0;   /* -q: suppress OK lines              */
static int  g_no_color   = 0;   /* --no-color                         */
static int  g_verbose    = 0;   /* -v: extra cert details             */
static int  g_timeout    = DEFAULT_TIMEOUT; /* -t: connect timeout, secs */

/* ── helpers ──────────────────────────────────────────────────────── */

static const char *c(const char *code)
{
    return g_no_color ? "" : code;
}

/* Pretty-print an ASN1_TIME as "YYYY-MM-DD" using broken-down UTC tm */
static void fmt_asn1_date(char *buf, size_t len, const ASN1_TIME *t)
{
    struct tm tm = {0};
    if (ASN1_TIME_to_tm(t, &tm) != 1) {
        snprintf(buf, len, "(unknown)");
        return;
    }
    strftime(buf, len, "%Y-%m-%d", &tm);
}

/* ── certificate evaluation ───────────────────────────────────────── */

typedef enum { CERT_OK, CERT_WARN, CERT_EXPIRED, CERT_ERROR } CertStatus;

/*
 * Evaluate a parsed X509 cert and print a result line.
 * Uses OpenSSL's ASN1_TIME_diff so no timegm / POSIX extension needed.
 * Returns CERT_OK / CERT_WARN / CERT_EXPIRED / CERT_ERROR.
 */
static CertStatus evaluate_cert(X509 *cert, const char *label)
{
    const ASN1_TIME *not_after  = X509_get0_notAfter(cert);
    const ASN1_TIME *not_before = X509_get0_notBefore(cert);

    /* days/secs from NOW to not_after (negative = already past) */
    int day_to_exp = 0, sec_to_exp = 0;
    if (ASN1_TIME_diff(&day_to_exp, &sec_to_exp, NULL, not_after) != 1) {
        fprintf(stderr, "%sERROR%s  %s — could not parse certificate dates\n",
                c(RED), c(RESET), label);
        return CERT_ERROR;
    }

    char expires_str[32];
    fmt_asn1_date(expires_str, sizeof(expires_str), not_after);

    if (day_to_exp < 0 || (day_to_exp == 0 && sec_to_exp < 0)) {
        /* ── EXPIRED ── */
        long days_ago = (long)(-day_to_exp);
        if (days_ago == 0) days_ago = 1;   /* same-day expiry */

        fprintf(stderr,
                "%sEXPIRED%s %s\n"
                "         expired %s (%ld day%s ago)\n",
                c(RED), c(RESET), label,
                expires_str,
                days_ago, days_ago == 1 ? "" : "s");

        if (g_verbose) {
            char valid_from[32];
            fmt_asn1_date(valid_from, sizeof(valid_from), not_before);
            fprintf(stderr, "         valid from %s\n", valid_from);
        }
        return CERT_EXPIRED;
    }

    long days_left = (long)day_to_exp;

    if (days_left <= g_warn_days) {
        /* ── EXPIRING SOON ── */
        printf("%sWARN%s    %s\n"
               "         expires %s (in %ld day%s)\n",
               c(YELLOW), c(RESET), label,
               expires_str,
               days_left, days_left == 1 ? "" : "s");
        return CERT_WARN;
    }

    /* ── OK ── */
    if (!g_quiet) {
        printf("%sOK%s      %s\n"
               "         expires %s (in %ld day%s)\n",
               c(GREEN), c(RESET), label,
               expires_str,
               days_left, days_left == 1 ? "" : "s");
    }
    return CERT_OK;
}

/* ── file-based check ─────────────────────────────────────────────── */

static CertStatus check_file(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror(path);
        return CERT_ERROR;
    }

    /* A PEM file may contain a chain; check every cert in it */
    CertStatus worst = CERT_OK;
    X509 *cert;
    int   idx = 0;

    while ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
        char label[512];
        if (idx == 0)
            snprintf(label, sizeof(label), "%s", path);
        else
            snprintf(label, sizeof(label), "%s [cert %d]", path, idx + 1);

        CertStatus s = evaluate_cert(cert, label);
        if (s > worst) worst = s;
        X509_free(cert);
        idx++;
    }

    fclose(fp);

    if (idx == 0) {
        fprintf(stderr, "%sERROR%s  %s — no valid PEM certificate found\n",
                c(RED), c(RESET), path);
        ERR_clear_error();
        return CERT_ERROR;
    }

    ERR_clear_error();
    return worst;
}

/* ── live TLS check ───────────────────────────────────────────────── */

/*
 * SIGALRM handler — fires when g_timeout seconds elapse inside check_host().
 * write() and _exit() are async-signal-safe; printf/fprintf are not.
 *
 * Security: without a timeout a hostile or slow peer can keep cck hung
 * indefinitely, blocking any pipeline or monitoring script that calls it.
 */
static void handle_alarm(int sig)
{
    (void)sig;
    static const char msg[] = "ERROR: connection timed out\n";
    if (write(STDERR_FILENO, msg, sizeof(msg) - 1) < 0) { /* silence -Wunused-result */ }
    _exit(EXIT_ERROR);
}

static CertStatus check_host(const char *host, const char *port)
{
    char label[256];
    snprintf(label, sizeof(label), "%s:%s", host, port);

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "%sERROR%s  %s — SSL_CTX_new failed\n",
                c(RED), c(RESET), label);
        return CERT_ERROR;
    }

    /*
     * SSL_VERIFY_NONE: intentional.  cck's purpose is to inspect whatever
     * cert the server presents — including self-signed or already-expired
     * ones — so we must not let verification abort the handshake.  We are
     * not using this connection for any authenticated data transfer; we
     * read the cert and immediately close.
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    /* Build address string for BIO */
    char addr[300];
    snprintf(addr, sizeof(addr), "%s:%s", host, port);

    BIO *bio = BIO_new_connect(addr);
    if (!bio) {
        fprintf(stderr, "%sERROR%s  %s — BIO_new_connect failed\n",
                c(RED), c(RESET), label);
        SSL_CTX_free(ctx);
        return CERT_ERROR;
    }
    BIO_set_conn_hostname(bio, host);   /* for SNI via SSL layer */

    /* FIX: check BIO_new_ssl return — NULL on OOM would cause a NULL deref
     * on the BIO_get_ssl / SSL_set_tlsext_host_name / BIO_push calls below. */
    SSL *ssl = NULL;
    BIO *ssl_bio = BIO_new_ssl(ctx, 1);
    if (!ssl_bio) {
        fprintf(stderr, "%sERROR%s  %s — BIO_new_ssl failed\n",
                c(RED), c(RESET), label);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return CERT_ERROR;
    }

    BIO_get_ssl(ssl_bio, &ssl);
    /* FIX: validate ssl pointer before use — BIO_get_ssl can fail if the BIO
     * is not an SSL BIO (should not happen here, but be explicit). */
    if (!ssl) {
        fprintf(stderr, "%sERROR%s  %s — BIO_get_ssl failed\n",
                c(RED), c(RESET), label);
        BIO_free_all(ssl_bio);
        SSL_CTX_free(ctx);
        return CERT_ERROR;
    }

    SSL_set_tlsext_host_name(ssl, host);  /* SNI */
    ssl_bio = BIO_push(ssl_bio, bio);

    /*
     * FIX: arm a timeout before blocking network I/O.
     * Without this, a slow or non-responsive peer keeps cck hung forever,
     * which blocks any script or monitoring pipeline that invokes it.
     * handle_alarm() calls _exit() — async-signal-safe — on expiry.
     */
    signal(SIGALRM, handle_alarm);
    alarm((unsigned int)g_timeout);

    if (BIO_do_connect(ssl_bio) <= 0) {
        alarm(0);
        fprintf(stderr, "%sERROR%s  %s — connection failed\n",
                c(RED), c(RESET), label);
        /* FIX: gate OpenSSL error detail behind -v to avoid leaking internal
         * state (memory addresses, cipher negotiation details) to untrusted
         * output in automated / logged contexts. */
        if (g_verbose) ERR_print_errors_fp(stderr);
        else           ERR_clear_error();
        BIO_free_all(ssl_bio);
        SSL_CTX_free(ctx);
        return CERT_ERROR;
    }

    if (BIO_do_handshake(ssl_bio) <= 0) {
        alarm(0);
        fprintf(stderr, "%sERROR%s  %s — TLS handshake failed\n",
                c(RED), c(RESET), label);
        if (g_verbose) ERR_print_errors_fp(stderr);
        else           ERR_clear_error();
        BIO_free_all(ssl_bio);
        SSL_CTX_free(ctx);
        return CERT_ERROR;
    }

    alarm(0);   /* connection + handshake done; cancel the alarm */

    /*
     * FIX: use SSL_get1_peer_certificate (the non-deprecated form since
     * OpenSSL 3.0).  Both increment the ref-count; X509_free() below is
     * required in either case.  The old name still works as an alias in 3.x
     * but triggers -Wdeprecated-declarations with some build configs.
     *
     * FIX: the earlier BIO_get_ssl call already populated `ssl`; the
     * redundant second BIO_get_ssl call that was here has been removed.
     */
    X509 *cert = SSL_get1_peer_certificate(ssl);
    if (!cert) {
        fprintf(stderr, "%sERROR%s  %s — no certificate presented\n",
                c(RED), c(RESET), label);
        BIO_free_all(ssl_bio);
        SSL_CTX_free(ctx);
        return CERT_ERROR;
    }

    if (g_verbose) {
        /* Show subject CN */
        X509_NAME *subj = X509_get_subject_name(cert);
        char cn[256] = "(unknown)";
        X509_NAME_get_text_by_NID(subj, NID_commonName, cn, sizeof(cn));
        printf("         subject CN: %s%s%s\n", c(CYAN), cn, c(RESET));
    }

    CertStatus s = evaluate_cert(cert, label);

    X509_free(cert);
    BIO_free_all(ssl_bio);
    SSL_CTX_free(ctx);
    ERR_clear_error();
    return s;
}

/* ── usage ────────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "%scck%s — SSL/TLS Certificate Checker\n\n"
        "Usage:\n"
        "  %s [OPTIONS] <file.pem> [file2.pem ...]   check certificate files\n"
        "  %s [OPTIONS] -H <host[:port]> [...]       check live TLS certs\n\n"
        "Options:\n"
        "  -H <host[:port]>   connect to host and check its TLS certificate\n"
        "                     (port defaults to 443)\n"
        "  -w <days>          warn if expiring within N days (default: %d)\n"
        "  -t <secs>          TLS connect timeout in seconds (default: %d)\n"
        "  -q                 quiet mode — only show problems\n"
        "  -v                 verbose — show extra cert details\n"
        "  --no-color         disable ANSI color output\n"
        "  --help             show this help\n\n"
        "Exit codes:\n"
        "  0  all certificates valid\n"
        "  1  one or more certificates expired or expiring soon\n"
        "  2  error (file not found, parse failure, connection error)\n\n"
        "Examples:\n"
        "  %s /etc/ssl/certs/my.pem\n"
        "  %s -H example.com\n"
        "  %s -H example.com:8443 -w 14\n"
        "  %s -q /etc/ssl/certs/*.pem\n",
        c(BOLD), c(RESET),
        prog, prog,
        DEFAULT_WARN_DAYS,
        DEFAULT_TIMEOUT,
        prog, prog, prog, prog);
}

/* ── main ─────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    /* Suppress OpenSSL's own error output unless -v */
    if (isatty(fileno(stdout)) == 0)
        g_no_color = 1;

    /* ── option parsing ── */
    int opt;
    int host_mode = 0;

    /* Support --no-color and --help as long options */
    static struct option long_opts[] = {
        {"no-color", no_argument,       NULL, 'C'},
        {"help",     no_argument,       NULL, '?'},
        {NULL, 0, NULL, 0}
    };

    /*
     * KNOWN LIMITATION: getopt stops at the first -H and hands off to the
     * manual loop below.  Flags placed after the first -H (e.g.
     * "cck -H host -w 14") are silently unrecognised and treated as
     * additional targets.  Put all flags before the first -H or target path.
     */
    while ((opt = getopt_long(argc, argv, "H:w:t:qvh?", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'H':
            host_mode = 1;
            /* optarg processed below per-argument */
            /* We allow multiple -H flags so we re-parse; just set mode here */
            optind--;          /* push back so we handle in the loop below */
            goto done_opts;    /* break out of getopt loop */
        case 'w': {
            /* FIX: atoi() silently returns 0 for non-numeric input and for
             * "0", giving no way to detect bad input.  Use strtol instead. */
            char *end;
            long v = strtol(optarg, &end, 10);
            if (*end != '\0' || v < 0 || v > 36500) {
                fprintf(stderr, "cck: -w requires an integer between 0 and 36500\n");
                return EXIT_ERROR;
            }
            g_warn_days = (int)v;
            break;
        }
        case 't': {
            char *end;
            long v = strtol(optarg, &end, 10);
            if (*end != '\0' || v < 1 || v > 300) {
                fprintf(stderr, "cck: -t requires an integer between 1 and 300\n");
                return EXIT_ERROR;
            }
            g_timeout = (int)v;
            break;
        }
        case 'q':
            g_quiet = 1;
            break;
        case 'v':
            g_verbose = 1;
            break;
        case 'C':
            g_no_color = 1;
            break;
        case 'h':
        case '?':
        default:
            usage(argv[0]);
            return EXIT_OK;
        }
    }
done_opts:;

    /* Rebuild: collect non-option args after getopt */
    /* We do a second pass to handle multiple -H <host> arguments */
    int remaining = argc - optind;

    if (remaining == 0 && !host_mode) {
        usage(argv[0]);
        return EXIT_OK;
    }

    /* Second pass: walk remaining args; detect -H flag inline */
    CertStatus worst = CERT_OK;
    int i = optind;

    while (i < argc) {
        if (strcmp(argv[i], "-H") == 0) {
            /* next arg is host[:port] */
            i++;
            if (i >= argc) {
                fprintf(stderr, "cck: -H requires a host argument\n");
                return EXIT_ERROR;
            }
            host_mode = 1;
        }

        const char *arg = argv[i];
        CertStatus s;

        if (host_mode) {
            /* Split host:port if provided */
            char host_buf[256];
            const char *port = DEFAULT_PORT;

            /* Check for IPv6 bracket notation [::1]:port */
            if (arg[0] == '[') {
                const char *close = strchr(arg, ']');
                if (close) {
                    size_t hlen = (size_t)(close - arg - 1);
                    if (hlen >= sizeof(host_buf)) hlen = sizeof(host_buf) - 1;
                    strncpy(host_buf, arg + 1, hlen);
                    host_buf[hlen] = '\0';
                    port = (close[1] == ':') ? close + 2 : DEFAULT_PORT;
                } else {
                    strncpy(host_buf, arg, sizeof(host_buf) - 1);
                    host_buf[sizeof(host_buf)-1] = '\0';
                }
            } else {
                /* plain host or host:port */
                const char *colon = strrchr(arg, ':');
                if (colon) {
                    size_t hlen = (size_t)(colon - arg);
                    if (hlen >= sizeof(host_buf)) hlen = sizeof(host_buf) - 1;
                    strncpy(host_buf, arg, hlen);
                    host_buf[hlen] = '\0';
                    port = colon + 1;
                } else {
                    strncpy(host_buf, arg, sizeof(host_buf) - 1);
                    host_buf[sizeof(host_buf)-1] = '\0';
                }
            }

            s = check_host(host_buf, port);
        } else {
            s = check_file(arg);
        }

        if (s > worst) worst = s;
        i++;
    }

    /* Map CertStatus → exit code */
    switch (worst) {
    case CERT_OK:   return EXIT_OK;
    case CERT_WARN: return EXIT_EXPIRED;   /* expiring soon = exit 1 */
    case CERT_EXPIRED: return EXIT_EXPIRED;
    default:        return EXIT_ERROR;
    }
}
