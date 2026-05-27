/*
 * nagios/check_cck_ssl.c — Nagios/Icinga plugin for SSL/TLS certificate checks
 *
 * Nagios plugin interface:
 *   Exit 0 (OK)       — cert is valid and not expiring soon
 *   Exit 1 (WARNING)  — cert expires within -w days
 *   Exit 2 (CRITICAL) — cert expires within -c days, or is already expired
 *   Exit 3 (UNKNOWN)  — connection/parse error
 *
 * Output format (single line + perfdata):
 *   SSL CERT OK - example.com:443 expires 2026-07-01 (in 35 days) | days_remaining=35;30;14;0;
 *
 * Usage:
 *   check_cck_ssl -H hostname [-p port] [-w warn] [-c crit]
 *   check_cck_ssl -f /path/to/cert.pem [-w warn] [-c crit]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

/* ── Nagios exit states ──────────────────────────────────────────────── */
#define STATE_OK       0
#define STATE_WARNING  1
#define STATE_CRITICAL 2
#define STATE_UNKNOWN  3

/* ── Defaults ────────────────────────────────────────────────────────── */
#define DEFAULT_PORT      "443"
#define DEFAULT_WARN_DAYS 30
#define DEFAULT_CRIT_DAYS 14
#define DEFAULT_TIMEOUT   10   /* seconds */

/* ── Helpers ─────────────────────────────────────────────────────────── */

static void fmt_asn1_date(char *buf, size_t len, const ASN1_TIME *t)
{
    struct tm tm = {0};
    if (ASN1_TIME_to_tm(t, &tm) != 1)
        snprintf(buf, len, "(unknown)");
    else
        strftime(buf, len, "%Y-%m-%d", &tm);
}

/*
 * Print a Nagios-format status line and exit.
 *
 *   SSL CERT OK - <label> expires <date> (in N days) | days_remaining=N;W;C;0;
 */
static void __attribute__((noreturn))
nagios_exit(int state, const char *label, const char *msg,
            long days_remaining, int warn_days, int crit_days)
{
    static const char *const states[] = {"OK", "WARNING", "CRITICAL", "UNKNOWN"};
    printf("SSL CERT %s - %s %s | days_remaining=%ld;%d;%d;0;\n",
           states[state], label, msg, days_remaining, warn_days, crit_days);
    exit(state);
}

static void __attribute__((noreturn))
nagios_unknown(const char *label, const char *reason)
{
    printf("SSL CERT UNKNOWN - %s %s | days_remaining=U;0;0;0;\n",
           label, reason);
    exit(STATE_UNKNOWN);
}

/* ── Certificate evaluation ──────────────────────────────────────────── */

/*
 * Result from evaluating one cert.  Filled in by evaluate_cert(); then
 * the caller decides whether to exit immediately or collect multiple results.
 */
typedef struct {
    int   state;          /* STATE_* */
    long  days_remaining; /* negative = already expired */
    char  date[32];       /* expiry date as YYYY-MM-DD  */
    char  msg[256];       /* human-readable description  */
} CertResult;

static void evaluate_cert(X509 *cert, const char *label,
                           int warn_days, int crit_days,
                           CertResult *out)
{
    const ASN1_TIME *not_after = X509_get0_notAfter(cert);

    int day = 0, sec = 0;
    if (ASN1_TIME_diff(&day, &sec, NULL, not_after) != 1) {
        out->state = STATE_UNKNOWN;
        out->days_remaining = 0;
        snprintf(out->date, sizeof(out->date), "(unknown)");
        snprintf(out->msg,  sizeof(out->msg),  "could not parse certificate dates");
        return;
    }

    fmt_asn1_date(out->date, sizeof(out->date), not_after);
    out->days_remaining = (long)day;

    if (day < 0 || (day == 0 && sec < 0)) {
        /* Expired */
        long ago = (long)(-day);
        if (ago == 0) ago = 1;
        out->state = STATE_CRITICAL;
        snprintf(out->msg, sizeof(out->msg),
                 "certificate EXPIRED on %s (%ld day%s ago)",
                 out->date, ago, ago == 1 ? "" : "s");
    } else if (day <= crit_days) {
        out->state = STATE_CRITICAL;
        snprintf(out->msg, sizeof(out->msg),
                 "expires %s (CRITICAL: in %ld day%s)",
                 out->date, (long)day, day == 1 ? "" : "s");
    } else if (day <= warn_days) {
        out->state = STATE_WARNING;
        snprintf(out->msg, sizeof(out->msg),
                 "expires %s (WARNING: in %ld day%s)",
                 out->date, (long)day, day == 1 ? "" : "s");
    } else {
        out->state = STATE_OK;
        snprintf(out->msg, sizeof(out->msg),
                 "expires %s (in %ld day%s)",
                 out->date, (long)day, day == 1 ? "" : "s");
    }
}

/* ── File-based check ────────────────────────────────────────────────── */

static void __attribute__((noreturn))
check_file(const char *path, int warn_days, int crit_days)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        char msg[512];
        snprintf(msg, sizeof(msg), "cannot open file: %s", path);
        nagios_unknown(path, msg);
    }

    /* Read all certs in the PEM; track the worst result */
    CertResult worst = { STATE_OK, LONG_MAX, "", "no certificate found" };
    X509 *cert;
    int idx = 0;

    while ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
        CertResult r;
        char label[512];
        if (idx == 0)
            snprintf(label, sizeof(label), "%s", path);
        else
            snprintf(label, sizeof(label), "%s [cert %d]", path, idx + 1);

        evaluate_cert(cert, label, warn_days, crit_days, &r);
        X509_free(cert);

        if (r.state > worst.state ||
            (r.state == worst.state && r.days_remaining < worst.days_remaining))
            worst = r;
        idx++;
    }
    fclose(fp);
    ERR_clear_error();

    if (idx == 0)
        nagios_unknown(path, "no valid PEM certificate found in file");

    /* For chains, annotate the label */
    char label[560];
    if (idx > 1)
        snprintf(label, sizeof(label), "%s (%d-cert chain)", path, idx);
    else
        snprintf(label, sizeof(label), "%s", path);

    nagios_exit(worst.state, label, worst.msg,
                worst.days_remaining, warn_days, crit_days);
}

/* ── Live TLS check ──────────────────────────────────────────────────── */

static void __attribute__((noreturn))
check_host(const char *host, const char *port, int warn_days, int crit_days)
{
    char label[256];
    snprintf(label, sizeof(label), "%s:%s", host, port);

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        nagios_unknown(label, "SSL_CTX_new failed");

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    char addr[300];
    snprintf(addr, sizeof(addr), "%s:%s", host, port);

    BIO *bio = BIO_new_connect(addr);
    if (!bio) {
        SSL_CTX_free(ctx);
        nagios_unknown(label, "BIO_new_connect failed");
    }
    BIO_set_conn_hostname(bio, host);

    SSL *ssl = NULL;
    BIO *ssl_bio = BIO_new_ssl(ctx, 1);
    BIO_get_ssl(ssl_bio, &ssl);
    SSL_set_tlsext_host_name(ssl, host);
    ssl_bio = BIO_push(ssl_bio, bio);

    if (BIO_do_connect(ssl_bio) <= 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "connection failed (port %s unreachable?)", port);
        ERR_clear_error();
        BIO_free_all(ssl_bio);
        SSL_CTX_free(ctx);
        nagios_unknown(label, msg);
    }

    if (BIO_do_handshake(ssl_bio) <= 0) {
        ERR_clear_error();
        BIO_free_all(ssl_bio);
        SSL_CTX_free(ctx);
        nagios_unknown(label, "TLS handshake failed");
    }

    BIO_get_ssl(ssl_bio, &ssl);
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        BIO_free_all(ssl_bio);
        SSL_CTX_free(ctx);
        nagios_unknown(label, "server presented no certificate");
    }

    CertResult r;
    evaluate_cert(cert, label, warn_days, crit_days, &r);

    X509_free(cert);
    BIO_free_all(ssl_bio);
    SSL_CTX_free(ctx);
    ERR_clear_error();

    nagios_exit(r.state, label, r.msg, r.days_remaining, warn_days, crit_days);
}

/* ── Usage ───────────────────────────────────────────────────────────── */

static void __attribute__((noreturn)) usage(const char *prog, int exit_code)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s -H <host> [-p <port>] [-w <days>] [-c <days>]\n"
        "  %s -f <cert.pem>         [-w <days>] [-c <days>]\n\n"
        "Options:\n"
        "  -H <host>    Hostname to connect to (TLS)\n"
        "  -p <port>    Port (default: %s)\n"
        "  -f <file>    PEM certificate file to check instead of live host\n"
        "  -w <days>    Warning threshold in days (default: %d)\n"
        "  -c <days>    Critical threshold in days (default: %d)\n"
        "  -h           Show this help\n\n"
        "Exit codes: 0=OK  1=WARNING  2=CRITICAL  3=UNKNOWN\n",
        prog, prog, DEFAULT_PORT, DEFAULT_WARN_DAYS, DEFAULT_CRIT_DAYS);
    exit(exit_code);
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    char *opt_host = NULL;
    char *opt_port = DEFAULT_PORT;
    char *opt_file = NULL;
    int   warn_days = DEFAULT_WARN_DAYS;
    int   crit_days = DEFAULT_CRIT_DAYS;

    int opt;
    while ((opt = getopt(argc, argv, "H:p:f:w:c:h")) != -1) {
        switch (opt) {
        case 'H': opt_host  = optarg;        break;
        case 'p': opt_port  = optarg;        break;
        case 'f': opt_file  = optarg;        break;
        case 'w': warn_days = atoi(optarg);  break;
        case 'c': crit_days = atoi(optarg);  break;
        case 'h': usage(argv[0], STATE_OK);
        default:  usage(argv[0], STATE_UNKNOWN);
        }
    }

    if (!opt_host && !opt_file) {
        fprintf(stderr, "error: specify -H <host> or -f <file>\n\n");
        usage(argv[0], STATE_UNKNOWN);
    }
    if (opt_host && opt_file) {
        fprintf(stderr, "error: -H and -f are mutually exclusive\n\n");
        usage(argv[0], STATE_UNKNOWN);
    }
    if (crit_days >= warn_days) {
        fprintf(stderr,
                "warning: -c (%d) should be less than -w (%d); "
                "WARNING zone will be empty\n",
                crit_days, warn_days);
    }

    if (opt_file)
        check_file(opt_file, warn_days, crit_days);
    else
        check_host(opt_host, opt_port, warn_days, crit_days);

    /* unreachable — check_* always exit() */
    return STATE_UNKNOWN;
}
