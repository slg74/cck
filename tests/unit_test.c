/*
 * tests/unit_test.c — unit tests for cck
 *
 * Strategy: pull in cck.c wholesale (renaming its main so there's no
 * conflict), then exercise the internal functions directly with certs
 * constructed via the OpenSSL API — no temp files, no shell-outs.
 *
 * Compile via: make test-unit
 */

/* Headers needed by the test helpers (before cck.c pulls in its own) */
#include <fcntl.h>    /* O_WRONLY */
#include <unistd.h>   /* dup, dup2, close, STDOUT_FILENO, STDERR_FILENO */

/* Rename cck's main before including the implementation */
#define main _cck_main_unused
#include "../cck.c"
#undef main

/* ── minimal test framework ─────────────────────────────────────────── */

static int g_t_pass = 0;
static int g_t_fail = 0;
static const char *g_suite = "";

static void suite(const char *name)
{
    g_suite = name;
    printf("\n── %s\n", name);
}

#define ASSERT_EQ(actual, expected, msg)                                    \
    do {                                                                    \
        int _a = (int)(actual), _e = (int)(expected);                      \
        if (_a == _e) {                                                     \
            printf("  PASS  " msg "\n");                                    \
            g_t_pass++;                                                     \
        } else {                                                            \
            printf("  FAIL  " msg " (got %d, expected %d)\n", _a, _e);     \
            g_t_fail++;                                                     \
        }                                                                   \
    } while (0)

#define ASSERT_TRUE(expr, msg)  ASSERT_EQ(!!(expr), 1, msg)
#define ASSERT_FALSE(expr, msg) ASSERT_EQ(!!(expr), 0, msg)

/* ── cert factory ────────────────────────────────────────────────────── */

/*
 * Create a self-signed EC cert.
 *   not_before_secs: offset from now (negative = in the past)
 *   not_after_secs:  offset from now
 */
static X509 *make_cert(long not_before_secs, long not_after_secs)
{
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
    if (!key) return NULL;

    X509 *cert = X509_new();
    X509_set_version(cert, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), not_before_secs);
    X509_gmtime_adj(X509_get_notAfter(cert), not_after_secs);

    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)"unit-test", -1, -1, 0);
    X509_set_issuer_name(cert, name);
    X509_set_pubkey(cert, key);
    X509_sign(cert, key, EVP_sha256());

    EVP_PKEY_free(key);
    return cert;
}

/*
 * Write an X509 cert to a temp PEM file.
 * Caller must free() the returned path.
 */
static char *cert_to_tmpfile(X509 *cert)
{
    char tmpl[] = "/tmp/cck_unit_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return NULL;

    FILE *fp = fdopen(fd, "w");
    PEM_write_X509(fp, cert);
    fclose(fp);

    /* Rename to .pem so cck's PEM reader is happy */
    char *path = malloc(strlen(tmpl) + 5);
    sprintf(path, "%s.pem", tmpl);
    rename(tmpl, path);
    return path;
}

/*
 * Capture stdout + stderr to /dev/null for the duration of fn(),
 * then restore. Used so test output isn't cluttered by cck's own prints.
 */
static CertStatus run_silent(CertStatus (*fn)(X509 *, const char *),
                              X509 *cert, const char *label)
{
    /* Flush before redirecting so buffered test output isn't lost */
    fflush(stdout);
    fflush(stderr);

    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    dup2(devnull, STDOUT_FILENO);
    dup2(devnull, STDERR_FILENO);
    close(devnull);

    CertStatus s = fn(cert, label);

    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    return s;
}

static CertStatus file_silent(const char *path)
{
    fflush(stdout);
    fflush(stderr);

    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    dup2(devnull, STDOUT_FILENO);
    dup2(devnull, STDERR_FILENO);
    close(devnull);

    CertStatus s = check_file(path);

    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    return s;
}

/* ── test suites ─────────────────────────────────────────────────────── */

static void test_evaluate_cert_ok(void)
{
    suite("evaluate_cert — valid certificate");

    g_warn_days = 30;       /* reset globals to defaults */
    g_quiet     = 0;
    g_no_color  = 1;        /* suppress ANSI in captured output */
    g_verbose   = 0;

    /* Cert valid for 10 years */
    X509 *cert = make_cert(-86400, 86400L * 3650);
    ASSERT_TRUE(cert != NULL, "make_cert succeeds");

    CertStatus s = run_silent(evaluate_cert, cert, "unit/valid");
    ASSERT_EQ(s, CERT_OK, "10-year cert → CERT_OK");

    X509_free(cert);
}

static void test_evaluate_cert_warn(void)
{
    suite("evaluate_cert — expiring soon");

    g_warn_days = 30;
    g_no_color  = 1;

    /* Cert that expires in 15 days — inside default 30-day warn window */
    X509 *cert = make_cert(-86400, 86400L * 15);
    ASSERT_TRUE(cert != NULL, "make_cert succeeds");

    CertStatus s = run_silent(evaluate_cert, cert, "unit/warn");
    ASSERT_EQ(s, CERT_WARN, "cert expiring in 15 days → CERT_WARN");

    X509_free(cert);
}

static void test_evaluate_cert_warn_boundary(void)
{
    suite("evaluate_cert — warn boundary conditions");

    g_no_color = 1;

    /* Exactly at the warn threshold (30 days) → WARN */
    g_warn_days = 30;
    X509 *c30 = make_cert(-86400, 86400L * 30);
    CertStatus s30 = run_silent(evaluate_cert, c30, "unit/boundary-30");
    ASSERT_EQ(s30, CERT_WARN, "cert expiring in exactly 30 days → CERT_WARN");
    X509_free(c30);

    /* One day past threshold (31 days) → OK */
    X509 *c31 = make_cert(-86400, 86400L * 31);
    CertStatus s31 = run_silent(evaluate_cert, c31, "unit/boundary-31");
    ASSERT_EQ(s31, CERT_OK, "cert expiring in 31 days → CERT_OK");
    X509_free(c31);

    /* warn_days = 0 → only expired certs trigger warn/expired */
    g_warn_days = 0;
    X509 *c1 = make_cert(-86400, 86400L * 1);
    CertStatus s1 = run_silent(evaluate_cert, c1, "unit/warn0");
    ASSERT_EQ(s1, CERT_OK, "warn_days=0, cert expiring in 1 day → CERT_OK");
    X509_free(c1);
}

static void test_evaluate_cert_expired(void)
{
    suite("evaluate_cert — expired certificate");

    g_warn_days = 30;
    g_no_color  = 1;
    g_verbose   = 0;

    /* Cert that expired 1 year ago */
    X509 *cert = make_cert(-86400L * 730, -86400L * 365);
    ASSERT_TRUE(cert != NULL, "make_cert succeeds");

    CertStatus s = run_silent(evaluate_cert, cert, "unit/expired");
    ASSERT_EQ(s, CERT_EXPIRED, "cert expired 1 year ago → CERT_EXPIRED");

    X509_free(cert);
}

static void test_evaluate_cert_expired_verbose(void)
{
    suite("evaluate_cert — expired cert verbose (shows valid-from)");

    g_warn_days = 30;
    g_no_color  = 1;
    g_verbose   = 1;   /* verbose on */

    X509 *cert = make_cert(-86400L * 730, -86400L * 365);
    CertStatus s = run_silent(evaluate_cert, cert, "unit/expired-verbose");
    ASSERT_EQ(s, CERT_EXPIRED, "expired cert in verbose mode → CERT_EXPIRED");
    /* (we can't easily assert on the printed text here; the important thing
        is that it doesn't crash and returns the right status) */

    g_verbose = 0;
    X509_free(cert);
}

static void test_evaluate_cert_quiet(void)
{
    suite("evaluate_cert — quiet mode suppresses OK output");

    g_warn_days = 30;
    g_no_color  = 1;
    g_quiet     = 1;

    X509 *cert = make_cert(-86400, 86400L * 3650);
    /* even in quiet mode, the return value must still be CERT_OK */
    CertStatus s = run_silent(evaluate_cert, cert, "unit/quiet-ok");
    ASSERT_EQ(s, CERT_OK, "quiet+valid → CERT_OK");

    g_quiet = 0;
    X509_free(cert);
}

/* ── check_file tests ────────────────────────────────────────────────── */

static void test_check_file_valid(void)
{
    suite("check_file — valid PEM file");

    g_warn_days = 30;
    g_no_color  = 1;

    X509 *cert = make_cert(-86400, 86400L * 3650);
    char *path = cert_to_tmpfile(cert);
    ASSERT_TRUE(path != NULL, "cert_to_tmpfile succeeds");

    CertStatus s = file_silent(path);
    ASSERT_EQ(s, CERT_OK, "valid PEM file → CERT_OK");

    X509_free(cert);
    unlink(path);
    free(path);
}

static void test_check_file_expired(void)
{
    suite("check_file — expired PEM file");

    g_warn_days = 30;
    g_no_color  = 1;

    X509 *cert = make_cert(-86400L * 730, -86400L * 365);
    char *path = cert_to_tmpfile(cert);

    CertStatus s = file_silent(path);
    ASSERT_EQ(s, CERT_EXPIRED, "expired PEM file → CERT_EXPIRED");

    X509_free(cert);
    unlink(path);
    free(path);
}

static void test_check_file_chain(void)
{
    suite("check_file — PEM chain (worst status wins)");

    g_warn_days = 30;
    g_no_color  = 1;

    X509 *valid   = make_cert(-86400, 86400L * 3650);
    X509 *expired = make_cert(-86400L * 730, -86400L * 365);

    /* Write a chain: valid cert + expired cert in one file */
    char chain_path[] = "/tmp/cck_unit_chain_XXXXXX";
    int fd = mkstemp(chain_path);
    FILE *fp = fdopen(fd, "w");
    PEM_write_X509(fp, valid);
    PEM_write_X509(fp, expired);
    fclose(fp);

    char *path = malloc(strlen(chain_path) + 5);
    sprintf(path, "%s.pem", chain_path);
    rename(chain_path, path);

    CertStatus s = file_silent(path);
    ASSERT_EQ(s, CERT_EXPIRED,
              "chain with valid+expired → worst status CERT_EXPIRED");

    X509_free(valid);
    X509_free(expired);
    unlink(path);
    free(path);
}

static void test_check_file_missing(void)
{
    suite("check_file — missing file");

    g_no_color = 1;
    CertStatus s = file_silent("/nonexistent/path/cert_that_does_not_exist.pem");
    ASSERT_EQ(s, CERT_ERROR, "missing file → CERT_ERROR");
}

static void test_check_file_not_pem(void)
{
    suite("check_file — file that is not a PEM cert");

    g_no_color = 1;

    /* Write a plain text file */
    char path[] = "/tmp/cck_unit_notpem_XXXXXX";
    int fd = mkstemp(path);
    FILE *fp = fdopen(fd, "w");
    fprintf(fp, "this is not a certificate\n");
    fclose(fp);

    CertStatus s = file_silent(path);
    ASSERT_EQ(s, CERT_ERROR, "non-PEM file → CERT_ERROR");

    unlink(path);
}

static void test_check_file_all_valid_chain(void)
{
    suite("check_file — chain of two valid certs → CERT_OK");

    g_warn_days = 30;
    g_no_color  = 1;

    X509 *a = make_cert(-86400, 86400L * 3650);
    X509 *b = make_cert(-86400, 86400L * 1825);

    char chain_path[] = "/tmp/cck_unit_chain2_XXXXXX";
    int fd = mkstemp(chain_path);
    FILE *fp = fdopen(fd, "w");
    PEM_write_X509(fp, a);
    PEM_write_X509(fp, b);
    fclose(fp);

    char *path = malloc(strlen(chain_path) + 5);
    sprintf(path, "%s.pem", chain_path);
    rename(chain_path, path);

    CertStatus s = file_silent(path);
    ASSERT_EQ(s, CERT_OK, "chain of two valid certs → CERT_OK");

    X509_free(a);
    X509_free(b);
    unlink(path);
    free(path);
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("cck unit tests\n");
    printf("══════════════════════════════════════════════════════\n");

    /* evaluate_cert */
    test_evaluate_cert_ok();
    test_evaluate_cert_warn();
    test_evaluate_cert_warn_boundary();
    test_evaluate_cert_expired();
    test_evaluate_cert_expired_verbose();
    test_evaluate_cert_quiet();

    /* check_file */
    test_check_file_valid();
    test_check_file_expired();
    test_check_file_chain();
    test_check_file_all_valid_chain();
    test_check_file_missing();
    test_check_file_not_pem();

    /* summary */
    int total = g_t_pass + g_t_fail;
    printf("\n══════════════════════════════════════════════════════\n");
    if (g_t_fail == 0) {
        printf("All %d tests passed.\n", total);
        return 0;
    } else {
        printf("%d/%d tests passed, %d FAILED.\n", g_t_pass, total, g_t_fail);
        return 1;
    }
}
