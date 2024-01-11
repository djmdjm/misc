/* $OpenBSD$ */
/*
 * Copyright (c) 2022 Damien Miller
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include "xmalloc.h"
#include "log.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "authfile.h"
#include "ssherr.h"
#include "misc.h"
#include "digest.h"

#include <fido.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

extern char *__progname;

#define ATTEST_MAGIC	"ssh-sk-attest-v01"

static int
prepare_fido_cred(fido_cred_t *cred, /* const */ struct sshbuf *b,
    const struct sshbuf *challenge)
{
	struct sshbuf *attestation_cert = NULL, *sig = NULL, *authdata = NULL;
	char *magic = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;

	/* Make sure it's the format we're expecting */
	if ((r = sshbuf_get_cstring(b, &magic, NULL)) != 0) {
		error_fr(r, "parse header");
		goto out;
	}
	if (strcmp(magic, ATTEST_MAGIC) != 0) {
		error_f("unsupported format");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* Parse the remaining fields */
	if ((r = sshbuf_froms(b, &attestation_cert)) != 0 ||
	    (r = sshbuf_froms(b, &sig)) != 0 ||
	    (r = sshbuf_froms(b, &authdata)) != 0 ||
	    (r = sshbuf_get_u32(b, NULL)) != 0 || /* reserved flags */
	    (r = sshbuf_get_string_direct(b, NULL, NULL)) != 0) { /* reserved */
		error_fr(r, "parse body");
		goto out;
	}

	fido_cred_set_type(cred, COSE_ES256);
	fido_cred_set_fmt(cred, "packed"); /* XXX or fido-u2f */
	fido_cred_set_clientdata(cred, sshbuf_ptr(challenge),
	    sshbuf_len(challenge));
	fido_cred_set_rp(cred, "ssh:", NULL); /* XXX */
	fido_cred_set_authdata(cred, sshbuf_ptr(authdata),
	    sshbuf_len(authdata));
	/* XXX set_extensions, set_rk, set_uv */
	fido_cred_set_x509(cred, sshbuf_ptr(attestation_cert),
	    sshbuf_len(attestation_cert));
	fido_cred_set_sig(cred, sshbuf_ptr(sig), sshbuf_len(sig));

	/* success */
	r = 0;
 out:
	free(magic);
	sshbuf_free(attestation_cert);
	sshbuf_free(sig);
	sshbuf_free(authdata);
	return r;
}

static uint8_t *
get_pubkey_from_cred(const fido_cred_t *cred, size_t *pubkey_len)
{
	const uint8_t *ptr;
	uint8_t *pubkey = NULL, *ret = NULL;
	BIGNUM *x = NULL, *y = NULL;
	EC_POINT *q = NULL;
	EC_GROUP *g = NULL;

	if ((x = BN_new()) == NULL ||
	    (y = BN_new()) == NULL ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL ||
	    (q = EC_POINT_new(g)) == NULL) {
		error_f("libcrypto setup failed");
		goto out;
	}
	if ((ptr = fido_cred_pubkey_ptr(cred)) == NULL) {
		error_f("fido_cred_pubkey_ptr failed");
		goto out;
	}
	if (fido_cred_pubkey_len(cred) != 64) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		goto out;
	}

	if (BN_bin2bn(ptr, 32, x) == NULL ||
	    BN_bin2bn(ptr + 32, 32, y) == NULL) {
		error_f("BN_bin2bn failed");
		goto out;
	}
	if (EC_POINT_set_affine_coordinates_GFp(g, q, x, y, NULL) != 1) {
		error_f("EC_POINT_set_affine_coordinates_GFp failed");
		goto out;
	}
	*pubkey_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	if (*pubkey_len == 0 || *pubkey_len > 2048) {
		error_f("bad pubkey length %zu", *pubkey_len);
		goto out;
	}
	if ((pubkey = malloc(*pubkey_len)) == NULL) {
		error_f("malloc pubkey failed");
		goto out;
	}
	if (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    pubkey, *pubkey_len, NULL) == 0) {
		error_f("EC_POINT_point2oct failed");
		goto out;
	}
	/* success */
	ret = pubkey;
	pubkey = NULL;
 out:
	free(pubkey);
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	return ret;
}

/* copied from sshsk_ecdsa_assemble() */
static int
cred_matches_key(const fido_cred_t *cred, const struct sshkey *k)
{
	struct sshkey *key = NULL;
	struct sshbuf *b = NULL;
	EC_POINT *q = NULL;
	uint8_t *pubkey = NULL;
	size_t pubkey_len;
	int r;

	if ((key = sshkey_new(KEY_ECDSA_SK)) == NULL) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	key->ecdsa_nid = NID_X9_62_prime256v1;
	if ((key->ecdsa = EC_KEY_new_by_curve_name(key->ecdsa_nid)) == NULL ||
	    (q = EC_POINT_new(EC_KEY_get0_group(key->ecdsa))) == NULL ||
	    (b = sshbuf_new()) == NULL) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((pubkey = get_pubkey_from_cred(cred, &pubkey_len)) == NULL) {
		error_f("get_pubkey_from_cred failed");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((r = sshbuf_put_string(b, pubkey, pubkey_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		goto out;
	}
	if ((r = sshbuf_get_ec(b, q, EC_KEY_get0_group(key->ecdsa))) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshkey_ec_validate_public(EC_KEY_get0_group(key->ecdsa), q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto out;
	}
	if (EC_KEY_set_public_key(key->ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	key->sk_application = xstrdup(k->sk_application); /* XXX */
	if (!sshkey_equal_public(key, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	r = 0; /* success */
 out:
	EC_POINT_free(q);
	free(pubkey);
	sshkey_free(key);
	sshbuf_free(b);
	return r;
}

int
main(int argc, char **argv)
{
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	int r, ch;
	struct sshkey *k = NULL;
	struct sshbuf *attestation = NULL, *challenge = NULL;
	fido_cred_t *cred = NULL;
	extern int optind;
	/* extern char *optarg; */

	ERR_load_crypto_strings();

	sanitise_stdfd();
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);

	while ((ch = getopt(argc, argv, "v")) != -1) {
		switch (ch) {
		case 'v':
			if (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			else if (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			break;
		default:
			goto usage;
		}
	}
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);
	argv += optind;
	argc -= optind;

	if (argc < 3) {
 usage:
		fprintf(stderr, "usage: %s [-v] "
		   "pubkey challenge attestation-blob\n", __progname);
		exit(1);
	}
	if ((r = sshkey_load_public(argv[0], &k, NULL)) != 0)
		fatal_r(r, "load key %s", argv[0]);
	if ((r = sshbuf_load_file(argv[1], &challenge)) != 0)
		fatal_r(r, "load challenge %s", argv[1]);
	if ((r = sshbuf_load_file(argv[2], &attestation)) != 0)
		fatal_r(r, "load attestation %s", argv[2]);
	if ((cred = fido_cred_new()) == NULL)
		fatal("fido_cred_new failed");

	if ((r = prepare_fido_cred(cred, attestation, challenge)) != 0)
		fatal_r(r, "prepare_fido_cred %s", argv[2]);
	if (fido_cred_x5c_ptr(cred) != NULL)
		r = fido_cred_verify(cred); /* basic attestation */
	else
		r = fido_cred_verify_self(cred); /* self-attestation */
	if (r != FIDO_OK)
		fatal("verification of attestation data failed");
	if (cred_matches_key(cred, k) != 0)
		fatal("cred authdata does not match key");

	fido_cred_free(&cred);

	logit("%s: GOOD", argv[2]);

	return (0);
}
