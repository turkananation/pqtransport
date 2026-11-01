/* BoringSSL 0.20261020.0 as a TLS 1.3 process. No dart:ffi.
   Default group: X25519MLKEM768. Optional group argument:
   x25519, secp256r1, secp384r1, mlkem1024.
   Suite: TLS_AES_256_GCM_SHA384.
   Modes: ML-DSA-65 X.509 (chain length 1), one P-256 leaf, or an
   ML-DSA-65 raw public key. The client pins that raw key. */
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void die(const char *what) {
  fprintf(stderr, "%s\n", what);
  ERR_print_errors_fp(stderr);
  exit(1);
}

static int write_pem_cert(const char *path, X509 *cert) {
  FILE *fp = fopen(path, "w");
  if (fp == NULL || PEM_write_X509(fp, cert) != 1) return 0;
  fclose(fp);
  return 1;
}

static int write_pem_key(const char *path, EVP_PKEY *key) {
  FILE *fp = fopen(path, "w");
  if (fp == NULL ||
      PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL) != 1) {
    return 0;
  }
  fclose(fp);
  return 1;
}

static int write_der_cert(const char *path, X509 *cert) {
  FILE *fp = fopen(path, "wb");
  if (fp == NULL || i2d_X509_fp(fp, cert) != 1) return 0;
  fclose(fp);
  return 1;
}

static int write_spki(const char *path, EVP_PKEY *key) {
  FILE *fp = fopen(path, "wb");
  if (fp == NULL || i2d_PUBKEY_fp(fp, key) != 1) return 0;
  fclose(fp);
  return 1;
}

static X509_NAME *set_cn(X509 *cert, const char *cn) {
  X509_NAME *name = X509_get_subject_name(cert);
  if (name == NULL ||
      X509_NAME_add_entry_by_txt(
          name, "CN", MBSTRING_ASC,
          (const unsigned char *)cn, -1, -1, 0) != 1) {
    return NULL;
  }
  return name;
}

static int add_constraints(X509 *cert, int is_ca) {
  BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();
  ASN1_BIT_STRING *ku = ASN1_BIT_STRING_new();
  if (bc == NULL || ku == NULL) return 0;
  bc->ca = is_ca ? 255 : 0;
  if (is_ca) {
    ASN1_BIT_STRING_set_bit(ku, 5, 1);
    ASN1_BIT_STRING_set_bit(ku, 6, 1);
  } else {
    ASN1_BIT_STRING_set_bit(ku, 0, 1);
  }
  int ok = X509_add1_ext_i2d(cert, NID_basic_constraints, bc, 1, 0) == 1 &&
           X509_add1_ext_i2d(cert, NID_key_usage, ku, 1, 0) == 1;
  BASIC_CONSTRAINTS_free(bc);
  ASN1_BIT_STRING_free(ku);
  return ok;
}

static int add_leaf_names(X509 *cert) {
  GENERAL_NAMES *names = sk_GENERAL_NAME_new_null();
  GENERAL_NAME *gn = GENERAL_NAME_new();
  ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();
  STACK_OF(ASN1_OBJECT) *eku = sk_ASN1_OBJECT_new_null();
  if (names == NULL || gn == NULL || ia5 == NULL || eku == NULL) return 0;
  if (ASN1_STRING_set(ia5, "localhost", 9) != 1) return 0;
  gn->type = GEN_DNS;
  gn->d.dNSName = ia5;
  if (sk_GENERAL_NAME_push(names, gn) <= 0) return 0;
  gn = NULL;
  ia5 = NULL;
  if (sk_ASN1_OBJECT_push(eku, OBJ_nid2obj(NID_server_auth)) <= 0) return 0;
  int ok = X509_add1_ext_i2d(cert, NID_subject_alt_name, names, 0, 0) == 1 &&
           X509_add1_ext_i2d(cert, NID_ext_key_usage, eku, 0, 0) == 1;
  sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
  sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
  return ok;
}

static X509 *make_cert(EVP_PKEY *subject_key, EVP_PKEY *issuer_key,
                       X509_NAME *issuer, const char *cn, int serial, int is_ca,
                       const EVP_MD *md) {
  X509 *cert = X509_new();
  if (cert == NULL || X509_set_version(cert, X509_VERSION_3) != 1 ||
      ASN1_INTEGER_set(X509_get_serialNumber(cert), serial) != 1 ||
      X509_gmtime_adj(X509_get_notBefore(cert), -3600) == NULL ||
      X509_gmtime_adj(X509_get_notAfter(cert), 24 * 60 * 60) == NULL) {
    X509_free(cert);
    return NULL;
  }
  X509_NAME *subject = set_cn(cert, cn);
  if (subject == NULL || !add_constraints(cert, is_ca)) {
    X509_free(cert);
    return NULL;
  }
  if (!is_ca && !add_leaf_names(cert)) {
    X509_free(cert);
    return NULL;
  }
  if (issuer == NULL) issuer = subject;
  if (X509_set_issuer_name(cert, issuer) != 1 ||
      X509_set_pubkey(cert, subject_key) != 1 ||
      X509_sign(cert, issuer_key, md) == 0) {
    X509_free(cert);
    return NULL;
  }
  return cert;
}

static int join_path(char *out, size_t out_len, const char *dir,
                     const char *name) {
  int n = snprintf(out, out_len, "%s/%s", dir, name);
  return n > 0 && (size_t)n < out_len;
}

static int mint(const char *dir) {
  char path[512];
  EVP_PKEY *ca = EVP_PKEY_generate_from_alg(EVP_pkey_ml_dsa_65());
  EVP_PKEY *leaf = EVP_PKEY_generate_from_alg(EVP_pkey_ml_dsa_65());
  if (ca == NULL || leaf == NULL) die("ML-DSA-65 keygen");
  X509 *ca_cert = make_cert(ca, ca, NULL, "pqtransport-bssl-ca", 1, 1, NULL);
  if (ca_cert == NULL) die("ML-DSA CA");
  X509 *leaf_cert = make_cert(leaf, ca, X509_get_subject_name(ca_cert),
                              "localhost", 2, 0, NULL);
  if (leaf_cert == NULL) die("ML-DSA leaf");
  if (!join_path(path, sizeof(path), dir, "mldsa-ca.pem") ||
      !write_pem_cert(path, ca_cert) ||
      !join_path(path, sizeof(path), dir, "mldsa-ca.der") ||
      !write_der_cert(path, ca_cert) ||
      !join_path(path, sizeof(path), dir, "mldsa-leaf.pem") ||
      !write_pem_cert(path, leaf_cert) ||
      !join_path(path, sizeof(path), dir, "mldsa-leaf.key") ||
      !write_pem_key(path, leaf)) {
    die("write ML-DSA material");
  }

  EVP_PKEY *p256_ca = EVP_PKEY_generate_from_alg(EVP_pkey_ec_p256());
  EVP_PKEY *p256_leaf = EVP_PKEY_generate_from_alg(EVP_pkey_ec_p256());
  if (p256_ca == NULL || p256_leaf == NULL) die("P-256 keygen");
  X509 *p256_ca_cert =
      make_cert(p256_ca, p256_ca, NULL, "pqtransport-bssl-p256", 1, 1,
                EVP_sha256());
  if (p256_ca_cert == NULL) die("P-256 CA");
  X509 *p256_leaf_cert =
      make_cert(p256_leaf, p256_ca, X509_get_subject_name(p256_ca_cert),
                "localhost", 2, 0, EVP_sha256());
  if (p256_leaf_cert == NULL) die("P-256 leaf");
  if (!join_path(path, sizeof(path), dir, "p256-ca.pem") ||
      !write_pem_cert(path, p256_ca_cert) ||
      !join_path(path, sizeof(path), dir, "p256-ca.der") ||
      !write_der_cert(path, p256_ca_cert) ||
      !join_path(path, sizeof(path), dir, "p256-leaf.pem") ||
      !write_pem_cert(path, p256_leaf_cert) ||
      !join_path(path, sizeof(path), dir, "p256-leaf.key") ||
      !write_pem_key(path, p256_leaf)) {
    die("write P-256 material");
  }

  EVP_PKEY *rpk = EVP_PKEY_generate_from_alg(EVP_pkey_ml_dsa_65());
  if (rpk == NULL) die("raw public key");
  if (!join_path(path, sizeof(path), dir, "rpk.key") || !write_pem_key(path, rpk) ||
      !join_path(path, sizeof(path), dir, "rpk.spki") || !write_spki(path, rpk)) {
    die("write raw public key");
  }
  return 0;
}

static uint8_t *read_file(const char *path, size_t *out_len) {
  FILE *fp = fopen(path, "rb");
  if (fp == NULL) return NULL;
  if (fseek(fp, 0, SEEK_END) != 0) return NULL;
  long n = ftell(fp);
  if (n <= 0 || n > 1 << 20) return NULL;
  if (fseek(fp, 0, SEEK_SET) != 0) return NULL;
  uint8_t *buf = (uint8_t *)malloc((size_t)n);
  if (buf == NULL || fread(buf, 1, (size_t)n, fp) != (size_t)n) {
    free(buf);
    fclose(fp);
    return NULL;
  }
  fclose(fp);
  *out_len = (size_t)n;
  return buf;
}

static uint8_t *g_pin;
static size_t g_pin_len;

static int spki_matches(EVP_PKEY *key) {
  if (key == NULL || g_pin == NULL) return 0;
  uint8_t *der = NULL;
  int len = i2d_PUBKEY(key, &der);
  if (len <= 0 || der == NULL) return 0;
  int ok = (size_t)len == g_pin_len && CRYPTO_memcmp(der, g_pin, g_pin_len) == 0;
  OPENSSL_free(der);
  return ok;
}

static enum ssl_verify_result_t pin_raw_key(SSL *ssl, uint8_t *out_alert) {
  EVP_PKEY *key = SSL_get0_peer_rpk(ssl);
  if (SSL_get_peer_cert_type(ssl) != TLSEXT_cert_type_rpk ||
      !spki_matches(key)) {
    *out_alert = SSL_AD_BAD_CERTIFICATE;
    return ssl_verify_invalid;
  }
  return ssl_verify_ok;
}

static uint16_t g_expect = SSL_GROUP_X25519_MLKEM768;

static uint16_t parse_group(const char *name) {
  if (name == NULL || name[0] == '\0' || strcmp(name, "x25519mlkem768") == 0) {
    return SSL_GROUP_X25519_MLKEM768;
  }
  if (strcmp(name, "mlkem1024") == 0) return SSL_GROUP_MLKEM1024;
  if (strcmp(name, "x25519") == 0) return SSL_GROUP_X25519;
  if (strcmp(name, "secp256r1") == 0) return SSL_GROUP_SECP256R1;
  if (strcmp(name, "secp384r1") == 0) return SSL_GROUP_SECP384R1;
  fprintf(stderr, "unknown group %s\n", name);
  exit(1);
}

static SSL_CTX *make_ctx(int server, const char *mode, uint16_t group) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  if (ctx == NULL) die("SSL_CTX_new");
  if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
      SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1) {
    die("TLS 1.3");
  }
  g_expect = group;
  const uint16_t suite = SSL_CIPHER_AES_256_GCM_SHA384;
  if (SSL_CTX_set1_group_ids(ctx, &group, 1) != 1) die("group");
  if (SSL_CTX_set1_tls13_ciphers(ctx, &suite, NULL, 1) != 1) die("cipher");
  uint16_t scheme = SSL_SIGN_ECDSA_SECP256R1_SHA256;
  if (strcmp(mode, "mldsa") == 0 || strcmp(mode, "rpk") == 0) {
    scheme = SSL_SIGN_ML_DSA_65;
  } else if (strcmp(mode, "p256") != 0) {
    die("mode");
  }
  if (server) {
    if (SSL_CTX_set_signing_algorithm_prefs(ctx, &scheme, 1) != 1) {
      die("signing prefs");
    }
  } else if (SSL_CTX_set_verify_algorithm_prefs(ctx, &scheme, 1) != 1) {
    die("verify prefs");
  }
  return ctx;
}

static void report(SSL *ssl, const char *role, const char *mode) {
  uint16_t group = SSL_get_group_id(ssl);
  const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
  uint16_t suite = cipher == NULL ? 0 : SSL_CIPHER_get_protocol_id(cipher);
  if (group != g_expect || suite != 0x1302) {
    fprintf(stderr, "negotiated group=%04x suite=%04x\n", group, suite);
    exit(1);
  }
  fprintf(stderr,
          "boringssl handshake ok group=%04x suite=1302 role=%s mode=%s\n",
          group, role, mode);
  fflush(stderr);
}

static void configure_server_identity(SSL_CTX *ctx, const char *mode,
                                      const char *dir) {
  char cert_path[512], key_path[512];
  if (strcmp(mode, "rpk") == 0) {
    if (!join_path(key_path, sizeof(key_path), dir, "rpk.key")) die("path");
    FILE *fp = fopen(key_path, "r");
    EVP_PKEY *key = fp == NULL ? NULL : PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (fp != NULL) fclose(fp);
    if (key == NULL) die("rpk key");
    SSL_CREDENTIAL *cred = SSL_CREDENTIAL_new_raw_public_key(key);
    if (cred == NULL || SSL_CTX_add1_credential(ctx, cred) != 1) die("rpk cred");
    SSL_CREDENTIAL_free(cred);
    EVP_PKEY_free(key);
    return;
  }
  const char *cert_name =
      strcmp(mode, "mldsa") == 0 ? "mldsa-leaf.pem" : "p256-leaf.pem";
  const char *key_name =
      strcmp(mode, "mldsa") == 0 ? "mldsa-leaf.key" : "p256-leaf.key";
  if (!join_path(cert_path, sizeof(cert_path), dir, cert_name) ||
      !join_path(key_path, sizeof(key_path), dir, key_name)) {
    die("path");
  }
  if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) != 1 ||
      SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != 1 ||
      SSL_CTX_check_private_key(ctx) != 1) {
    die("leaf");
  }
}

static int listen_on(int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) die("socket");
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
      listen(fd, 1) != 0) {
    die("listen");
  }
  return fd;
}

static void serve(int port, const char *mode, const char *dir, uint16_t group) {
  SSL_CTX *ctx = make_ctx(1, mode, group);
  configure_server_identity(ctx, mode, dir);
  int srv = listen_on(port);
  fprintf(stderr, "boringssl listening %d\n", port);
  fflush(stderr);
  for (;;) {
    int fd = accept(srv, NULL, NULL);
    if (fd < 0) die("accept");
    SSL *ssl = SSL_new(ctx);
    BIO *bio = BIO_new_socket(fd, BIO_NOCLOSE);
    if (ssl == NULL || bio == NULL) die("ssl");
    SSL_set_bio(ssl, bio, bio);
    if (SSL_accept(ssl) != 1) {
      ERR_print_errors_fp(stderr);
      SSL_free(ssl);
      close(fd);
      continue;
    }
    report(ssl, "server", mode);
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    poll(&pfd, 1, 15000);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    break;
  }
  close(srv);
  SSL_CTX_free(ctx);
}

static void configure_client_trust(SSL_CTX *ctx, const char *mode,
                                   const char *dir) {
  char path[512];
  if (strcmp(mode, "rpk") == 0) {
    if (!join_path(path, sizeof(path), dir, "expected.spki")) die("path");
    g_pin = read_file(path, &g_pin_len);
    if (g_pin == NULL) die("expected.spki");
    const uint8_t type = TLSEXT_cert_type_rpk;
    if (SSL_CTX_set1_accepted_peer_cert_types(ctx, &type, 1) != 1) die("rpk");
    SSL_CTX_set_custom_verify(ctx, SSL_VERIFY_PEER, pin_raw_key);
    return;
  }
  const char *ca = strcmp(mode, "mldsa") == 0 ? "mldsa-ca.pem" : "p256-ca.pem";
  if (!join_path(path, sizeof(path), dir, ca)) die("path");
  if (SSL_CTX_load_verify_locations(ctx, path, NULL) != 1) die("CA");
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}

static int connect_to(const char *host, int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) die("socket");
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) die("host");
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) die("connect");
  return fd;
}

static void connect_peer(const char *host, int port, const char *mode,
                         const char *dir, uint16_t group) {
  SSL_CTX *ctx = make_ctx(0, mode, group);
  configure_client_trust(ctx, mode, dir);
  int fd = connect_to(host, port);
  SSL *ssl = SSL_new(ctx);
  BIO *bio = BIO_new_socket(fd, BIO_NOCLOSE);
  if (ssl == NULL || bio == NULL) die("ssl");
  SSL_set_bio(ssl, bio, bio);
  if (SSL_set_tlsext_host_name(ssl, "localhost") != 1 ||
      SSL_set1_host(ssl, "localhost") != 1) {
    die("hostname");
  }
  if (SSL_connect(ssl) != 1) die("SSL_connect");
  if (strcmp(mode, "rpk") != 0 && SSL_get_verify_result(ssl) != X509_V_OK) {
    fprintf(stderr, "verify %ld\n", SSL_get_verify_result(ssl));
    exit(1);
  }
  report(ssl, "client", mode);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(fd);
  SSL_CTX_free(ctx);
}

int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "mint") == 0) return mint(argv[2]);
  if (argc == 5 && strcmp(argv[1], "serve") == 0) {
    serve(atoi(argv[2]), argv[3], argv[4], SSL_GROUP_X25519_MLKEM768);
    return 0;
  }
  if (argc == 6 && strcmp(argv[1], "serve") == 0) {
    serve(atoi(argv[2]), argv[3], argv[4], parse_group(argv[5]));
    return 0;
  }
  if (argc == 6 && strcmp(argv[1], "connect") == 0) {
    connect_peer(argv[2], atoi(argv[3]), argv[4], argv[5],
                 SSL_GROUP_X25519_MLKEM768);
    return 0;
  }
  if (argc == 7 && strcmp(argv[1], "connect") == 0) {
    connect_peer(argv[2], atoi(argv[3]), argv[4], argv[5], parse_group(argv[6]));
    return 0;
  }
  fprintf(stderr,
          "usage: boringssl_peer mint DIR\n"
          "       boringssl_peer serve PORT mldsa|p256|rpk DIR [group]\n"
          "       boringssl_peer connect HOST PORT mldsa|p256|rpk DIR [group]\n"
          "       group: x25519mlkem768 (default) | x25519 | secp256r1 | "
          "secp384r1 | mlkem1024\n");
  return 2;
}
