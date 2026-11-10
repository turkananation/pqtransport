/* libnghttp2 1.66 client. RFC 8441 extended CONNECT.
 * curl 8.23's wss:// URL is HTTP/1.1 Upgrade, so this is the nghttp2
 * peer for :protocol. Not curl. */
#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static SSL *g_ssl;
static int g_status;
static int g_end_stream = -1;
static int32_t g_stream = -1;
static int g_bytes;
static int g_frames;

static ssize_t send_cb(nghttp2_session *session, const uint8_t *data,
                        size_t length, int flags, void *user_data) {
  (void)session;
  (void)flags;
  (void)user_data;
  int n = SSL_write(g_ssl, data, (int)length);
  if (n > 0) return n;
  int err = SSL_get_error(g_ssl, n);
  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ||
      (err == SSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EWOULDBLOCK))) {
    return NGHTTP2_ERR_WOULDBLOCK;
  }
  return NGHTTP2_ERR_CALLBACK_FAILURE;
}

static ssize_t recv_cb(nghttp2_session *session, uint8_t *buf, size_t length,
                        int flags, void *user_data) {
  (void)session;
  (void)flags;
  (void)user_data;
  int n = SSL_read(g_ssl, buf, (int)length);
  if (n > 0) {
    g_bytes += n;
    return n;
  }
  if (n == 0) return NGHTTP2_ERR_EOF;
  int err = SSL_get_error(g_ssl, n);
  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ||
      (err == SSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EWOULDBLOCK))) {
    return NGHTTP2_ERR_WOULDBLOCK;
  }
  return NGHTTP2_ERR_CALLBACK_FAILURE;
}

static int on_header(nghttp2_session *session, const nghttp2_frame *frame,
                      const uint8_t *name, size_t namelen,
                      const uint8_t *value, size_t valuelen, uint8_t flags,
                      void *user_data) {
  (void)session;
  (void)flags;
  (void)user_data;
  if (frame->hd.stream_id != g_stream) return 0;
  if (namelen == 7 && memcmp(name, ":status", 7) == 0 && valuelen < 8) {
    char tmp[8];
    memcpy(tmp, value, valuelen);
    tmp[valuelen] = 0;
    g_status = atoi(tmp);
  }
  return 0;
}

static int on_frame(nghttp2_session *session, const nghttp2_frame *frame,
                     void *user_data) {
  (void)session;
  (void)user_data;
  g_frames++;
  fprintf(stderr, "frame type=%u stream=%d flags=0x%x\n", frame->hd.type,
          frame->hd.stream_id, frame->hd.flags);
  if (frame->hd.stream_id == g_stream && frame->hd.type == NGHTTP2_HEADERS) {
    g_end_stream = (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0;
  }
  return 0;
}

static nghttp2_nv nv(const char *name, const char *value) {
  nghttp2_nv out;
  out.name = (uint8_t *)name;
  out.value = (uint8_t *)value;
  out.namelen = strlen(name);
  out.valuelen = strlen(value);
  out.flags = NGHTTP2_NV_FLAG_NONE;
  return out;
}

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: h2connect host port ca.pem\n");
    return 64;
  }
  const char *host = argv[1];
  const char *port = argv[2];
  const char *ca = argv[3];

  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (ctx == NULL) return 1;
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
  if (SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768") != 1) {
    fprintf(stderr, "groups\n");
    return 1;
  }
  if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384") != 1) {
    fprintf(stderr, "ciphers\n");
    return 1;
  }
  if (SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1) {
    fprintf(stderr, "ca\n");
    return 1;
  }
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  /* h2 only. A missing selection is a failed flight, not HTTP/1. */
  if (SSL_CTX_set_alpn_protos(ctx, (const unsigned char *)"\x02h2", 3) != 0) {
    fprintf(stderr, "alpn\n");
    return 1;
  }

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo *res = NULL;
  if (getaddrinfo(host, port, &hints, &res) != 0 || res == NULL) {
    fprintf(stderr, "resolve\n");
    return 1;
  }
  int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (fd < 0 || connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
    fprintf(stderr, "connect\n");
    return 1;
  }
  freeaddrinfo(res);

  g_ssl = SSL_new(ctx);
  SSL_set_fd(g_ssl, fd);
  SSL_set_tlsext_host_name(g_ssl, "localhost");
  SSL_set1_host(g_ssl, "localhost");
  if (SSL_connect(g_ssl) != 1) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "ssl\n");
    return 1;
  }
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 200000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  const unsigned char *alpn = NULL;
  unsigned int alpn_len = 0;
  SSL_get0_alpn_selected(g_ssl, &alpn, &alpn_len);
  X509 *cert = SSL_get1_peer_certificate(g_ssl);
  int leaf_mldsa = cert != NULL && X509_get_signature_nid(cert) != NID_undef;
  /* ML-DSA-65 NID is checked by name because the numeric NID moves. */
  const char *sig = cert == NULL ? "" : OBJ_nid2sn(X509_get_signature_nid(cert));
  int mldsa65 = sig != NULL && strcmp(sig, "id-ml-dsa-65") == 0;
  const char *group = SSL_group_to_name(g_ssl, SSL_get_negotiated_group(g_ssl));
  if (cert != NULL) X509_free(cert);

  nghttp2_session_callbacks *callbacks;
  nghttp2_session_callbacks_new(&callbacks);
  nghttp2_session_callbacks_set_send_callback(callbacks, send_cb);
  nghttp2_session_callbacks_set_recv_callback(callbacks, recv_cb);
  nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame);
  nghttp2_session *session;
  if (nghttp2_session_client_new(&session, callbacks, NULL) != 0) return 1;
  nghttp2_session_callbacks_del(callbacks);

  nghttp2_settings_entry iv = {NGHTTP2_SETTINGS_ENABLE_PUSH, 0};
  nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, &iv, 1);
  nghttp2_nv hdrs[5];
  hdrs[0] = nv(":method", "CONNECT");
  hdrs[1] = nv(":protocol", "websocket");
  hdrs[2] = nv(":scheme", "https");
  hdrs[3] = nv(":authority", "localhost");
  hdrs[4] = nv(":path", "/tunnel");
  g_stream = nghttp2_submit_request(session, NULL, hdrs, 5, NULL, NULL);
  if (g_stream < 0) {
    fprintf(stderr, "submit %s\n", nghttp2_strerror(g_stream));
    return 1;
  }
  for (int i = 0; i < 40 && g_status == 0; i++) {
    int rv = nghttp2_session_send(session);
    if (rv != 0 && rv != NGHTTP2_ERR_WOULDBLOCK) {
      fprintf(stderr, "send %s\n", nghttp2_strerror(rv));
      return 1;
    }
    rv = nghttp2_session_recv(session);
    if (rv == NGHTTP2_ERR_WOULDBLOCK) {
      continue;
    }
    if (rv != 0) {
      fprintf(stderr, "recv %s status=%d\n", nghttp2_strerror(rv), g_status);
      break;
    }
  }
  printf(
      "nghttp2-connect status=%d end_stream=%d alpn=%.*s group=%s sig=%s bytes=%d frames=%d\n",
      g_status, g_end_stream, (int)alpn_len,
      alpn == NULL ? "" : (const char *)alpn, group == NULL ? "" : group,
      sig == NULL ? "" : sig, g_bytes, g_frames);
  int ok = g_status == 200 && g_end_stream == 0 && alpn_len == 2 &&
           memcmp(alpn, "h2", 2) == 0 && group != NULL &&
           strcmp(group, "X25519MLKEM768") == 0 && mldsa65 && leaf_mldsa;
  nghttp2_session_del(session);
  SSL_shutdown(g_ssl);
  SSL_free(g_ssl);
  SSL_CTX_free(ctx);
  close(fd);
  return ok ? 0 : 1;
}
