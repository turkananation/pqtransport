/* QPACK bridge against libnghttp3.
 *
 * decode <section.bin>
 *   Read a field section (prefix + block). Print "name\tvalue" lines.
 * encode <headers.txt> <section.bin> <encoder.bin>
 *   headers.txt is "name\tvalue" lines. Writes the field section
 *   (prefix || block) and the encoder stream (may be empty).
 *
 * Dynamic table capacity is 0 so the section does not depend on a
 * prior encoder stream. Encoder bytes are still recorded; the Dart
 * peer ingests them before decoding.
 */
#include <nghttp3/nghttp3.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *what, int err) {
  if (err < 0) {
    fprintf(stderr, "%s: %s\n", what, nghttp3_strerror(err));
  } else {
    fprintf(stderr, "%s\n", what);
  }
  exit(1);
}

static uint8_t *read_file(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  if (!f) die("open", 0);
  if (fseek(f, 0, SEEK_END) != 0) die("seek", 0);
  long sz = ftell(f);
  if (sz < 0) die("ftell", 0);
  if (fseek(f, 0, SEEK_SET) != 0) die("seek", 0);
  uint8_t *buf = malloc((size_t)sz + 1);
  if (!buf) die("malloc", 0);
  if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) die("read", 0);
  fclose(f);
  buf[sz] = 0;
  *len = (size_t)sz;
  return buf;
}

static void write_file(const char *path, const uint8_t *p, size_t n) {
  FILE *f = fopen(path, "wb");
  if (!f) die("open out", 0);
  if (n > 0 && fwrite(p, 1, n, f) != n) die("write", 0);
  fclose(f);
}

static int cmd_decode(const char *path) {
  size_t srclen = 0;
  uint8_t *src = read_file(path, &srclen);
  const nghttp3_mem *mem = nghttp3_mem_default();
  nghttp3_qpack_decoder *dec = NULL;
  int rv = nghttp3_qpack_decoder_new(&dec, 0, 0, mem);
  if (rv != 0) die("decoder_new", rv);
  rv = nghttp3_qpack_decoder_set_max_dtable_capacity(dec, 0);
  if (rv != 0) die("set_max", rv);
  nghttp3_qpack_stream_context *sctx = NULL;
  rv = nghttp3_qpack_stream_context_new(&sctx, 0, mem);
  if (rv != 0) die("sctx", rv);

  const uint8_t *p = src;
  size_t left = srclen;
  int final_seen = 0;
  while (!final_seen) {
    nghttp3_qpack_nv nv;
    uint8_t flags = 0;
    nghttp3_ssize nread = nghttp3_qpack_decoder_read_request(
        dec, sctx, &nv, &flags, p, left, 1);
    if (nread < 0) die("read_request", (int)nread);
    if ((size_t)nread > left) die("read_request overshoot", 0);
    p += (size_t)nread;
    left -= (size_t)nread;
    if (flags & NGHTTP3_QPACK_DECODE_FLAG_EMIT) {
      nghttp3_vec name = nghttp3_rcbuf_get_buf(nv.name);
      nghttp3_vec value = nghttp3_rcbuf_get_buf(nv.value);
      fwrite(name.base, 1, name.len, stdout);
      fputc('\t', stdout);
      fwrite(value.base, 1, value.len, stdout);
      fputc('\n', stdout);
      nghttp3_rcbuf_decref(nv.name);
      nghttp3_rcbuf_decref(nv.value);
    }
    if (flags & NGHTTP3_QPACK_DECODE_FLAG_BLOCKED) die("blocked", 0);
    if (flags & NGHTTP3_QPACK_DECODE_FLAG_FINAL) final_seen = 1;
    if (nread == 0 && !final_seen) die("decode stalled", 0);
  }
  nghttp3_qpack_stream_context_del(sctx);
  nghttp3_qpack_decoder_del(dec);
  free(src);
  const nghttp3_info *info = nghttp3_version(0);
  fprintf(stderr, "nghttp3 %s decode ok\n", info->version_str);
  return 0;
}

static int cmd_encode(const char *headers, const char *section_path,
                      const char *encoder_path) {
  size_t text_len = 0;
  char *text = (char *)read_file(headers, &text_len);
  nghttp3_nv nva[64];
  /* Pointers into [text], which stays alive until encode returns. */
  size_t nvlen = 0;
  char *cursor = text;
  while (*cursor) {
    char *nl = strchr(cursor, '\n');
    if (nl) *nl = 0;
    if (cursor[0] != 0) {
      char *tab = strchr(cursor, '\t');
      if (!tab) die("header line missing tab", 0);
      *tab = 0;
      if (nvlen == 64) die("too many fields", 0);
      size_t i = nvlen++;
      nva[i].name = (uint8_t *)cursor;
      nva[i].namelen = strlen(cursor);
      nva[i].value = (uint8_t *)(tab + 1);
      nva[i].valuelen = strlen(tab + 1);
      nva[i].flags = NGHTTP3_NV_FLAG_NONE;
    }
    if (!nl) break;
    cursor = nl + 1;
  }

  const nghttp3_mem *mem = nghttp3_mem_default();
  nghttp3_qpack_encoder *enc = NULL;
  int rv = nghttp3_qpack_encoder_new(&enc, 0, mem);
  if (rv != 0) die("encoder_new", rv);
  nghttp3_buf pbuf, rbuf, ebuf;
  nghttp3_buf_init(&pbuf);
  nghttp3_buf_init(&rbuf);
  nghttp3_buf_init(&ebuf);
  rv = nghttp3_qpack_encoder_encode(enc, &pbuf, &rbuf, &ebuf, 0, nva, nvlen);
  if (rv != 0) die("encode", rv);

  size_t plen = nghttp3_buf_len(&pbuf);
  size_t rlen = nghttp3_buf_len(&rbuf);
  size_t elen = nghttp3_buf_len(&ebuf);
  uint8_t *section = malloc(plen + rlen);
  if (!section) die("malloc", 0);
  if (plen) memcpy(section, pbuf.pos, plen);
  if (rlen) memcpy(section + plen, rbuf.pos, rlen);
  write_file(section_path, section, plen + rlen);
  write_file(encoder_path, elen ? ebuf.pos : (const uint8_t *)"", elen);
  free(section);
  nghttp3_qpack_encoder_del(enc);
  free(text);
  const nghttp3_info *info = nghttp3_version(0);
  fprintf(stderr, "nghttp3 %s encode ok section=%zu encoder=%zu\n",
          info->version_str, plen + rlen, elen);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "decode") == 0) return cmd_decode(argv[2]);
  if (argc == 5 && strcmp(argv[1], "encode") == 0) {
    return cmd_encode(argv[2], argv[3], argv[4]);
  }
  fprintf(stderr,
          "usage:\n"
          "  qpack_iov decode <section.bin>\n"
          "  qpack_iov encode <headers.txt> <section.bin> <encoder.bin>\n");
  return 2;
}
