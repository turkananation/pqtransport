/// Every protocol size for `package:pqtransport`.
///
/// A numeric literal for a protocol size in any other file is a defect.
library;

// ---------------------------------------------------------------------------
// ML-KEM (FIPS 203)
// ---------------------------------------------------------------------------

const int mlKem768PublicKeyBytes = 1184;
const int mlKem768CiphertextBytes = 1088;
const int mlKem768SecretKeyBytes = 2400;
const int mlKem768SharedSecretBytes = 32;

const int mlKem1024PublicKeyBytes = 1568;
const int mlKem1024CiphertextBytes = 1568;
const int mlKem1024SecretKeyBytes = 3168;
const int mlKem1024SharedSecretBytes = 32;

// ---------------------------------------------------------------------------
// Classical ECDH
// ---------------------------------------------------------------------------

const int x25519ShareBytes = 32;
const int x25519SharedSecretBytes = 32;

const int secp256r1UncompressedBytes = 65; // 0x04 || X || Y
const int secp256r1SharedSecretBytes = 32; // x-coordinate

const int secp384r1UncompressedBytes = 97; // 0x04 || X || Y
const int secp384r1SharedSecretBytes = 48; // x-coordinate

const int uncompressedPointPrefix = 0x04;

// ---------------------------------------------------------------------------
// ML-DSA-65 (FIPS 204) — default identity signature
// ---------------------------------------------------------------------------

const int mlDsa65PublicKeyBytes = 1952;
const int mlDsa65SecretKeyBytes = 4032;
const int mlDsa65SignatureBytes = 3309;
const int mlDsa87PublicKeyBytes = 2592;
const int mlDsa87SecretKeyBytes = 4896;
const int mlDsa87SignatureBytes = 4627;
const int mlDsaSeedBytes = 32;
const int mlDsaContextMaxBytes = 255;

// ---------------------------------------------------------------------------
// RFC 10024 hybrid groups
// ---------------------------------------------------------------------------

const int namedGroupSecP256r1MlKem768 = 0x11EB; // 4587
const int namedGroupX25519MlKem768 = 0x11EC; // 4588
const int namedGroupSecP384r1MlKem1024 = 0x11ED; // 4589

const int x25519MlKem768ClientShareBytes = 1216; // 1184 + 32
const int x25519MlKem768ServerShareBytes = 1120; // 1088 + 32
const int x25519MlKem768SharedSecretBytes = 64; // 32 + 32

const int secP256r1MlKem768ClientShareBytes = 1249; // 65 + 1184
const int secP256r1MlKem768ServerShareBytes = 1153; // 65 + 1088
const int secP256r1MlKem768SharedSecretBytes = 64; // 32 + 32

const int secP384r1MlKem1024ClientShareBytes = 1665; // 97 + 1568
const int secP384r1MlKem1024ServerShareBytes = 1665; // 97 + 1568
const int secP384r1MlKem1024SharedSecretBytes = 80; // 48 + 32

// ---------------------------------------------------------------------------
// Session / transcript / AEAD
// ---------------------------------------------------------------------------

const int nonceBytes = 32;
const int sha256HashBytes = 32;
const int sha384HashBytes = 48;

/// SHA-256 digest size. ChaCha suite (`0x1303`) and UDP HKDF use this.
/// TLS `0x1302` uses [sha384HashBytes] via [TlsCipherSuite.hashBytes].
const int transcriptHashBytes = sha256HashBytes;
const int appSessionKeyBytes = 32;
const int aeadNonceBytes = 12;
const int aeadTagBytes = 16;
const int aeadKeyBytes = 32;

const int handshakeRandomBytes = 32;

/// Finished verify_data for SHA-256. SHA-384 verify_data is [sha384HashBytes].
const int verifyDataBytes = sha256HashBytes;

// ---------------------------------------------------------------------------
// UDP datagram envelope
// ---------------------------------------------------------------------------

const int datagramVersion = 1;
const int datagramVersionBytes = 1;
const int datagramHeaderLenBytes = 1;
const int datagramSequenceBytes = 8;
const int datagramDefaultMaxPayloadBytes = 1200;
const int datagramReplayWindowSize = 64;
const int datagramMinHeaderBytes = 10; // version + hdrLen + sequence(8)

const String udpSessionInfoPrefix = 'pqtransport udp-session v1';

// ---------------------------------------------------------------------------
// DNS / mDNS
// ---------------------------------------------------------------------------

const int dnsPort = 53;
const int mdnsPort = 5353;
const String mdnsIpv4Group = '224.0.0.251';
const String mdnsIpv6Group = 'ff02::fb';
const int dnsMessageMaxBytes = 65535;
const int dnsUdpClassicMaxBytes = 512;
const int dnsLabelMaxBytes = 63;
const int dnsNameMaxBytes = 255;
const int dnsPointerMask = 0xC0;
const int dnsPointerDepthMax = 10;
const int dnsHeaderBytes = 12;
const int edns0UdpPayloadDefault = 1232;

const int dnsTypeA = 1;
const int dnsTypeNs = 2;
const int dnsTypeCname = 5;
const int dnsTypeSoa = 6;
const int dnsTypePtr = 12;
const int dnsTypeMx = 15;
const int dnsTypeTxt = 16;
const int dnsTypeAaaa = 28;
const int dnsTypeSrv = 33;
const int dnsTypeOpt = 41;
const int dnsTypeDs = 43;
const int dnsTypeRrsig = 46;
const int dnsTypeCaa = 257;
const int dnsTypeHttps = 65;
const int dnsTypeSvcb = 64;

const int dnsClassIn = 1;
const int dnsClassAny = 255;

const int mdnsProbeCount = 2;

// ---------------------------------------------------------------------------
// TLS 1.3
// ---------------------------------------------------------------------------

const int tlsLegacyVersion = 0x0303; // recorded on the wire
const int tls13Version = 0x0304;
const int tlsRecordHeaderBytes = 5;
const int tlsMaxPlaintextBytes = 16384;

/// RFC 8446 §5.2: a TLSCiphertext fragment is at most 2^14 + 256 bytes.
const int tlsMaxCiphertextBytes = 16640;
const int tlsHandshakeReassemblyMaxBytes = 65536;
const int tlsHandshakeHeaderBytes = 4;
const int tlsFinishedLabelBytes = 32;
const int tlsCipherChaCha20Poly1305Sha256 = 0x1303;
const int tlsCipherAes256GcmSha384 = 0x1302;

/// Retired 0.1 private-use suite (AES-256-GCM + HKDF-SHA-256). Decode refuses
/// it. IANA `0x1302` / `0x1303` are the suites on the wire (OPEN-02, OPEN-13).
const int tlsCipherAes256GcmSha256Private = 0xFF00;
const int tlsContentHandshake = 22;
const int tlsContentApplicationData = 23;
const int tlsContentAlert = 21;
const int tlsContentChangeCipherSpec = 20;
const int tlsHsClientHello = 1;
const int tlsHsServerHello = 2;
const int tlsHsEncryptedExtensions = 8;
const int tlsHsCertificate = 11;
const int tlsHsCertificateVerify = 15;
const int tlsHsFinished = 20;
const int tlsHsKeyUpdate = 24;

/// RFC 8446 §4.4.1 synthetic handshake wrapping Hash(ClientHello1) in an HRR
/// transcript. Not sent on the wire.
const int tlsHsMessageHash = 254;
const int tlsExtSupportedVersions = 43;
const int tlsExtKeyShare = 51;
const int tlsExtSignatureAlgorithms = 13;
const int tlsExtSupportedGroups = 10;
const int tlsExtServerName = 0;
const int tlsExtAlpn = 16;
const int tlsExtClientCertificateType = 19;
const int tlsExtServerCertificateType = 20;
const int tlsExtCookie = 44;
const int tlsServerNameTypeHostName = 0;
const int tlsSignatureMldsa65 = 0x0905;
const int tlsSignatureMldsa87 = 0x0906;
const int tlsCertTypeRawPublicKey = 2;
const int tlsCompressionNull = 0;
const int tlsLegacySessionIdMaxBytes = 32;
const int tlsCookieBytes = 32;
const int tlsAlertIllegalParameter = 47;
const int tlsAlertUnexpectedMessage = 10;
const int tlsAlertDecryptError = 51;
const int tlsAlertHandshakeFailure = 40;
const int tlsAlertInternalError = 80;
const int tlsMaxHelloRetry = 1;

/// RFC 8446 §4.1.3 HelloRetryRequest.random = SHA-256("HelloRetryRequest").
const List<int> tlsHelloRetryRequestRandom = <int>[
  0xCF,
  0x21,
  0xAD,
  0x74,
  0xE5,
  0x9A,
  0x61,
  0x11,
  0xBE,
  0x1D,
  0x8C,
  0x02,
  0x1E,
  0x65,
  0xB8,
  0x91,
  0xC2,
  0xA2,
  0x11,
  0x16,
  0x7A,
  0xBB,
  0x8C,
  0x5E,
  0x07,
  0x9E,
  0x09,
  0xE2,
  0xC8,
  0xA8,
  0x33,
  0x9C,
];

const String tlsHkdfLabelPrefix = 'tls13 ';
const String tlsLabelDerived = 'derived';
const String tlsLabelCHsTraffic = 'c hs traffic';
const String tlsLabelSHsTraffic = 's hs traffic';
const String tlsLabelCApTraffic = 'c ap traffic';
const String tlsLabelSApTraffic = 's ap traffic';
const String tlsLabelFinished = 'finished';
const String tlsLabelExpMaster = 'exp master';
const String tlsLabelExporter = 'exporter';
const String tlsLabelIv = 'iv';
const String tlsLabelKey = 'key';

const int handshakeTimestampWindowMs = 2000;

// ---------------------------------------------------------------------------
// QUIC
// ---------------------------------------------------------------------------

const int quicVersion1 = 0x00000001;
const int quicMaxStreamDataDefault = 65536;
const int quicMaxDataDefault = 262144;
const int quicHeaderProtectionSampleBytes = 16;
const int quicPacketNumberMaxBytes = 4;
const int quicShortDcidBytes = 8;
const int quicAes128KeyBytes = 16;
const int quicMaxConnectionIdBytes = 20;

/// RFC 9000 §14.1: UDP datagrams carrying client Initial packets.
const int quicMinClientInitialUdpBytes = 1200;

/// RFC 9001 §5.2 Initial salt for QUIC version 1.
const List<int> quicInitialSaltV1 = [
  0x38,
  0x76,
  0x2c,
  0xf7,
  0xf5,
  0x59,
  0x34,
  0xb3,
  0x4d,
  0x17,
  0x9a,
  0xe6,
  0xa4,
  0xc8,
  0x0c,
  0xad,
  0xcc,
  0xbb,
  0x7f,
  0x0a,
];

const String quicLabelClientIn = 'client in';
const String quicLabelServerIn = 'server in';
const String quicLabelKey = 'quic key';
const String quicLabelIv = 'quic iv';
const String quicLabelHp = 'quic hp';

const int quicFramePadding = 0x00;
const int quicFramePing = 0x01;
const int quicFrameAck = 0x02;
const int quicFrameAckEcn = 0x03;
const int quicFrameCrypto = 0x06;
const int quicFrameStream = 0x08;
const int quicFrameStreamTypeMask = 0xF8;
const int quicFrameStreamOffBit = 0x04;
const int quicFrameStreamLenBit = 0x02;
const int quicFrameStreamFinBit = 0x01;
const int quicFrameResetStream = 0x04;
const int quicFrameMaxData = 0x10;
const int quicFrameMaxStreamData = 0x11;
const int quicFrameDataBlocked = 0x14;
const int quicFrameStreamDataBlocked = 0x15;
const int quicFrameConnectionClose = 0x1c;
const int quicFrameConnectionCloseApp = 0x1d;

/// RFC 9000 §20. A STREAM past MAX_DATA or MAX_STREAM_DATA.
const int quicErrorFlowControl = 0x03;

/// RFC 9000 §20.1. No error. Used by an application CONNECTION_CLOSE.
const int quicErrorNoError = 0x00;

/// Local idle timer. Not the negotiated `max_idle_timeout` transport
/// parameter (this stack does not send transport parameters). Null on
/// [PqQuicConn] leaves the timer disarmed. RFC 9000 §10.1.
const int quicLocalIdleTimeoutMicros = 30000000;

/// RFC 9000 §10.2. The draining period is three times the current PTO.
const int quicDrainPtoMultiplier = 3;

const int quicStreamIdTypeMask = 0x03;
const int quicStreamIdClientBidi = 0x00;
const int quicStreamIdServerBidi = 0x01;
const int quicStreamIdClientUni = 0x02;
const int quicStreamIdServerUni = 0x03;
const int quicStreamIdIncrement = 4;

const int quicVarintMax1 = 63;
const int quicVarintMax2 = 16383;
const int quicVarintMax4 = 1073741823;
const int quicVarint2Prefix = 0x4000;
const int quicVarint4Prefix = 0x80000000;
const int quicVarint8Prefix = 0xC0;
const int quicVarintPrefixShift = 6;
const int quicVarintPrefixMask = 0x3f;

// ---------------------------------------------------------------------------
// QUIC loss recovery (RFC 9002) and the RFC 9000 constants it depends on.
// Protocol sizes stay here. recovery.dart / congestion.dart consume the names.
// ---------------------------------------------------------------------------

/// RFC 9002 §6.1.1. Packets this many numbers older than the largest
/// acknowledged packet are lost.
const int quicPacketThreshold = 3;

/// RFC 9002 §6.1.2. Time threshold is 9/8 of the larger RTT sample.
const int quicTimeThresholdNumerator = 9;
const int quicTimeThresholdDenominator = 8;

/// RFC 9002 §6.1.2. Timer granularity, one millisecond, in microseconds.
const int quicGranularityMicros = 1000;

/// RFC 9002 §5.3. `smoothed_rtt` is 7/8 of the previous estimate plus 1/8
/// of the adjusted sample. `rttvar` is 3/4 of the previous variance plus
/// 1/4 of the absolute residual. The PTO period uses `4 * rttvar`.
const int quicRttSmoothNumerator = 7;
const int quicRttSmoothDenominator = 8;
const int quicRttVarNumerator = 3;
const int quicRttVarDenominator = 4;
const int quicRttVarPtoMultiplier = 4;

/// RFC 9002 §6.2.2. RTT used until the first sample (333 milliseconds).
const int quicInitialRttMicros = 333000;

/// RFC 9000 §18.2. Default `max_ack_delay` (25 milliseconds).
const int quicMaxAckDelayMicros = 25000;

/// RFC 9000 §18.2. Default `ack_delay_exponent` (delay × 2^3 microseconds).
const int quicAckDelayExponentDefault = 3;

/// RFC 9002 §7.2. Recommended initial window, in maximum datagrams.
const int quicInitialWindowDatagrams = 10;

/// RFC 9002 §7.2. Minimum congestion window, in maximum datagrams.
const int quicMinimumWindowDatagrams = 2;

/// RFC 9002 §7.2. Byte cap on the initial window (RFC 6928 raised for UDP).
const int quicInitialWindowFloorBytes = 14720;

/// RFC 9002 §7.6.1. Persistent congestion is this many PTO periods.
const int quicPersistentCongestionThreshold = 3;

/// RFC 9002 §7. Multiplicative decrease is 1/2.
const int quicLossReductionNumerator = 1;
const int quicLossReductionDenominator = 2;

/// Local probe budget (OPEN-15). Not an RFC 9002 constant.
///
/// `max_idle_timeout` (RFC 9000 §10.1) is not negotiated, so without this
/// cap a peer that never ACKs would arm PTO forever.
const int quicMaxPtoCount = 8;

/// RFC 9002 §6.2.4. A PTO sends one ack-eliciting probe and may send a
/// second. Both ignore the congestion window (Section 7.5).
const int quicPtoProbePackets = 2;

/// 1-RTT short header counted in `bytes_in_flight`: flags, DCID, 4-byte
/// packet number, AEAD tag. The payload is not included.
const int quicShortHeaderOverhead =
    1 + quicShortDcidBytes + quicPacketNumberMaxBytes + aeadTagBytes;

/// Initial long header for an 8-byte DCID, 8-byte SCID, empty token, and a
/// 2-byte length varint, plus the 4-byte packet number and AEAD tag.
const int quicInitialHeaderOverhead =
    1 +
    4 +
    1 +
    quicShortDcidBytes +
    1 +
    quicShortDcidBytes +
    1 +
    2 +
    quicPacketNumberMaxBytes +
    aeadTagBytes;

/// RFC 9002 §7.2 initial congestion window in bytes.
///
/// `min(10 × maxDatagramSize, max(14720, 2 × maxDatagramSize))`.
int quicInitialCongestionWindow(int maxDatagramSize) {
  final ten = quicInitialWindowDatagrams * maxDatagramSize;
  final twice = quicMinimumWindowDatagrams * maxDatagramSize;
  final limit = quicInitialWindowFloorBytes > twice
      ? quicInitialWindowFloorBytes
      : twice;
  return ten < limit ? ten : limit;
}

/// RFC 9002 §7.2 minimum congestion window in bytes.
int quicMinimumCongestionWindow(int maxDatagramSize) =>
    quicMinimumWindowDatagrams * maxDatagramSize;

/// Encoded size of a QUIC variable-length integer (RFC 9000 §16).
int quicVarintLength(int value) {
  if (value <= quicVarintMax1) return 1;
  if (value <= quicVarintMax2) return 2;
  if (value <= quicVarintMax4) return 4;
  return 8;
}

/// Payload bytes that make a client Initial datagram at least
/// [quicMinClientInitialUdpBytes] (RFC 9000 §14.1, RFC 9002 §6.2.1).
///
/// Padding is applied to the UDP datagram, not by inflating the frame
/// payload to 1200 and then adding the long header on top. [payloadLength]
/// is what the packet already carries; the return value is never smaller.
/// An empty token is assumed. The length field's own size is included.
int quicClientInitialPayloadBytes({
  required int dcidLength,
  required int scidLength,
  required int payloadLength,
}) {
  final prefix = 1 + 4 + 1 + dcidLength + 1 + scidLength + 1;
  var payload = payloadLength < 0 ? 0 : payloadLength;
  while (true) {
    final bodyLen = quicPacketNumberMaxBytes + payload + aeadTagBytes;
    final lengthField = quicVarintLength(bodyLen);
    final total =
        prefix +
        lengthField +
        quicPacketNumberMaxBytes +
        payload +
        aeadTagBytes;
    if (total >= quicMinClientInitialUdpBytes) {
      final extra = total - quicMinClientInitialUdpBytes;
      if (extra > 0 &&
          payload - extra >= (payloadLength < 0 ? 0 : payloadLength)) {
        final shrunk = payload - extra;
        final shrunkLen = quicPacketNumberMaxBytes + shrunk + aeadTagBytes;
        if (quicVarintLength(shrunkLen) == lengthField) return shrunk;
      }
      return payload;
    }
    final deficit = quicMinClientInitialUdpBytes - total;
    payload += deficit > 0 ? deficit : 1;
  }
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

const int http3FrameData = 0x00;
const int http3FrameHeaders = 0x01;
const int http3FrameCancelPush = 0x03;
const int http3FrameSettings = 0x04;
const int http3FramePushPromise = 0x05;
const int http3FrameGoaway = 0x07;
const int http3FrameMaxPushId = 0x0d;
const int httpMaxHeaderBytes = 65536;

const int http3StreamTypeControl = 0x00;
const int http3StreamTypePush = 0x01;
const int http3StreamTypeQpackEncoder = 0x02;
const int http3StreamTypeQpackDecoder = 0x03;

const int http3SettingsQpackMaxTableCapacity = 0x01;
const int http3SettingsMaxFieldSectionSize = 0x06;
const int http3SettingsQpackBlockedStreams = 0x07;
const int http3DefaultQpackMaxTableCapacity = 4096;
const int http3DefaultQpackBlockedStreams = 16;

const String httpAlpnH1 = 'http/1.1';
const String httpAlpnH2 = 'h2';
const String httpAlpnH3 = 'h3';

/// RFC 7858 DNS-over-TLS ALPN.
const String dnsAlpnDot = 'dot';

/// RFC 7858 default port.
const int dnsDotPort = 853;

/// RFC 8484 media type for the DNS wire format on HTTP.
const String dnsMessageMediaType = 'application/dns-message';

/// RFC 8484 URI template expression. Only this form is expanded.
const String dohTemplateQuery = '{?dns}';

/// RFC 9113 §3.4 connection preface. ASCII, 24 bytes.
const String http2ConnectionPreface = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
const int http2PrefaceBytes = 24;
const int http2FrameHeaderBytes = 9;
const int http2DefaultMaxFrameSize = 16384;
const int http2MinMaxFrameSize = 16384;
const int http2MaxMaxFrameSize = 16777215;
const int http2DefaultHeaderTableSize = 4096;
const int http2DefaultInitialWindowSize = 65535;
const int http2MaxWindowSize = 0x7fffffff;
const int http2DefaultMaxConcurrentStreams = 100;
const int http2SettingEntryBytes = 6;
const int http2PriorityPayloadBytes = 5;
const int http2PingPayloadBytes = 8;
const int http2RstStreamPayloadBytes = 4;
const int http2WindowUpdatePayloadBytes = 4;
const int http2GoawayMinPayloadBytes = 8;
const int http2StreamIdMask = 0x7fffffff;
const int http2ClientInitialStreamId = 1;

const int http2FrameData = 0x00;
const int http2FrameHeaders = 0x01;
const int http2FramePriority = 0x02;
const int http2FrameRstStream = 0x03;
const int http2FrameSettings = 0x04;
const int http2FramePushPromise = 0x05;
const int http2FramePing = 0x06;
const int http2FrameGoaway = 0x07;
const int http2FrameWindowUpdate = 0x08;
const int http2FrameContinuation = 0x09;

const int http2FlagEndStream = 0x01;
const int http2FlagAck = 0x01;
const int http2FlagEndHeaders = 0x04;
const int http2FlagPadded = 0x08;
const int http2FlagPriority = 0x20;

const int http2SettingsHeaderTableSize = 0x01;
const int http2SettingsEnablePush = 0x02;
const int http2SettingsMaxConcurrentStreams = 0x03;
const int http2SettingsInitialWindowSize = 0x04;
const int http2SettingsMaxFrameSize = 0x05;
const int http2SettingsMaxHeaderListSize = 0x06;

const int hpackStaticTableLength = 61;
const int hpackEntryOverheadBytes = 32;
const int hpackIndexedMask = 0x80;
const int hpackLiteralIncremental = 0x40;
const int hpackLiteralIncrementalMask = 0xc0;
const int hpackTableSizeUpdate = 0x20;
const int hpackTableSizeUpdateMask = 0xe0;
const int hpackLiteralNever = 0x10;
const int hpackLiteralNeverMask = 0xf0;
const int hpackLiteralWithoutMask = 0xf0;
const int hpackHuffmanBit = 0x80;
const int hpackIntContinuation = 0x80;
const int hpackMaxIntegerShift = 28;
const int hpackHuffmanEosBits = 30;
const int hpackHuffmanMaxCodeBits = 30;

const int qpackStaticTableLength = 99;
const int qpackDefaultMaxTableCapacity = 0;
const int qpackIndexedMask = 0x80;
const int qpackLiteralNameRef = 0x40;
const int qpackLiteralNameRefMask = 0xc0;
const int qpackLiteralName = 0x20;
const int qpackLiteralNameMask = 0xe0;
const int qpackIndexedPostBase = 0x10;
const int qpackIndexedPostBaseMask = 0xf0;
const int qpackLiteralPostBase = 0x00;
const int qpackLiteralPostBaseMask = 0xf0;
const int qpackEncoderCapacity = 0x20;
const int qpackEncoderCapacityMask = 0xe0;
const int qpackEncoderInsertNameRef = 0x80;
const int qpackEncoderInsertLiteral = 0x40;
const int qpackEncoderInsertLiteralMask = 0xc0;
const int qpackEncoderDuplicateMask = 0xe0;
const int qpackDecoderSectionAck = 0x80;
const int qpackDecoderStreamCancel = 0x40;
const int qpackDecoderStreamCancelMask = 0xc0;
const int qpackDecoderInsertCountIncMask = 0xc0;
