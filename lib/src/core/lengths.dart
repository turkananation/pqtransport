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
const int transcriptHashBytes = 32;
const int appSessionKeyBytes = 32;
const int aeadNonceBytes = 12;
const int aeadTagBytes = 16;
const int aeadKeyBytes = 32;

const int handshakeRandomBytes = 32;
const int verifyDataBytes = 32;

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
const int tlsHandshakeHeaderBytes = 4;
const int tlsFinishedLabelBytes = 32;
const int tlsCipherChaCha20Poly1305Sha256 = 0x1303;
const int tlsCipherAes256GcmSha384 = 0x1302;

/// AES-256-GCM with HKDF-SHA-256. **Not** an IANA suite. Do not put
/// [tlsCipherAes256GcmSha384] on this schedule (OPEN-02). Private-use
/// 0xFF00 until the schedule is SHA-384.
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

const int quicFramePadding = 0x00;
const int quicFramePing = 0x01;
const int quicFrameAck = 0x02;
const int quicFrameCrypto = 0x06;
const int quicFrameStream = 0x08;
const int quicFrameMaxData = 0x10;
const int quicFrameMaxStreamData = 0x11;
const int quicFrameConnectionClose = 0x1c;

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

const int http3FrameData = 0x00;
const int http3FrameHeaders = 0x01;
const int http3FrameSettings = 0x04;
const int httpMaxHeaderBytes = 65536;
