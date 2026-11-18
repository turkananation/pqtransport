import 'dart:typed_data';

/// RFC 7692 raw DEFLATE for one message.
///
/// [compress] returns the deflate block with the trailing
/// `00 00 ff ff` already removed. [decompress] puts that trailer
/// back before inflate. The VM engine is `dart:io`. The web engine
/// refuses the extension. Neither path is `dart:ffi`.
abstract interface class WebSocketDeflate {
  Uint8List compress(Uint8List message);

  Uint8List decompress(Uint8List payload);
}
