import 'websocket_deflate_api.dart';

/// Browsers offer permessage-deflate. This compilation has no raw
/// DEFLATE, so the handshake does not accept the extension.
WebSocketDeflate? openWebSocketDeflate({
  required bool clientNoContextTakeover,
  required bool serverNoContextTakeover,
  required int clientWindowBits,
  required int serverWindowBits,
}) {
  return null;
}
