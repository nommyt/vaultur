import { DurableObject } from 'cloudflare:workers';
import { encode } from '@msgpack/msgpack';
import type { Bindings } from '../env';

/**
 * WebSocket hub for Bitwarden's SignalR-style /notifications/hub protocol.
 *
 * Bitwarden clients connect with `?access_token=...` and speak SignalR over
 * MessagePack. We implement the minimal subset vaultwarden implements:
 *  - handshake: client sends `{"protocol":"messagepack","version":1}\x1e`, server replies `{}\x1e`
 *  - server → client: type-1 (Invocation) messages with target "ReceiveMessage"
 *  - client → server pings (type 6) answered with pings
 *
 * One DO instance per user id; vault mutation endpoints POST /publish here.
 */
export class NotificationsHub extends DurableObject<Bindings> {
  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname.endsWith('/connect')) {
      if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
        return new Response('Expected websocket', { status: 426 });
      }
      const pair = new WebSocketPair();
      const [client, server] = [pair[0], pair[1]];
      this.ctx.acceptWebSocket(server);
      return new Response(null, { status: 101, webSocket: client });
    }

    if (url.pathname.endsWith('/publish') && request.method === 'POST') {
      // Body is a pre-encoded SignalR MessagePack frame (built in the Worker)
      const frame = new Uint8Array(await request.arrayBuffer());
      for (const ws of this.ctx.getWebSockets()) {
        try {
          ws.send(frame);
        } catch {
          // ignore dead sockets; runtime will reap them
        }
      }
      return new Response(null, { status: 204 });
    }

    return new Response('Not found', { status: 404 });
  }

  override async webSocketMessage(ws: WebSocket, message: ArrayBuffer | string): Promise<void> {
    // SignalR JSON handshake ends with 0x1e
    if (typeof message === 'string' && message.endsWith('')) {
      ws.send('{}');
      return;
    }
    // MessagePack ping (type 6) → reply with ping
    if (typeof message !== 'string') {
      const bytes = new Uint8Array(message);
      // [0x91, 0x06] length-prefixed → respond with same ping frame
      if (bytes.length >= 2) {
        ws.send(PING_FRAME);
      }
    }
  }

  override async webSocketClose(): Promise<void> {
    // nothing to clean up — sockets are managed by the runtime
  }
}

/** SignalR binary frames are length-prefixed with a varint. */
function withVarintLength(body: Uint8Array): Uint8Array {
  const lengthBytes: number[] = [];
  let length = body.length;
  do {
    let byte = length & 0x7f;
    length >>>= 7;
    if (length > 0) byte |= 0x80;
    lengthBytes.push(byte);
  } while (length > 0);
  const out = new Uint8Array(lengthBytes.length + body.length);
  out.set(lengthBytes, 0);
  out.set(body, lengthBytes.length);
  return out;
}

/** Type 6 = Ping */
const PING_FRAME = withVarintLength(encode([6]));
