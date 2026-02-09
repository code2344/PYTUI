const WebSocket = require('ws');

const PORT = process.env.PORT || 8080;
const wss = new WebSocket.Server({ port: PORT });

const clients = new Map(); // clientId -> { ws, nickname }

function broadcast(payload, exceptWs = null) {
  const msg = JSON.stringify(payload);
  for (const { ws } of clients.values()) {
    if (ws !== exceptWs && ws.readyState === WebSocket.OPEN) {
      ws.send(msg);
    }
  }
}

function sendTo(clientId, payload) {
  const entry = clients.get(clientId);
  if (!entry) {
    return false;
  }
  if (entry.ws.readyState === WebSocket.OPEN) {
    entry.ws.send(JSON.stringify(payload));
    return true;
  }
  return false;
}

wss.on('connection', (ws) => {
  let currentClientId = null;

  ws.on('message', (data) => {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch (err) {
      return;
    }

    if (msg.type === 'hello') {
      const { clientId, nickname } = msg;
      if (!clientId || !nickname) {
        ws.send(JSON.stringify({ type: 'error', message: 'Missing clientId or nickname.' }));
        return;
      }

      currentClientId = clientId;
      clients.set(clientId, { ws, nickname });

      ws.send(JSON.stringify({
        type: 'welcome',
        clientId,
        nickname,
        online: Array.from(clients.entries()).map(([id, info]) => ({
          clientId: id,
          nickname: info.nickname
        }))
      }));

      broadcast({ type: 'presence', clientId, nickname, status: 'online' }, ws);
      return;
    }

    if (!currentClientId) {
      ws.send(JSON.stringify({ type: 'error', message: 'Client not registered. Send hello first.' }));
      return;
    }

    if (msg.type === 'list_request') {
      ws.send(JSON.stringify({
        type: 'list_response',
        online: Array.from(clients.entries()).map(([id, info]) => ({
          clientId: id,
          nickname: info.nickname
        }))
      }));
      return;
    }

    if (['chat_request', 'chat_accept', 'public_key', 'encrypted'].includes(msg.type)) {
      const targetId = msg.to;
      if (!targetId) {
        ws.send(JSON.stringify({ type: 'error', message: 'Missing target clientId.' }));
        return;
      }

      const delivered = sendTo(targetId, msg);
      if (!delivered) {
        ws.send(JSON.stringify({ type: 'error', message: `Client ${targetId} not online.` }));
      }
      return;
    }
  });

  ws.on('close', () => {
    if (currentClientId && clients.has(currentClientId)) {
      const { nickname } = clients.get(currentClientId);
      clients.delete(currentClientId);
      broadcast({ type: 'presence', clientId: currentClientId, nickname, status: 'offline' });
    }
  });
});

console.log(`Server running on ws://localhost:${PORT}`);
