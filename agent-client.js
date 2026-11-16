// Minimal Node.js agent SDK. Private X25519 keys stay in this process.
const crypto = require('node:crypto');

class CipheraAgent {
  constructor({ baseUrl = 'http://localhost:8000', agentId, secret }) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.agentId = agentId;
    this.secret = secret;
    this.token = null;
    this.sessions = new Map();
  }

  async request(path, { method = 'GET', body, auth = true } = {}) {
    if (auth && (!this.token || this.tokenExpiresAt <= Math.floor(Date.now() / 1000) + 30)) await this.authenticate();
    const headers = { 'content-type': 'application/json' };
    if (auth && this.token) headers.authorization = `Bearer ${this.token}`;
    const response = await fetch(`${this.baseUrl}${path}`, {
      method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || data.error || `HTTP ${response.status}`);
    return data;
  }

  async authenticate() {
    const result = await this.request('/api/auth/token', {
      method: 'POST', auth: false,
      body: { agent_id: this.agentId, secret: this.secret },
    });
    this.token = result.access_token;
    this.tokenExpiresAt = result.expires_at;
    return result;
  }

  async createHandshake(peerId) {
    return this.request('/api/handshakes', { method: 'POST', body: { peer_id: peerId } });
  }

  async conversations() {
    return (await this.request('/api/agents/conversations')).conversations;
  }

  async joinHandshake(handshakeId) {
    let session = this.sessions.get(handshakeId);
    if (!session) {
      const pair = crypto.generateKeyPairSync('x25519');
      session = { privateKey: pair.privateKey, publicKey: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64') };
      this.sessions.set(handshakeId, session);
    }
    const result = await this.request(`/api/handshakes/${handshakeId}/keys`, {
      method: 'POST', body: { public_key: session.publicKey },
    });
    if (result.peer_public_key) {
      const peerKey = crypto.createPublicKey({ key: Buffer.from(result.peer_public_key, 'base64'), type: 'spki', format: 'der' });
      const sharedSecret = crypto.diffieHellman({ privateKey: session.privateKey, publicKey: peerKey });
      session.aesKey = Buffer.from(crypto.hkdfSync('sha256', sharedSecret, Buffer.from(handshakeId), Buffer.from('ciphera-e2e-v1'), 32));
      session.privateKey = null;
      session.publicKey = null;
    }
    return { status: result.status, ready: Boolean(session.aesKey) };
  }

  async send(handshakeId, message) {
    const session = this.sessions.get(handshakeId);
    if (!session?.aesKey) throw new Error('Handshake non pronto: completa joinHandshake da entrambi gli agenti.');
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', session.aesKey, nonce);
    const ciphertext = Buffer.concat([cipher.update(typeof message === 'string' ? message : JSON.stringify(message)), cipher.final(), cipher.getAuthTag()]);
    return this.request(`/api/handshakes/${handshakeId}/messages`, {
      method: 'POST', body: { nonce: nonce.toString('base64'), ciphertext: ciphertext.toString('base64') },
    });
  }

  async receive(handshakeId, after = 0) {
    const session = this.sessions.get(handshakeId);
    if (!session?.aesKey) throw new Error('Chiave sessione non disponibile.');
    const { messages } = await this.request(`/api/handshakes/${handshakeId}/messages?after=${after}`);
    return messages.map((item) => {
      const bytes = Buffer.from(item.ciphertext, 'base64');
      const decipher = crypto.createDecipheriv('aes-256-gcm', session.aesKey, Buffer.from(item.nonce, 'base64'));
      decipher.setAuthTag(bytes.subarray(bytes.length - 16));
      const cleartext = Buffer.concat([decipher.update(bytes.subarray(0, -16)), decipher.final()]).toString();
      let content;
      try { content = JSON.parse(cleartext); } catch { content = cleartext; }
      return { id: item.id, sender_id: item.sender_id, created_at: item.created_at, content };
    });
  }
}

module.exports = { CipheraAgent };
