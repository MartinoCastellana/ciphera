# Ciphera

Ciphera è un prototipo locale per coordinare la comunicazione tra due agenti AI appartenenti a organizzazioni diverse. Il server gestisce identità, token, handshake e inoltro dei messaggi; i contenuti restano cifrati end-to-end e non vengono salvati in chiaro nel database.

## Avvio

Richiede Python 3.10+, Node.js 18+ e un server Ollama locale con il modello configurato disponibile.

```bash
python3 server.py
```

Apri http://localhost:8000. Il database SQLite viene creato in `data/ciphera.db` al primo avvio. Avvia poi i due agenti locali, in terminali separati:

```bash
node agent-worker.js nexa
node agent-worker.js orion
```

La dashboard crea una sessione chiedendo il secret dell'agente iniziatore; i worker autenticati la trovano automaticamente tramite l'API, stabiliscono il canale cifrato e iniziano uno scambio limitato. Ogni worker legge solo il proprio file (`data/nexa.json` o `data/orion.json`) e usa Ollama (`llama3.2` per default). Configura `NEXA_MODEL`, `ORION_MODEL`, `OLLAMA_URL` o `CIPHERA_MAX_TURNS` per cambiare il comportamento. Le credenziali locali di esempio sono configurate in `server.py`; imposta `CIPHERA_SECRET`, `CIPHERA_AGENT_A_SECRET` e `CIPHERA_AGENT_B_SECRET` prima di un uso diverso da quello locale.

## API

- `POST /api/auth/token` — emette un bearer JWT a scadenza per un agente.
- `POST /api/handshakes` — avvia una sessione tra agenti autenticati.
- `POST /api/handshakes/{id}/keys` — registra la chiave pubblica effimera dell'agente.
- `POST /api/handshakes/{id}/messages` — inoltra un payload cifrato end-to-end.
- `GET /api/dashboard` — statistiche e metadati delle sessioni (nessun contenuto in chiaro).
- `GET /api/agents/conversations` — restituisce all'agente autenticato le sessioni a cui partecipa.
- `GET /api/handshakes/{id}/messages?after=ID` — recupera messaggi cifrati destinati all'agente.
- `GET /api/health` — stato del servizio.

Le chiavi effimere sono generate dagli agenti. Ciphera non possiede le chiavi private e non può decifrare i messaggi. Il trasporto va esposto solo dietro HTTPS in ambienti condivisi. Questo prototipo non sostituisce un audit crittografico o una gestione di segreti di produzione.

## Client degli agenti

`agent-client.js` usa le primitive crittografiche native di Node.js (X25519, HKDF-SHA256 e AES-256-GCM). Autenticare ciascun agente, creare una sessione con `createHandshake`, quindi chiamare `joinHandshake(id)` da entrambi gli agenti fino a ottenere `ready: true`. A quel punto `send(id, messaggio)` cifra prima dell'invio e `receive(id, ultimoId)` recupera e decifra i nuovi messaggi. `agent-worker.js` implementa il polling, il completamento automatico degli handshake e un dialogo limitato tramite Ollama.

```js
const { CipheraAgent } = require('./agent-client');
const agent = new CipheraAgent({ agentId: 'nexa', secret: process.env.AGENT_SECRET });
await agent.authenticate();
const session = await agent.createHandshake('orion');
// L'altro agente deve unirsi alla stessa sessione e completare lo scambio chiavi.
await agent.joinHandshake(session.handshake_id);
```

Ogni processo agente deve conservare la propria istanza e la chiave effimera in memoria per la durata della sessione.
