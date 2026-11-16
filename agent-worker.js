// Local autonomous agent: polls Ciphera, establishes E2E sessions, and uses Ollama.
const fs = require('node:fs');
const path = require('node:path');
const { CipheraAgent } = require('./agent-client');

const id = process.argv[2];
if (!['nexa', 'orion'].includes(id)) {
  console.error('Uso: node agent-worker.js nexa|orion');
  process.exit(1);
}
const peerId = id === 'nexa' ? 'orion' : 'nexa';
const secret = process.env[id === 'nexa' ? 'CIPHERA_AGENT_A_SECRET' : 'CIPHERA_AGENT_B_SECRET'] || `${id}-local-demo-key`;
const baseUrl = process.env.CIPHERA_URL || 'http://localhost:8000';
const ollamaUrl = process.env.OLLAMA_URL || 'http://localhost:11434/api/chat';
const model = process.env[`${id.toUpperCase()}_MODEL`] || process.env.OLLAMA_MODEL || 'llama3.2';
const dataPath = path.join(__dirname, 'data', `${id}.json`);
const privateData = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
const agent = new CipheraAgent({ baseUrl, agentId: id, secret });
const sessions = new Map();
const maxTurns = Number(process.env.CIPHERA_MAX_TURNS || 8);

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function askLocalModel(history) {
  const response = await fetch(ollamaUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model, stream: false, messages: [
      { role: 'system', content: `Sei l'agente ${id} dell'organizzazione ${privateData.organization}. Rispondi in italiano, con chiarezza e in massimo 120 parole. Usa solo queste informazioni aziendali autorizzate; non inventare dati e non rivelare informazioni non incluse qui. Se una richiesta eccede ciò che puoi condividere, dichiaralo. Dati disponibili: ${JSON.stringify(privateData.context)}` },
      ...history,
    ] }),
  });
  if (!response.ok) throw new Error(`Ollama ha risposto HTTP ${response.status}`);
  const data = await response.json();
  return data.message?.content?.trim() || 'Non ho una risposta disponibile al momento.';
}

async function main() {
  await agent.authenticate();
  console.log(`[${id}] autenticato; modello locale: ${model}; peer: ${peerId}`);
  while (true) {
    try {
      const conversations = await agent.conversations();
      for (const conversation of conversations) {
        let state = sessions.get(conversation.id);
        if (!state) {
          state = { ready: false, lastId: 0, turns: 0, greeted: false, history: [] };
          sessions.set(conversation.id, state);
        }
        if (!state.ready) {
          const result = await agent.joinHandshake(conversation.id);
          state.ready = result.ready;
          if (!state.ready) continue;
          console.log(`[${id}] sessione ${conversation.id} cifrata e pronta`);
        }
        if (id === conversation.agent_a && !state.greeted) {
          await agent.send(conversation.id, `Ciao, sono l'agente ${id} di ${privateData.organization}. Possiamo confrontare le informazioni che ciascuno è autorizzato a condividere.`);
          state.greeted = true;
        }
        const incoming = await agent.receive(conversation.id, state.lastId);
        for (const message of incoming) {
          state.lastId = Math.max(state.lastId, message.id);
          state.history.push({ role: 'user', content: String(message.content) });
          console.log(`[${id}] ricevuto messaggio cifrato dalla sessione ${conversation.id}`);
          if (state.turns >= maxTurns) continue;
          const answer = await askLocalModel(state.history.slice(-12));
          await agent.send(conversation.id, answer);
          state.history.push({ role: 'assistant', content: answer });
          state.turns += 1;
          console.log(`[${id}] risposta cifrata inviata (${state.turns}/${maxTurns})`);
        }
      }
    } catch (error) {
      console.error(`[${id}] ${error.message}`);
    }
    await delay(1500);
  }
}

main();
