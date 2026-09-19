import { createHash, randomUUID } from 'node:crypto';
import Corestore from 'corestore';
import Autobase from 'autobase';
import Hyperdrive from 'hyperdrive';
import Hyperswarm from 'hyperswarm';

const HEX = /^[0-9a-f]{64}$/;
const MAX_REPORT_BYTES = 64 * 1024;
export const codeHash = code => createHash('sha256').update(code).digest('hex');

function validFinding(value) {
  const a = value?.artifact;
  return value?.type === 'finding' && typeof value.id === 'string' &&
    /^[0-9a-f-]{36}$/.test(value.id) && HEX.test(value.codeHash) &&
    a && HEX.test(a.driveKey) && HEX.test(a.sha256) &&
    Number.isSafeInteger(a.version) && a.version > 0 &&
    a.path === `/reviews/${value.id}.txt`;
}

// SAM carries tool calls. This store's Hypercore streams carry workspace data.
export async function openWorkspace({ directory, bootstrapKey, network = true, readTimeoutMs = 3000, onError = console.error }) {
  if (!directory) throw new Error('WORKSPACE_DIRECTORY_REQUIRED');
  if (bootstrapKey && !HEX.test(bootstrapKey)) throw new Error('INVALID_KEY');
  if (!Number.isSafeInteger(readTimeoutMs) || readTimeoutMs <= 0) throw new Error('INVALID_TIMEOUT');
  const store = new Corestore(directory);
  const base = new Autobase(store, bootstrapKey ? Buffer.from(bootstrapKey, 'hex') : null, {
    valueEncoding: 'json', ackInterval: 1000,
    open: viewStore => viewStore.get('findings', { valueEncoding: 'json' }),
    async apply(nodes, view, host) {
      for (const node of nodes) {
        const value = node.value;
        if (value?.type === 'writer.add') {
          if (node.from.key.equals(host.key) && HEX.test(value.key)) {
            await host.addWriter(Buffer.from(value.key, 'hex'), { indexer: false });
          }
        } else if (validFinding(value)) {
          await view.append({ ...value, author: node.from.key.toString('hex') });
        }
      }
    },
  });
  base.on('error', onError);
  const drive = new Hyperdrive(store.namespace('reports'));
  const remoteDrives = new Map();
  let swarm;
  let closed = false;
  try {
    await base.ready();
    await drive.ready();
    if (network) {
      swarm = new Hyperswarm();
      swarm.on('error', onError);
      swarm.on('connection', socket => {
        socket.on('error', onError);
        base.replicate(socket).on('error', onError);
      });
      swarm.join(base.discoveryKey, { server: true, client: true });
    }
  } catch (err) {
    if (swarm) await swarm.destroy();
    await Promise.allSettled([drive.close(), base.close()]);
    await store.close();
    throw err;
  }

  return {
    info() {
      return {
        baseKey: base.key.toString('hex'), writerKey: base.local.key.toString('hex'),
        driveKey: drive.key.toString('hex'), writable: base.writable,
      };
    },
    replicate: connection => base.replicate(connection),
    async admitWriter(key) {
      if (!base.local.key.equals(base.key)) throw new Error('FOUNDER_ONLY');
      if (!HEX.test(key)) throw new Error('INVALID_KEY');
      await base.append({ type: 'writer.add', key });
    },
    async publishFinding({ codeHash: hash, report }) {
      if (!base.writable) throw new Error('NOT_WRITABLE');
      if (!HEX.test(hash) || typeof report !== 'string') throw new Error('INVALID_FINDING');
      if (Buffer.byteLength(report) > MAX_REPORT_BYTES) throw new Error('REPORT_TOO_LARGE');
      const id = randomUUID();
      const path = `/reviews/${id}.txt`;
      await drive.put(path, Buffer.from(report));
      const finding = {
        type: 'finding', id, codeHash: hash,
        artifact: { driveKey: drive.key.toString('hex'), version: drive.version, path, sha256: codeHash(report) },
      };
      await base.append(finding);
      return { ...finding, author: base.local.key.toString('hex') };
    },
    async listFindings({ codeHash: hash, limit = 20 } = {}) {
      if (hash !== undefined && !HEX.test(hash)) throw new Error('INVALID_CODE_HASH');
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error('INVALID_LIMIT');
      await base.update();
      const snapshot = base.view.snapshot({ valueEncoding: 'json' });
      try {
        await snapshot.ready();
        const findings = [];
        const seen = new Set();
        for (let i = snapshot.length - 1; i >= 0 && findings.length < limit; i--) {
          const row = await snapshot.get(i);
          if (hash !== undefined && row.codeHash !== hash) continue;
          const key = `${row.author}:${row.id}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push(row);
        }
        return findings;
      } finally { await snapshot.close(); }
    },
    async readFinding(finding) {
      if (!validFinding(finding)) throw new Error('INVALID_FINDING');
      const key = finding.artifact.driveKey;
      let remote = key === drive.key.toString('hex') ? drive : remoteDrives.get(key);
      if (!remote) {
        remote = new Hyperdrive(store.namespace(`read/${key}`), Buffer.from(key, 'hex'));
        remoteDrives.set(key, remote);
      }
      let snapshot;
      let timer;
      try {
        const read = async () => {
          await remote.ready();
          snapshot = remote.checkout(finding.artifact.version);
          const entry = await snapshot.entry(finding.artifact.path, { timeout: readTimeoutMs });
          if (!entry?.value.blob) throw new Error('ARTIFACT_UNAVAILABLE');
          if (entry.value.blob.byteLength > MAX_REPORT_BYTES) throw new Error('REPORT_TOO_LARGE');
          const bytes = await snapshot.get(finding.artifact.path, { timeout: readTimeoutMs });
          if (!bytes) throw new Error('ARTIFACT_UNAVAILABLE');
          if (codeHash(bytes) !== finding.artifact.sha256) throw new Error('HASH_MISMATCH');
          return bytes.toString('utf8');
        };
        return await Promise.race([
          read(),
          new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('ARTIFACT_UNAVAILABLE')), readTimeoutMs); }),
        ]);
      } catch (err) {
        if (['HASH_MISMATCH', 'REPORT_TOO_LARGE'].includes(err.message)) throw err;
        throw new Error('ARTIFACT_UNAVAILABLE', { cause: err });
      } finally {
        clearTimeout(timer);
        if (snapshot) await snapshot.close();
      }
    },
    async close() {
      if (closed) return;
      closed = true;
      if (swarm) await swarm.destroy();
      for (const remote of remoteDrives.values()) await remote.close();
      await drive.close();
      await base.close();
      await store.close();
    },
  };
}
