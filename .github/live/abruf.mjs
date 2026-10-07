// Tägliche Aktualisierung der Schiffsposition für das Projektportal (GitHub Actions, Node ≥ 22, ohne npm-Pakete).
//
// Holt die letzte AIS-Position eines Schiffs und legt sie verschlüsselt neben die Portal-Seite (m/live.bin).
// Verschlüsselt wird mit dem öffentlichen Schlüssel des Portals (ECDH P-256 → HKDF-SHA256 → AES-256-GCM);
// den privaten Schlüssel hat nur die entsperrte Seite. Das Repo ist öffentlich – deshalb stehen im Log
// weder Positionen noch Zeiten noch Kennungen des Schiffs, und die MMSI kommt aus einem Secret.
//
// Umgebung:
//   SCHIFF_MMSI           MMSI des Schiffs (Secret)
//   AISSTREAM_API_KEY     Schlüssel von aisstream.io (Secret; kostenlos, Küstenstationen)
//   VESSELFINDER_USERKEY  optional (Secret): VesselFinder-API mit Satellit (Credits) – hat Vorrang
//   ZIEL                  Datei im Repo (Standard gmh-bess-dillfeld/m/live.bin)
//   PUB                   öffentlicher Schlüssel als JWK (Standard .github/live/gmh-bess-dillfeld.pub.json)
//   ENDE                  letzter Abruftag YYYY-MM-DD (danach tut der Workflow nichts mehr)
//   MINUTEN               Höchstdauer des Empfangs bei aisstream (Standard 20)
//   NACHLAUF_S            nach der ersten Position so lange auf Ziel/ETA warten (Standard 400 s)
//   AISSTREAM_URL, VF_URL nur für Tests

import { readFile, writeFile, mkdir, appendFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const env = process.env;
const CFG = {
  ziel: env.ZIEL || 'gmh-bess-dillfeld/m/live.bin',
  pub: env.PUB || '.github/live/gmh-bess-dillfeld.pub.json',
  ende: (env.ENDE || '').trim(),
  minuten: Number(env.MINUTEN || 20),
  nachlaufS: Number(env.NACHLAUF_S || 400),
  mmsi: (env.SCHIFF_MMSI || '').trim(),
  ais: (env.AISSTREAM_API_KEY || '').trim(),
  vf: (env.VESSELFINDER_USERKEY || '').trim(),
  aisUrl: env.AISSTREAM_URL || 'wss://stream.aisstream.io/v0/stream',
  vfUrl: env.VF_URL || 'https://api.vesselfinder.com/vessels',
  maxEintraege: 400,
};
const INFO = new TextEncoder().encode('entec-live-v1');
const log = (s) => console.log(s);
const hinweis = (s) => console.log(`::notice::${s}`);
const warnung = (s) => console.log(`::warning::${s}`);

async function zusammenfassung(text) {
  if (env.GITHUB_STEP_SUMMARY) { try { await appendFile(env.GITHUB_STEP_SUMMARY, text + '\n'); } catch {} }
}

// ---------- Hilfen ----------
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const rund = (x, n) => (x == null || !Number.isFinite(x)) ? null : Math.round(x * 10 ** n) / 10 ** n;
const gueltigLat = (v) => Number.isFinite(v) && v >= -90 && v <= 90;
const gueltigLon = (v) => Number.isFinite(v) && v >= -180 && v <= 180;

function isoAusAis(s) {
  // aisstream: "2026-10-08 04:51:37.318353 +0000 UTC" · VesselFinder: "2026-10-08 04:51:37 UTC"
  if (!s) return null;
  const m = String(s).match(/(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})/);
  if (!m) return null;
  const t = Date.parse(`${m[1]}T${m[2]}Z`);
  return Number.isFinite(t) ? new Date(t).toISOString().replace('.000Z', 'Z') : null;
}

function etaAusAis(eta, jetzt = new Date()) {
  // AIS-ETA ohne Jahr: {Month, Day, Hour, Minute}; 0/24/60 = nicht angegeben.
  if (!eta) return null;
  const mo = eta.Month, d = eta.Day;
  if (!mo || !d || mo > 12 || d > 31) return null;
  const h = (eta.Hour == null || eta.Hour >= 24) ? 0 : eta.Hour;
  const mi = (eta.Minute == null || eta.Minute >= 60) ? 0 : eta.Minute;
  // Jahr so wählen, dass die ETA zwischen einem Monat vor und elf Monaten nach jetzt liegt.
  for (const y of [jetzt.getUTCFullYear(), jetzt.getUTCFullYear() + 1, jetzt.getUTCFullYear() - 1]) {
    const t = Date.UTC(y, mo - 1, d, h, mi);
    const diff = (t - jetzt.getTime()) / 86400e3;
    if (diff >= -31 && diff <= 335) return new Date(t).toISOString().slice(0, 16) + 'Z';
  }
  return null;
}

const ziel = (s) => {
  const t = String(s || '').replace(/[^\x20-\x7e]/g, '').replace(/\s+/g, ' ').trim();
  return t ? t.slice(0, 40) : null;
};

// ---------- Verschlüsselung (identisch zur Entschlüsselung im Portal) ----------
async function verschluesseln(pubJwk, klartext) {
  const s = globalThis.crypto.subtle;
  const pub = await s.importKey('jwk', { kty: 'EC', crv: 'P-256', x: pubJwk.x, y: pubJwk.y }, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const eph = await s.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const ephRaw = new Uint8Array(await s.exportKey('raw', eph.publicKey));
  const bits = await s.deriveBits({ name: 'ECDH', public: pub }, eph.privateKey, 256);
  const hk = await s.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
  const key = await s.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: ephRaw, info: INFO }, hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = await s.encrypt({ name: 'AES-GCM', iv, additionalData: INFO }, key, new TextEncoder().encode(JSON.stringify(klartext)));
  return { e: b64u(ephRaw), i: b64u(iv), c: b64u(new Uint8Array(ct)) };
}

// ---------- Quelle 1: aisstream.io (WebSocket, nur Live-Meldungen) ----------
function ausAisstream() {
  return new Promise((resolve) => {
    const start = Date.now();
    const bisMs = CFG.minuten * 60e3;
    let pos = null, statisch = null, nPos = 0, ersteAt = 0, fertig = false, ws = null, versuche = 0, fatal = false;

    const ende = (grund) => {
      if (fertig) return;
      fertig = true;
      clearTimeout(tMax); clearInterval(tick);
      try { ws && ws.close(); } catch {}
      log(`aisstream: ${grund} – ${nPos} Positionsmeldung(en), Zieldaten ${statisch ? 'ja' : 'nein'}`);
      if (!pos) return resolve(fatal ? { fehler: true } : null);
      resolve({ ...pos, dest: statisch?.dest ?? null, eta: statisch?.eta ?? null, n: nPos, q: 'aisstream' });
    };
    const tMax = setTimeout(() => ende(pos ? 'Empfangszeit vorbei' : `keine Meldung in ${CFG.minuten} Minuten (außerhalb der Reichweite der Küstenstationen)`), bisMs);
    const tick = setInterval(() => {
      if (pos && statisch) ende('Position und Zieldaten empfangen');
      else if (pos && Date.now() - ersteAt > CFG.nachlaufS * 1e3) ende('Position empfangen');
    }, 1000);

    const verbinden = () => {
      versuche++;
      ws = new WebSocket(CFG.aisUrl);
      ws.binaryType = 'arraybuffer';
      ws.onopen = () => {
        log(versuche === 1 ? 'aisstream: verbunden' : `aisstream: erneut verbunden (Versuch ${versuche})`);
        ws.send(JSON.stringify({
          APIKey: CFG.ais,
          BoundingBoxes: [[[-90, -180], [90, 180]]],
          FiltersShipMMSI: [CFG.mmsi],
          FilterMessageTypes: ['PositionReport', 'LongRangeAisBroadcastMessage', 'ShipStaticData'],
        }));
      };
      ws.onmessage = (ev) => {
        let j;
        try { j = JSON.parse(typeof ev.data === 'string' ? ev.data : new TextDecoder().decode(ev.data)); } catch { return; }
        if (j && j.error) {
          fatal = true;
          warnung(`aisstream meldet: ${String(j.error).replace(/[^\w .,:;!?()-]/g, '').slice(0, 120)}`);
          return ende('Abbruch');
        }
        const typ = j?.MessageType, meta = j?.MetaData || {};
        if (String(meta.MMSI ?? meta.MMSI_String ?? '') !== CFG.mmsi) return;
        const m = j?.Message?.[typ];
        if (!m) return;
        if (typ === 'ShipStaticData') {
          statisch = { dest: ziel(m.Destination), eta: etaAusAis(m.Eta) };
          return;
        }
        const lat = Number(m.Latitude ?? meta.latitude), lon = Number(m.Longitude ?? meta.longitude);
        if (!gueltigLat(lat) || !gueltigLon(lon) || (lat === 0 && lon === 0)) return;
        const t = isoAusAis(meta.time_utc) || new Date().toISOString().replace(/\.\d+Z$/, 'Z');
        nPos++;
        if (!ersteAt) ersteAt = Date.now();
        if (pos && pos.t > t) return;
        const sog = Number(m.Sog), cog = Number(m.Cog), hdg = Number(m.TrueHeading);
        pos = {
          t, lat: rund(lat, 4), lon: rund(lon, 4),
          sog: Number.isFinite(sog) && sog < 102.2 ? rund(sog, 1) : null,
          cog: Number.isFinite(cog) && cog < 360 ? rund(cog, 1) : null,
          hdg: Number.isFinite(hdg) && hdg < 360 ? hdg : null,
          nav: Number.isFinite(Number(m.NavigationalStatus)) ? Number(m.NavigationalStatus) : null,
        };
      };
      ws.onerror = () => {};
      ws.onclose = (ev) => {
        if (fertig) return;
        const rest = bisMs - (Date.now() - start);
        if (pos && Date.now() - ersteAt > 30e3) return ende('Verbindung beendet');
        if (rest > 20e3 && versuche < 6) {
          log(`aisstream: Verbindung getrennt (Code ${ev?.code ?? '?'}), neuer Versuch in 10 s`);
          setTimeout(() => { if (!fertig) verbinden(); }, 10e3);
        } else ende('Verbindung beendet');
      };
    };
    verbinden();
  });
}

// ---------- Quelle 2: VesselFinder-API (optional, Credits; sat=1 = Satellit, falls neuer) ----------
async function ausVesselfinder() {
  const url = `${CFG.vfUrl}?userkey=${encodeURIComponent(CFG.vf)}&mmsi=${encodeURIComponent(CFG.mmsi)}&sat=1`;
  let r;
  try { r = await fetch(url, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(60e3) }); }
  catch { warnung('VesselFinder: keine Verbindung'); return null; }
  if (!r.ok) { warnung(`VesselFinder: HTTP ${r.status}`); return null; }
  let j;
  try { j = await r.json(); } catch { warnung('VesselFinder: Antwort nicht lesbar'); return null; }
  const a = Array.isArray(j) ? j[0]?.AIS : null;
  if (!a) {
    const fehler = j && (j.error || j.ERROR);
    warnung(`VesselFinder: keine Daten${fehler ? ` (${String(fehler).replace(/[^\w .,:;!?()-]/g, '').slice(0, 80)})` : ''}`);
    return null;
  }
  const lat = Number(a.LATITUDE), lon = Number(a.LONGITUDE);
  if (!gueltigLat(lat) || !gueltigLon(lon)) { warnung('VesselFinder: ungültige Position'); return null; }
  const num = (v, max) => { const n = Number(v); return Number.isFinite(n) && n < max ? n : null; };
  const eta = isoAusAis(a.ETA_AIS || a.ETA);
  log(`VesselFinder: Position erhalten (Quelle ${a.SRC === 'SAT' ? 'Satellit' : 'Küstenstation'})`);
  return {
    t: isoAusAis(a.TIMESTAMP), lat: rund(lat, 4), lon: rund(lon, 4),
    sog: rund(num(a.SPEED, 102.2), 1), cog: rund(num(a.COURSE, 360), 1), hdg: num(a.HEADING, 360),
    nav: Number.isFinite(Number(a.NAVSTAT)) ? Number(a.NAVSTAT) : null,
    dest: ziel(a.DESTINATION), eta: eta ? eta.slice(0, 16) + 'Z' : null,
    q: a.SRC === 'SAT' ? 'vesselfinder-sat' : 'vesselfinder',
  };
}

// ---------- Ablauf ----------
async function main() {
  const heute = new Date().toISOString().slice(0, 10);
  if (CFG.ende && heute > CFG.ende) {
    hinweis(`Abrufzeitraum beendet (${CFG.ende}) – der Workflow kann deaktiviert werden.`);
    await zusammenfassung('Abrufzeitraum beendet – nichts zu tun.');
    return 0;
  }
  if (!/^\d{9}$/.test(CFG.mmsi) || (!CFG.ais && !CFG.vf)) {
    hinweis('Noch nicht eingerichtet: Secrets SCHIFF_MMSI und AISSTREAM_API_KEY fehlen – nichts zu tun.');
    await zusammenfassung('Noch nicht eingerichtet (Secrets fehlen).');
    return 0;
  }
  const pubJwk = JSON.parse(await readFile(CFG.pub, 'utf8'));

  let fix = null, fehler = false;
  if (CFG.vf) fix = await ausVesselfinder();
  if (!fix && CFG.ais) {
    const r = await ausAisstream();
    if (r && r.fehler) fehler = true; else fix = r;
  }

  let doc = { v: 1, items: [] };
  try {
    const alt = JSON.parse(await readFile(CFG.ziel, 'utf8'));
    if (alt && alt.v === 1 && Array.isArray(alt.items)) doc = alt;
  } catch {}

  const jetzt = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  let neu = false;
  if (fix && fix.t && (!doc.letzte || fix.t > doc.letzte)) {
    doc.items.push(await verschluesseln(pubJwk, { ...fix, abruf: jetzt }));
    doc.items = doc.items.slice(-CFG.maxEintraege);
    doc.letzte = fix.t;
    neu = true;
  }
  doc.geprueft = jetzt;
  await mkdir(dirname(CFG.ziel), { recursive: true });
  await writeFile(CFG.ziel, JSON.stringify({ v: 1, geprueft: doc.geprueft, letzte: doc.letzte || null, items: doc.items }));

  const satz = neu ? 'Neue Position übernommen.' : (fix ? 'Keine neuere Position als beim letzten Abruf.' : 'Keine Position im Abrufzeitraum.');
  log(`${satz} Einträge gesamt: ${doc.items.length}`);
  await zusammenfassung(satz);
  if (fehler) { warnung('Abruf fehlgeschlagen – API-Schlüssel prüfen.'); return 1; }
  return 0;
}

export { verschluesseln, etaAusAis, isoAusAis };

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().then((code) => process.exit(code), (e) => {
    console.log(`::error::Unerwarteter Fehler: ${String(e && e.message || e).slice(0, 200)}`);
    process.exit(1);
  });
}
