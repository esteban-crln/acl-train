'use strict';
/* sim.js : trajet d'un paquet dans Ro — ACL, NAT/PAT, redirection de ports, inspection
   Ordre du cours : sens IN = ACL puis redirection de ports ; sens OUT = NAT puis ACL. */

function connectedIface(ip) {
  return IFACES.find(i => i.id !== 'S0/0' && IP.inNet(ip, i.net, i.prefix)) || null;
}
function ownerIface(ip) {
  return IFACES.find(i => i.ipn === ip) || null;
}

function portOk(ps, port) {
  if (!ps) return true;
  if (port == null) return false;
  switch (ps.op) {
    case 'eq': return ps.ports.includes(port);
    case 'neq': return port !== ps.a;
    case 'lt': return port < ps.a;
    case 'gt': return port > ps.a;
    case 'range': return port >= ps.a && port <= ps.b;
  }
  return false;
}

// la règle correspond-elle au paquet (sans tenir compte de la plage horaire) ?
function entryMatch(type, e, p) {
  if (!IP.match(p.src, e.src.base, e.src.wild)) return false;
  if (type === 'standard') return true;
  if (e.proto !== 'ip' && e.proto !== p.proto) return false;
  if (!IP.match(p.dst, e.dst.base, e.dst.wild)) return false;
  if ((p.proto === 'tcp' || p.proto === 'udp') && e.proto !== 'ip') {
    if (!portOk(e.srcPort, p.sport) || !portOk(e.dstPort, p.dport)) return false;
  }
  if (e.established && !(p.proto === 'tcp' && p.ack)) return false;
  if (e.icmp && !(p.proto === 'icmp' && p.icmp === e.icmp)) return false;
  return true;
}

// pourquoi la règle ne correspond pas (pour les explications du quiz)
function entryMismatch(type, e, p) {
  if (!IP.match(p.src, e.src.base, e.src.wild)) return 'source';
  if (type === 'standard') return null;
  if (e.proto !== 'ip' && e.proto !== p.proto) return 'protocole';
  if (!IP.match(p.dst, e.dst.base, e.dst.wild)) return 'destination';
  if ((p.proto === 'tcp' || p.proto === 'udp') && e.proto !== 'ip') {
    if (!portOk(e.srcPort, p.sport)) return 'port source';
    if (!portOk(e.dstPort, p.dport)) return 'port';
  }
  if (e.established && !(p.proto === 'tcp' && p.ack)) return 'established';
  if (e.icmp && !(p.proto === 'icmp' && p.icmp === e.icmp)) return 'type icmp';
  return null;
}

function evalAcl(cfg, name, p, date, count) {
  const acl = cfg.acls[name];
  if (!acl) return { verdict: 'permit', missing: true, inactive: [] };
  const inactive = [];
  for (const e of acl.entries) {
    if (e.remark != null) continue;
    if (!entryMatch(acl.type, e, p)) continue;
    if (e.timeRange) {
      const tr = cfg.timeRanges[e.timeRange];
      if (!tr || !trActive(tr, date)) { inactive.push(e); continue; }
    }
    if (count) e.matches = (e.matches || 0) + 1;
    return { verdict: e.action, entry: e, inactive };
  }
  return { verdict: 'deny', implicit: true, inactive };
}

function pktStr(p) {
  const a = (ip, port) => IP.toStr(ip) + (p.proto === 'icmp' || port == null ? '' : ':' + port);
  const proto = p.proto === 'icmp' ? 'icmp ' + p.icmp : p.proto;
  return `${a(p.src, p.sport)} → ${a(p.dst, p.dport)} (${proto}${p.ack ? ', ACK' : ''})`;
}
const ipPort = (ip, port) => IP.toStr(ip) + (port == null ? '' : ':' + port);

function aclStep(cfg, ifId, dir, p, date, count) {
  const name = cfg.ifaces[ifId][dir];
  if (!name) return { type: 'pass', ok: true, iface: ifId, dir, text: `${ifId} ${dir} : aucune ACL appliquée.` };
  const r = evalAcl(cfg, name, p, date, count);
  const acl = cfg.acls[name];
  const ok = r.verdict === 'permit';
  let text;
  if (r.missing) text = `${ifId} ${dir} · ACL ${name} : elle n'existe pas, donc tout passe.`;
  else if (r.implicit) text = `${ifId} ${dir} · ACL ${name} : aucune ligne ne correspond → deny implicite.`;
  else text = `${ifId} ${dir} · ACL ${name}, ligne ${r.entry.seq} « ${fmtEntry(r.entry, acl.type)} » → ${ok ? 'autorisé' : 'bloqué'}.`;
  if (r.inactive.length) {
    const s = r.inactive.length > 1;
    text += ` Ligne${s ? 's' : ''} ${r.inactive.map(e => e.seq).join(', ')} ignorée${s ? 's' : ''} : plage horaire inactive à ce moment.`;
  }
  return { type: 'acl', iface: ifId, dir, ok, text, acl: name, seq: r.entry ? r.entry.seq : null };
}

const INSPECT_APPS = {
  http: ['tcp', 80], https: ['tcp', 443], smtp: ['tcp', 25], ftp: ['tcp', 21], pop3: ['tcp', 110],
  imap: ['tcp', 143], dns: ['udp', 53], tftp: ['udp', 69], ntp: ['udp', 123],
};
function inspectCovers(list, p) {
  return list.some(x => {
    if (x === p.proto) return true;
    const a = INSPECT_APPS[x];
    return a && a[0] === p.proto && a[1] === p.dport;
  });
}

/* ---------- aller ---------- */
function sendRequest(cfg, spec, date, count = false) {
  const R = { steps: [], hops: [], delivered: false, atIp: null, final: null, natSrc: null, natDst: null, ingress: null, egress: null, sessions: [], noReturn: false, sameNet: false, stop: null };
  const icmp = spec.proto === 'icmp';
  const p = { src: spec.src, dst: spec.dst, proto: spec.proto, sport: icmp ? null : (spec.sport || 50123), dport: icmp ? null : spec.dport, icmp: icmp ? 'echo' : null, ack: false };
  const add = (type, ok, text, extra) => R.steps.push(Object.assign({ type, ok, text }, extra || {}));
  R.hops.push({ k: 'host', ip: p.src });
  add('emit', null, 'Paquet émis : ' + pktStr(p));

  const srcIf = connectedIface(p.src);
  const ing = srcIf ? srcIf.id : 'S0/0';
  R.ingress = ing;
  if (srcIf && IP.inNet(p.dst, srcIf.net, srcIf.prefix) && !ownerIface(p.dst)) {
    R.sameNet = true; R.delivered = true; R.atIp = p.dst; R.final = Object.assign({}, p);
    add('info', true, 'Même réseau que la source : le paquet passe par le switch sans traverser Ro. Aucune ACL du routeur ne le voit.');
    R.hops.push({ k: 'host', ip: p.dst });
    return R;
  }
  if (!srcIf && !ownerIface(p.dst)) {
    if (IP.isPrivate(p.dst)) {
      add('drop', false, `Sur Internet, ${IP.toStr(p.dst)} est une adresse privée (RFC 1918) : elle n'est pas routable. Depuis Internet, on vise l'adresse publique 200.0.0.254.`);
      R.stop = 'src';
      return R;
    }
    add('info', true, "Trafic entre deux machines d'Internet : il ne passe pas par Ro.");
    R.sameNet = true; R.delivered = true; R.atIp = p.dst; R.final = Object.assign({}, p);
    R.hops.push({ k: 'host', ip: p.dst });
    return R;
  }

  // 1. ACL en entrée
  R.hops.push({ k: 'if', id: ing });
  let s = aclStep(cfg, ing, 'in', p, date, count);
  R.steps.push(s);
  if (!s.ok) { R.stop = 'in'; return R; }

  // 2. paquet adressé au routeur : redirection de ports ?
  const own = ownerIface(p.dst);
  if (own) {
    const fromOutside = cfg.ifaces[ing].nat === 'outside' && own.id === ing;
    const st = fromOutside
      ? cfg.natStatic.find(x => x.outIp === p.dst && (x.proto === null || (x.proto === p.proto && x.outPort === p.dport)))
      : null;
    if (!st) {
      R.hops.push({ k: 'router' });
      let why;
      if (own.id === ing && ing === 'S0/0' && cfg.ifaces[ing].nat !== 'outside') {
        why = `Le paquet vise 200.0.0.254, l'adresse de Ro. S0/0 n'est pas marquée « ip nat outside » : aucune redirection ne s'applique, le paquet s'arrête au routeur.`;
      } else if (fromOutside) {
        why = `Aucune redirection de port pour ${icmp ? 'icmp' : p.proto + '/' + p.dport} vers ${IP.toStr(p.dst)} : le paquet s'arrête au routeur.`;
      } else {
        why = `Le paquet est destiné à Ro lui-même (${IP.toStr(p.dst)}) : il s'arrête au routeur.`;
      }
      add('drop', false, why);
      R.stop = 'router';
      return R;
    }
    const before = ipPort(p.dst, p.dport);
    R.natDst = { pubIp: p.dst, pubPort: p.dport, inIp: st.inIp, inPort: st.inPort != null ? st.inPort : p.dport };
    p.dst = st.inIp;
    if (st.inPort != null) p.dport = st.inPort;
    add('nat', true, `Redirection de port (après l'ACL d'entrée) : ${before} → ${ipPort(p.dst, p.dport)}.`, { iface: ing });
  }

  // 3. routage
  const dIf = connectedIface(p.dst);
  const eg = dIf ? dIf.id : 'S0/0';
  R.egress = eg;
  if (eg === ing) {
    R.hops.push({ k: 'router' });
    add('drop', false, "Ro devrait renvoyer le paquet par son interface d'entrée : ce trafic ne le concerne pas.");
    R.stop = 'router';
    return R;
  }
  if (!dIf && IP.isPrivate(p.dst)) {
    R.hops.push({ k: 'router' });
    add('drop', false, `${IP.toStr(p.dst)} est une adresse privée inconnue de Ro : pas de route.`);
    R.stop = 'router';
    return R;
  }
  if (R.natDst && cfg.ifaces[eg].nat !== 'inside') {
    R.hops.push({ k: 'router' });
    add('drop', false, `La redirection exige que ${eg} soit marquée « ip nat inside » : la NAT traduit entre une interface outside et une interface inside.`);
    R.stop = 'router';
    return R;
  }
  R.hops.push({ k: 'router' });
  add('route', true, `Routage : sortie par ${eg} (${ZONES[IFACE_BY_ID[eg].zone].name}${dIf ? ', réseau directement connecté' : ', route par défaut'}).`);

  // 4. NAT/PAT de la source (avant l'ACL de sortie)
  if (cfg.ifaces[eg].nat === 'outside' && IP.isPrivate(p.src)) {
    if (cfg.ifaces[ing].nat !== 'inside') {
      add('info', null, `Pas de NAT : ${ing} n'est pas marquée « ip nat inside ».`);
    } else {
      const st = cfg.natStatic.find(x => x.proto === null && x.inIp === p.src);
      const dyn = st ? null : cfg.natDyn.find(d => d.iface === eg && cfg.acls[d.list] && evalAcl(cfg, d.list, p, date, false).verdict === 'permit');
      if (st || dyn) {
        const pub = st ? st.outIp : IFACE_BY_ID[eg].ipn;
        R.natSrc = { inIp: p.src, inPort: p.sport, pubIp: pub, pubPort: p.sport };
        const before = ipPort(p.src, p.sport);
        p.src = pub;
        add('nat', true, `NAT/PAT (avant l'ACL de sortie) : source ${before} → ${ipPort(p.src, p.sport)}.`, { iface: eg });
        if (count && !st) {
          cfg.natTable.push([p.proto, ipPort(pub, p.sport), ipPort(R.natSrc.inIp, R.natSrc.inPort), ipPort(p.dst, p.dport), ipPort(p.dst, p.dport)]);
          if (cfg.natTable.length > 20) cfg.natTable.shift();
        }
      } else {
        add('info', null, cfg.natDyn.length
          ? "Aucune règle NAT ne s'applique : l'adresse n'est pas permise par l'ACL de NAT. La source reste privée."
          : "Pas de « ip nat inside source list … » : la source reste privée.");
      }
    }
  }

  // 5. ACL en sortie
  R.hops.push({ k: 'if', id: eg });
  s = aclStep(cfg, eg, 'out', p, date, count);
  R.steps.push(s);
  if (!s.ok) { R.stop = 'out'; return R; }

  // 6. livraison
  R.hops.push({ k: 'host', ip: p.dst });
  R.delivered = true;
  R.atIp = p.dst;
  R.final = Object.assign({}, p);
  const h = HOST_BY_IP[p.dst];
  add('deliver', true, `Arrivé : ${h ? h.name : IP.toStr(p.dst)} reçoit ${pktStr(p)}.`);
  if (eg === 'S0/0' && IP.isPrivate(p.src)) {
    R.noReturn = true;
    add('warn', false, "La source est restée privée : sur Internet, la réponse ne pourra jamais revenir. Il manque la NAT/PAT.");
  }

  // 7. inspection : le routeur mémorise la session
  const insIn = cfg.ifaces[ing].inspectIn, insOut = cfg.ifaces[eg].inspectOut;
  if (insIn && cfg.inspect[insIn] && inspectCovers(cfg.inspect[insIn], p)) {
    R.sessions.push({ iface: ing, dir: 'in', name: insIn });
    add('inspect', true, `Inspection ${insIn} sur ${ing} in : session mémorisée, la réponse sera acceptée en sortie de ${ing}.`);
  }
  if (insOut && cfg.inspect[insOut] && inspectCovers(cfg.inspect[insOut], p)) {
    R.sessions.push({ iface: eg, dir: 'out', name: insOut });
    add('inspect', true, `Inspection ${insOut} sur ${eg} out : session mémorisée, la réponse sera acceptée en entrée de ${eg}.`);
  }
  return R;
}

/* ---------- retour ---------- */
function sendReply(cfg, R, date, count = false) {
  if (!R.delivered) return null;
  const Q = { steps: [], hops: [], delivered: false, stop: null };
  const add = (type, ok, text, extra) => Q.steps.push(Object.assign({ type, ok, text }, extra || {}));
  const f = R.final;
  const p = { src: f.dst, dst: f.src, proto: f.proto, sport: f.dport, dport: f.sport, icmp: f.proto === 'icmp' ? 'echo-reply' : null, ack: f.proto === 'tcp' };
  Q.hops.push({ k: 'host', ip: p.src });
  add('emit', null, 'Réponse émise : ' + pktStr(p));
  if (R.sameNet) {
    Q.delivered = true;
    Q.hops.push({ k: 'host', ip: p.dst });
    add('deliver', true, 'La réponse revient directement, sans passer par Ro.');
    return Q;
  }
  if (R.noReturn) {
    add('drop', false, `La réponse vise ${IP.toStr(p.dst)}, une adresse privée : elle se perd sur Internet. Il faut la NAT/PAT.`);
    Q.stop = 'src';
    return Q;
  }
  const ing = R.egress, eg = R.ingress;

  Q.hops.push({ k: 'if', id: ing });
  const sIn = R.sessions.find(x => x.iface === ing && x.dir === 'out');
  if (sIn) {
    add('inspect', true, `${ing} in : réponse reconnue par l'inspection ${sIn.name}, acceptée sans consulter l'ACL.`, { iface: ing, dir: 'in' });
  } else {
    const s = aclStep(cfg, ing, 'in', p, date, count);
    Q.steps.push(s);
    if (!s.ok) { Q.stop = 'in'; return Q; }
  }
  if (R.natSrc) {
    const before = ipPort(p.dst, p.dport);
    p.dst = R.natSrc.inIp;
    p.dport = R.natSrc.inPort;
    add('nat', true, `PAT inverse : ${before} → ${ipPort(p.dst, p.dport)}.`, { iface: ing });
  }
  Q.hops.push({ k: 'router' });
  add('route', true, `Routage : retour par ${eg}.`);
  if (R.natDst) {
    const before = ipPort(p.src, p.sport);
    p.src = R.natDst.pubIp;
    p.sport = R.natDst.pubPort;
    add('nat', true, `Redirection inverse : la source ${before} redevient ${ipPort(p.src, p.sport)}.`, { iface: eg });
  }
  Q.hops.push({ k: 'if', id: eg });
  const sOut = R.sessions.find(x => x.iface === eg && x.dir === 'in');
  if (sOut) {
    add('inspect', true, `${eg} out : réponse reconnue par l'inspection ${sOut.name}, acceptée sans consulter l'ACL.`, { iface: eg, dir: 'out' });
  } else {
    const s = aclStep(cfg, eg, 'out', p, date, count);
    Q.steps.push(s);
    if (!s.ok) { Q.stop = 'out'; return Q; }
  }
  Q.hops.push({ k: 'host', ip: p.dst });
  Q.delivered = true;
  const h = HOST_BY_IP[p.dst];
  add('deliver', true, `Réponse reçue par ${h ? h.name : IP.toStr(p.dst)}.`);
  return Q;
}
