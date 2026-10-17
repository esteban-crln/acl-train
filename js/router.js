'use strict';
/* router.js : configuration de Ro et interpréteur de commandes façon Cisco IOS */

const ICMP_TYPES = ['echo', 'echo-reply', 'unreachable', 'time-exceeded'];
const INSPECT_PROTOS = ['tcp', 'udp', 'icmp', 'http', 'https', 'dns', 'smtp', 'ftp', 'pop3', 'imap', 'tftp', 'ntp'];
const DAY_WORDS = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday', 'daily', 'weekdays', 'weekend'];
const DAY_INDEX = { sunday: 0, monday: 1, tuesday: 2, wednesday: 3, thursday: 4, friday: 5, saturday: 6 };
const MONTHS_EN = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
const PORT_OPS = ['eq', 'neq', 'lt', 'gt', 'range'];

function aclTypeForNumber(n) {
  if ((n >= 1 && n <= 99) || (n >= 1300 && n <= 1999)) return 'standard';
  if ((n >= 100 && n <= 199) || (n >= 2000 && n <= 2699)) return 'extended';
  return null;
}

function newConfig() {
  const ifaces = {};
  for (const i of IFACES) ifaces[i.id] = { in: null, out: null, nat: null, inspectIn: null, inspectOut: null, desc: '' };
  return { hostname: 'Ro', acls: {}, ifaces, timeRanges: {}, inspect: {}, natDyn: [], natStatic: [], natTable: [] };
}

/* ---------- formatage des règles ---------- */
function portName(p, proto) {
  const m = PORT_DISPLAY[proto];
  return (m && m[p]) || String(p);
}
function fmtPorts(ps, proto) {
  if (!ps) return '';
  if (ps.op === 'eq') return 'eq ' + ps.ports.map(p => portName(p, proto)).join(' ');
  if (ps.op === 'range') return `range ${portName(ps.a, proto)} ${portName(ps.b, proto)}`;
  return `${ps.op} ${portName(ps.a, proto)}`;
}
function fmtAddr(a) {
  if (a.wild === 0xFFFFFFFF) return 'any';
  if (a.wild === 0) return 'host ' + IP.toStr(a.base);
  return IP.toStr(a.base) + ' ' + IP.toStr(a.wild);
}
// forme « running-config », sans numéro de séquence
function fmtEntry(e, type) {
  if (e.remark != null) return 'remark ' + e.remark;
  if (type === 'standard') return `${e.action} ${fmtAddr(e.src)}${e.log ? ' log' : ''}`;
  const parts = [e.action, e.proto, fmtAddr(e.src)];
  if (e.srcPort) parts.push(fmtPorts(e.srcPort, e.proto));
  parts.push(fmtAddr(e.dst));
  if (e.dstPort) parts.push(fmtPorts(e.dstPort, e.proto));
  if (e.icmp) parts.push(e.icmp);
  if (e.established) parts.push('established');
  if (e.log) parts.push('log');
  if (e.timeRange) parts.push('time-range ' + e.timeRange);
  return parts.join(' ');
}
// forme « show access-lists »
function fmtEntryShow(e, type) {
  if (e.remark != null) return null;
  if (type === 'standard') {
    const a = e.src;
    let s;
    if (a.wild === 0xFFFFFFFF) s = 'any';
    else if (a.wild === 0) s = IP.toStr(a.base);
    else s = `${IP.toStr(a.base)}, wildcard bits ${IP.toStr(a.wild)}`;
    return `${e.action.padEnd(6)} ${s}${e.log ? ' log' : ''}`;
  }
  return fmtEntry(e, type).replace(/^deny /, 'deny   ');
}
function fmtIosDate(d) {
  const mon = MONTHS_EN[d.getMonth()];
  return `${hhmm(d)} ${pad2(d.getDate())} ${mon[0].toUpperCase() + mon.slice(1)} ${d.getFullYear()}`;
}
function aclSort(a, b) {
  const na = /^\d+$/.test(a.name), nb = /^\d+$/.test(b.name);
  if (na && nb) return +a.name - +b.name;
  if (na !== nb) return na ? -1 : 1;
  return a.name.localeCompare(b.name);
}

/* ---------- plages horaires ---------- */
function trActive(tr, date) {
  if (tr.absolute) {
    const { start, end } = tr.absolute;
    if (start && date < start) return false;
    if (end && date > end) return false;
  }
  if (!tr.periodic.length) return true;
  const d = date.getDay(), m = date.getHours() * 60 + date.getMinutes();
  return tr.periodic.some(p => {
    if (p.span) {
      const wk = (day, mm) => ((day + 6) % 7) * 1440 + mm;
      const now = wk(d, m), s = wk(p.startDay, p.from), e = wk(p.endDay, p.to);
      return s <= e ? now >= s && now <= e : now >= s || now <= e;
    }
    return p.days.includes(d) && m >= p.from && m <= p.to;
  });
}

/* ---------- couverture d'une règle par une autre (lignes jamais atteintes) ---------- */
function portRanges(ps) {
  if (!ps) return [[0, 65535]];
  switch (ps.op) {
    case 'eq': return ps.ports.map(p => [p, p]);
    case 'range': return [[ps.a, ps.b]];
    case 'lt': return ps.a > 0 ? [[0, ps.a - 1]] : [];
    case 'gt': return ps.a < 65535 ? [[ps.a + 1, 65535]] : [];
    case 'neq': return [[0, ps.a - 1], [ps.a + 1, 65535]].filter(r => r[0] <= r[1]);
  }
  return [];
}
function rangesCover(A, B) {
  const sorted = [...A].sort((x, y) => x[0] - y[0]);
  return B.every(([lo, hi]) => {
    let cur = lo;
    for (const [a, b] of sorted) {
      if (a <= cur && b >= cur) cur = b + 1;
      if (cur > hi) return true;
    }
    return cur > hi;
  });
}
function addrCovers(A, B) {
  return ((B.wild & ~A.wild) >>> 0) === 0 && IP.match(B.base, A.base, A.wild);
}
function covers(a, b, type) {
  if (!addrCovers(a.src, b.src)) return false;
  if (type === 'standard') return true;
  if (a.proto !== 'ip' && a.proto !== b.proto) return false;
  if (!addrCovers(a.dst, b.dst)) return false;
  if (a.proto === 'tcp' || a.proto === 'udp') {
    if (!rangesCover(portRanges(a.srcPort), portRanges(b.srcPort))) return false;
    if (!rangesCover(portRanges(a.dstPort), portRanges(b.dstPort))) return false;
  }
  if (a.established && !b.established) return false;
  if (a.icmp && a.icmp !== b.icmp) return false;
  return true;
}

/* ---------- lecture de la ligne de commande ---------- */
class CliError extends Error {
  constructor(kind, pos, help, msg) {
    super(msg || kind);
    this.kind = kind;
    this.pos = pos;
    this.help = help;
  }
}

class Cursor {
  constructor(line) {
    this.line = line;
    this.toks = [];
    const re = /\S+/g;
    let m;
    while ((m = re.exec(line))) this.toks.push({ text: m[0], pos: m.index });
    this.i = 0;
  }
  done() { return this.i >= this.toks.length; }
  peek() { return this.toks[this.i] || null; }
  peekLow() { const t = this.peek(); return t ? t.text.toLowerCase() : null; }
  next() { return this.toks[this.i++] || null; }
  pos() { const t = this.peek(); return t ? t.pos : this.line.length; }
  fail(help) { throw new CliError('invalid', this.pos(), help); }
  incomplete(help) { throw new CliError('incomplete', null, help); }
  rest() {
    const t = this.peek();
    this.i = this.toks.length;
    return t ? this.line.slice(t.pos).trim() : '';
  }
  // mot-clé, abréviations Cisco acceptées (conf t, int g0/0, sh access-l…)
  match(options) {
    const t = this.peekLow();
    if (t == null) return null;
    if (options.includes(t)) return t;
    const m = options.filter(o => o.startsWith(t));
    if (m.length === 1) return m[0];
    if (m.length > 1) throw new CliError('ambiguous', this.pos(), 'Abréviation ambiguë : tape quelques lettres de plus.', `% Ambiguous command:  "${this.peek().text}"`);
    return null;
  }
  kw(options, help) {
    if (this.done()) this.incomplete(help);
    const w = this.match(options);
    if (!w) this.fail(help);
    this.i++;
    return w;
  }
  optKw(options) {
    if (this.done()) return null;
    const w = this.match(options);
    if (w) this.i++;
    return w;
  }
  word(help) {
    if (this.done()) this.incomplete(help);
    return this.next().text;
  }
  endOrFail(help) {
    if (!this.done()) this.fail(help || 'Il y a des mots en trop à la fin de la commande.');
  }
}

const MODE_CMDS = {
  user:   ['enable', 'show', 'exit', 'logout'],
  priv:   ['configure', 'show', 'disable', 'exit', 'clear', 'copy', 'write', 'end'],
  config: ['access-list', 'ip', 'interface', 'time-range', 'no', 'hostname', 'do', 'exit', 'end'],
  if:     ['ip', 'no', 'shutdown', 'description', 'exit', 'end', 'do'],
  nacl:   ['permit', 'deny', 'remark', 'no', 'exit', 'end', 'do'],
  tr:     ['periodic', 'absolute', 'no', 'exit', 'end', 'do'],
};

const MODE_HELP = {
  user: [
    ['enable', 'Passer en mode privilégié (Ro#)'],
    ['show …', 'Afficher des informations'],
  ],
  priv: [
    ['configure terminal', 'Entrer en configuration globale (conf t)'],
    ['show access-lists', 'Voir les ACL et leurs compteurs'],
    ['show running-config', 'Voir toute la configuration (show run)'],
    ['show ip interface brief', 'Voir les interfaces et leurs adresses'],
    ['show ip interface G0/0', 'Voir les ACL appliquées sur une interface'],
    ['show time-range', 'Voir les plages horaires (active ou non)'],
    ['show ip nat translations', 'Voir les redirections et traductions NAT'],
    ['clear access-list counters', 'Remettre les compteurs à zéro'],
    ['disable', 'Revenir en mode utilisateur'],
  ],
  config: [
    ['access-list N …', 'ACL numérotée : 1-99 standard, 100-199 étendue'],
    ['ip access-list standard|extended NOM', 'ACL nommée'],
    ['interface G0/0 | G0/1.x | S0/0', 'Configurer une interface'],
    ['time-range NOM', 'Définir une plage horaire'],
    ['ip inspect name NOM tcp|udp|icmp…', 'Règle d\'inspection (filtrage avec état)'],
    ['ip nat inside source …', 'NAT/PAT ou redirection de ports'],
    ['no …', 'Supprimer une commande'],
    ['do show …', 'Lancer un show sans quitter la config'],
    ['end', 'Revenir en mode privilégié'],
  ],
  if: [
    ['ip access-group NOM in|out', 'Appliquer une ACL dans un sens'],
    ['ip nat inside|outside', 'Rôle de l\'interface pour la NAT'],
    ['ip inspect NOM in|out', 'Inspecter les requêtes dans ce sens'],
    ['no ip access-group NOM in|out', 'Retirer une ACL'],
    ['exit', 'Revenir en configuration globale'],
  ],
  'nacl-std': [
    ['[seq] permit|deny source', 'Ajouter une règle (seq optionnel, ex. 15)'],
    ['no SEQ', 'Supprimer la ligne SEQ (ex. no 20)'],
    ['remark texte', 'Ajouter un commentaire'],
    ['exit', 'Revenir en configuration globale'],
  ],
  'nacl-ext': [
    ['[seq] permit|deny proto src [port] dst [port]', 'Ajouter une règle (seq optionnel, ex. 15)'],
    ['no SEQ', 'Supprimer la ligne SEQ (ex. no 20)'],
    ['remark texte', 'Ajouter un commentaire'],
    ['exit', 'Revenir en configuration globale'],
  ],
  tr: [
    ['periodic jours HH:MM to HH:MM', 'Créneau récurrent (weekdays, weekend, daily, monday…)'],
    ['absolute start HH:MM JJ Mois AAAA end …', 'Période datée (mois en anglais : Nov, Dec…)'],
    ['no periodic …', 'Retirer un créneau'],
    ['exit', 'Revenir en configuration globale'],
  ],
};

const COMPLETE = {
  user: { '': ['enable', 'show'] },
  priv: {
    '': ['configure', 'show', 'clear', 'copy', 'write', 'disable'],
    'configure': ['terminal'], 'clear': ['access-list'], 'clear access-list': ['counters'],
    'copy': ['running-config'], 'copy running-config': ['startup-config'],
  },
  config: {
    '': ['access-list', 'ip', 'interface', 'time-range', 'no', 'hostname', 'do', 'exit', 'end'],
    'ip': ['access-list', 'nat', 'inspect'], 'ip access-list': ['standard', 'extended', 'resequence'],
    'ip nat': ['inside'], 'ip nat inside': ['source'], 'ip nat inside source': ['list', 'static'],
    'ip nat inside source static': ['tcp', 'udp'], 'ip inspect': ['name'],
    'no': ['access-list', 'ip', 'time-range'], 'no ip': ['access-list', 'nat', 'inspect'],
    'no ip access-list': ['standard', 'extended'], 'interface': '@ifaces',
  },
  if: {
    '': ['ip', 'no', 'exit', 'end', 'do', 'description', 'shutdown', 'interface'],
    'ip': ['access-group', 'nat', 'inspect'], 'ip nat': ['inside', 'outside'],
    'no': ['ip', 'shutdown'], 'no ip': ['access-group', 'nat', 'inspect'], 'no ip nat': ['inside', 'outside'],
    'ip access-group': '@acls', 'ip inspect': '@inspects', 'interface': '@ifaces',
  },
  nacl: {
    '': ['permit', 'deny', 'remark', 'no', 'exit', 'end', 'do'],
  },
  tr: {
    '': ['periodic', 'absolute', 'no', 'exit', 'end'],
    'periodic': DAY_WORDS, 'absolute': ['start', 'end'], 'no': ['periodic', 'absolute'],
  },
  common: {
    'show': ['access-lists', 'running-config', 'ip', 'time-range', 'clock'],
    'show ip': ['interface', 'nat', 'access-lists', 'inspect', 'route'],
    'show ip interface': ['brief'], 'show ip nat': ['translations'], 'show access-lists': '@acls',
  },
};
const GENERIC_WORDS = ['permit', 'deny', 'any', 'host', 'eq', 'neq', 'range', 'gt', 'lt', 'established', 'time-range', 'log',
  'in', 'out', 'tcp', 'udp', 'icmp', 'ip', 'echo', 'echo-reply', 'overload', 'interface', 'list', 'static', 'inside', 'outside',
  'extendable', 'to', 'start', 'end', 'www', 'domain', 'smtp', 'telnet', 'ftp', 'pop3', ...DAY_WORDS];

class Router {
  constructor() {
    this.cfg = newConfig();
    this.mode = 'priv';
    this.curIf = null;
    this.curAcl = null;
    this.curTr = null;
    this.clock = parseWhen('mar 10:00');
    this.out = [];
  }

  prompt() {
    const h = this.cfg.hostname;
    switch (this.mode) {
      case 'user': return h + '>';
      case 'priv': return h + '#';
      case 'config': return h + '(config)#';
      case 'if': return h + (this.curIf.includes('.') ? '(config-subif)#' : '(config-if)#');
      case 'nacl': return h + (this.curAclType() === 'standard' ? '(config-std-nacl)#' : '(config-ext-nacl)#');
      case 'tr': return h + '(config-time-range)#';
    }
    return h + '#';
  }
  modeLabel() {
    return {
      user: 'mode utilisateur', priv: 'mode privilégié', config: 'configuration globale',
      if: 'interface ' + this.curIf, nacl: 'ACL ' + this.curAcl, tr: 'plage horaire ' + this.curTr,
    }[this.mode];
  }
  curAclType() {
    const a = this.cfg.acls[this.curAcl];
    return a ? a.type : 'extended';
  }

  say(t, cls = 'out') { this.out.push({ t, cls }); }
  tip(t) { this.say(t, 'tip'); }
  warn(t) { this.say(t, 'warn'); }
  err(msg, help) { throw new CliError('msg', null, help, msg); }

  // exécute sans rien afficher (config de départ des missions)
  runSilently(lines) {
    for (const l of lines) {
      const r = this.exec(l);
      if (r.error && typeof console !== 'undefined') console.warn('Config de départ :', l, r.lines.map(x => x.t).join(' / '));
    }
  }

  exec(raw) {
    this.out = [];
    const line = String(raw).replace(/\t/g, ' ');
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('!')) return { lines: [] };
    if (trimmed.endsWith('?')) {
      this.contextHelp(line.slice(0, line.lastIndexOf('?')));
      return { lines: this.out, help: true };
    }
    const c = new Cursor(line);
    try {
      this.dispatch(c, this.mode);
    } catch (e) {
      if (!(e instanceof CliError)) throw e;
      const lines = [];
      if (e.kind === 'invalid') lines.push({ t: "% Invalid input detected at '^' marker.", cls: 'err' });
      else if (e.kind === 'incomplete') lines.push({ t: '% Incomplete command.', cls: 'err' });
      else lines.push({ t: e.message, cls: 'err' });
      if (e.help) lines.push({ t: e.help, cls: 'tip' });
      return { lines, caret: e.kind === 'invalid' || e.kind === 'ambiguous' ? e.pos : null, error: true };
    }
    return { lines: this.out };
  }

  dispatch(c, mode) {
    if (mode === 'nacl' && /^\d+$/.test(c.peek().text)) return this.naclSeq(c);
    const w = c.match(MODE_CMDS[mode]);
    if (w) {
      c.i++;
      return this['c_' + mode + '_' + w.replace(/-/g, '_')](c);
    }
    // une commande globale tapée depuis un sous-mode : IOS remonte au mode config
    if (mode === 'if' || mode === 'nacl' || mode === 'tr') {
      const g = c.match(MODE_CMDS.config);
      if (g && !['no', 'do', 'exit', 'end'].includes(g)) return this.toConfig(c, c.i);
    }
    const low = c.peekLow();
    const cfgMode = !['user', 'priv'].includes(mode);
    if (cfgMode && low.length >= 2 && 'show'.startsWith(low)) {
      c.fail('En mode configuration, préfixe la commande par do : « do show access-lists », « do show run ».');
    }
    if (cfgMode && low.length >= 4 && 'configure'.startsWith(low)) {
      c.fail('Tu es déjà en mode configuration.');
    }
    if (!cfgMode) {
      let g = null;
      try { g = c.match(MODE_CMDS.config); } catch (e) { g = null; }
      if (g && !['exit', 'end', 'do'].includes(g)) {
        c.fail(mode === 'user'
          ? "Passe d'abord en mode privilégié (enable), puis en configuration (configure terminal)."
          : "Entre d'abord en configuration : configure terminal (ou conf t).");
      }
      if (mode === 'user' && low.length >= 4 && 'configure'.startsWith(low)) c.fail("Passe d'abord en mode privilégié : enable.");
    }
    c.fail(this.modeHint());
  }

  toConfig(c, start) {
    c.i = start;
    const saved = [this.mode, this.curIf, this.curAcl, this.curTr];
    this.mode = 'config';
    try {
      return this.dispatch(c, 'config');
    } catch (e) {
      [this.mode, this.curIf, this.curAcl, this.curTr] = saved;
      throw e;
    }
  }

  modeHint() {
    switch (this.mode) {
      case 'user': return 'Commande inconnue. Ici : enable, show… Tape « ? » pour l\'aide.';
      case 'priv': return 'Commande inconnue. Pour configurer : configure terminal (conf t). Tape « ? » pour la liste.';
      case 'config': return 'Commande inconnue. Ici : access-list, ip access-list, interface, time-range, ip inspect name, ip nat…, no …, do show …';
      case 'if': return `Tu es dans l'interface ${this.curIf} : ip access-group NOM in|out, ip nat inside|outside, ip inspect NOM in|out, exit.`;
      case 'nacl': return this.curAclType() === 'standard'
        ? `Tu es dans l'ACL standard ${this.curAcl} : [seq] permit|deny source, no SEQ, exit.`
        : `Tu es dans l'ACL étendue ${this.curAcl} : [seq] permit|deny protocole source [port] destination [port], no SEQ, exit.`;
      case 'tr': return `Tu es dans la plage horaire ${this.curTr} : periodic … ou absolute …, exit.`;
    }
    return '';
  }

  doCmd(c) {
    if (c.done()) c.incomplete('do show access-lists, do show run…');
    const saved = this.mode;
    this.mode = 'priv';
    try {
      const w = c.match(MODE_CMDS.priv);
      if (w === 'configure' || w === 'end' || w === 'exit' || w === 'disable') c.fail('Après do, lance plutôt un show : do show access-lists.');
      this.dispatch(c, 'priv');
    } finally {
      this.mode = saved;
    }
  }

  intArg(c, min, max, help) {
    const t = c.peek();
    if (!t) c.incomplete(help);
    if (!/^\d+$/.test(t.text) || +t.text < min || +t.text > max) c.fail(help);
    c.i++;
    return +t.text;
  }

  parseIface(c) {
    const help = 'Interfaces de Ro : G0/0 (DMZ), G0/1.0 (serveurs), G0/1.1 (filaire), G0/1.2 (wifi), S0/0 (Internet).';
    if (c.done()) c.incomplete(help);
    const t0 = c.peek();
    let s = t0.text;
    c.i++;
    if (/^[a-z]+$/i.test(s) && !c.done() && /^\d/.test(c.peek().text)) s += c.next().text;
    const m = /^([a-z]+)([\d/.]+)$/i.exec(s);
    const fail = h => { throw new CliError('invalid', t0.pos, h); };
    if (!m) fail(help);
    const kind = m[1].toLowerCase(), num = m[2];
    let type = null;
    if ('gigabitethernet'.startsWith(kind)) type = 'G';
    else if ('serial'.startsWith(kind)) type = 'S';
    else if ('fastethernet'.startsWith(kind) || 'ethernet'.startsWith(kind)) fail('Ro n\'a pas d\'interface FastEthernet : ' + help);
    else fail(help);
    if (type === 'G' && num === '0/1') fail('G0/1 est l\'interface physique (trunk). Les réseaux sont sur les sous-interfaces G0/1.0, G0/1.1 et G0/1.2.');
    const id = type + num;
    if (!IFACE_BY_ID[id]) fail(help);
    return id;
  }

  /* ===== mode utilisateur ===== */
  c_user_enable(c) { c.endOrFail(); this.mode = 'priv'; }
  c_user_show(c) { this.show(c); }
  c_user_exit() {}
  c_user_logout() {}

  /* ===== mode privilégié ===== */
  c_priv_configure(c) {
    c.optKw(['terminal']);
    c.endOrFail();
    this.mode = 'config';
    this.say('Enter configuration commands, one per line.  End with CNTL/Z.', 'dim');
  }
  c_priv_show(c) { this.show(c); }
  c_priv_disable() { this.mode = 'user'; }
  c_priv_exit() {
    this.mode = 'user';
    this.tip('Session console fermée (pour de faux). Tape enable pour revenir en mode privilégié.');
  }
  c_priv_end() {}
  c_priv_clear(c) {
    const help = 'clear access-list counters [NOM]';
    c.kw(['access-list'], help);
    c.kw(['counters'], help);
    const name = c.done() ? null : c.next().text;
    for (const a of Object.values(this.cfg.acls)) {
      if (!name || a.name === name) a.entries.forEach(e => { e.matches = 0; });
    }
  }
  c_priv_copy(c) {
    c.i = c.toks.length;
    this.say('Destination filename [startup-config]?', 'dim');
    this.say('Building configuration...', 'dim');
    this.say('[OK]');
  }
  c_priv_write(c) {
    c.i = c.toks.length;
    this.say('Building configuration...', 'dim');
    this.say('[OK]');
  }

  /* ===== configuration globale ===== */
  c_config_exit() { this.mode = 'priv'; }
  c_config_end() { this.mode = 'priv'; }
  c_config_do(c) { this.doCmd(c); }
  c_config_hostname(c) {
    const n = c.word('hostname NOM');
    c.endOrFail();
    if (!/^[A-Za-z][\w-]*$/.test(n)) c.fail('Le nom doit commencer par une lettre.');
    this.cfg.hostname = n;
  }

  c_config_interface(c) {
    const id = this.parseIface(c);
    c.endOrFail();
    this.mode = 'if';
    this.curIf = id;
  }

  c_config_time_range(c) {
    const name = c.word('Donne un nom à la plage horaire, ex. time-range MIDI.');
    if (!/^[A-Za-z][\w-]*$/.test(name)) { c.i--; c.fail('Le nom doit commencer par une lettre (ex. MIDI, WEEKEND).'); }
    c.endOrFail();
    if (!this.cfg.timeRanges[name]) this.cfg.timeRanges[name] = { name, periodic: [], absolute: null };
    this.mode = 'tr';
    this.curTr = name;
  }

  c_config_access_list(c) {
    const syn = 'access-list NUMÉRO {permit|deny} … — 1-99 : standard (source seule) · 100-199 : étendue (protocole, source, destination, ports).';
    const t = c.peek();
    if (!t) c.incomplete(syn);
    if (!/^\d+$/.test(t.text)) c.fail("Ici il faut le numéro de l'ACL (1-99 standard, 100-199 étendue). Pour une ACL nommée : ip access-list standard|extended NOM.");
    const n = +t.text;
    const type = aclTypeForNumber(n);
    if (!type) c.fail('Numéro hors plage : 1-99 ou 1300-1999 pour une standard, 100-199 ou 2000-2699 pour une étendue.');
    c.i++;
    const act = c.kw(['permit', 'deny', 'remark'], type === 'standard'
      ? `access-list ${n} {permit|deny} source [masque générique]`
      : `access-list ${n} {permit|deny} protocole source [port] destination [port]`);
    const name = String(n);
    if (act === 'remark') {
      this.addEntry(name, type, { remark: c.rest() });
      return;
    }
    const e = this.parseEntry(c, type, act);
    this.addEntry(name, type, e);
  }

  c_config_ip(c) {
    const w = c.kw(['access-list', 'nat', 'inspect', 'access-group', 'address', 'route'],
      "Après ip : access-list (ACL nommée), nat (traduction d'adresses), inspect (filtrage avec état).");
    if (w === 'access-group') { c.i--; c.fail("ip access-group s'utilise dans une interface : « interface G0/1.1 » puis « ip access-group NOM in|out »."); }
    if (w === 'address') { c.i--; c.fail("ip address se configure dans une interface, et ici l'adressage du TD est déjà en place."); }
    if (w === 'route') { c.i--; c.fail('Pas de route statique à écrire : les réseaux sont directement connectés et la route par défaut part par S0/0.'); }
    if (w === 'access-list') return this.ipAccessList(c);
    if (w === 'nat') return this.ipNatGlobal(c, false);
    return this.ipInspectName(c, false);
  }

  ipAccessList(c) {
    const kind = c.kw(['standard', 'extended', 'resequence'], 'ip access-list {standard|extended} NOM');
    if (kind === 'resequence') {
      const help = 'ip access-list resequence NOM DÉBUT PAS — ex. ip access-list resequence WIFI 10 10';
      const name = c.word(help);
      const s = this.intArg(c, 1, 2147483647, help);
      const inc = this.intArg(c, 1, 2147483647, help);
      c.endOrFail();
      const acl = this.cfg.acls[name];
      if (!acl) this.err(`% Access list ${name} does not exist`, 'Vérifie le nom avec show access-lists (les noms sont sensibles à la casse).');
      acl.entries.forEach((e, k) => { e.seq = s + k * inc; });
      return;
    }
    const name = c.word(`Donne un nom (ex. ip access-list ${kind} WIFI-IN) ou un numéro.`);
    if (/^\d+$/.test(name)) {
      if (aclTypeForNumber(+name) !== kind) {
        c.i--;
        c.fail(`Le numéro ${name} ne correspond pas à une ACL ${kind === 'standard' ? 'standard (1-99, 1300-1999)' : 'étendue (100-199, 2000-2699)'}.`);
      }
    } else if (!/^[A-Za-z][\w.-]*$/.test(name)) {
      c.i--;
      c.fail('Le nom doit commencer par une lettre (lettres, chiffres, - et _).');
    }
    c.endOrFail();
    const ex = this.cfg.acls[name];
    if (ex && ex.type !== kind) {
      this.err(`% A named ${ex.type} IP access list with this name already exists`,
        `L'ACL ${name} existe déjà en ${ex.type}. Choisis un autre nom ou supprime-la : no ip access-list ${ex.type} ${name}.`);
    }
    if (!ex) this.cfg.acls[name] = { name, type: kind, entries: [] };
    this.mode = 'nacl';
    this.curAcl = name;
  }

  ipInspectName(c, neg) {
    const help = 'ip inspect name NOM {tcp|udp|icmp|http|dns|smtp|ftp…}';
    c.kw(['name'], help);
    const name = c.word(help);
    if (neg) {
      if (c.done()) { delete this.cfg.inspect[name]; return; }
      const p = c.kw(INSPECT_PROTOS, help);
      c.endOrFail();
      const l = this.cfg.inspect[name];
      if (l) {
        this.cfg.inspect[name] = l.filter(x => x !== p);
        if (!this.cfg.inspect[name].length) delete this.cfg.inspect[name];
      }
      return;
    }
    const p = c.kw(INSPECT_PROTOS, 'Protocole à inspecter : tcp, udp, icmp, ou un protocole applicatif (http, dns, smtp, ftp…).');
    c.i = c.toks.length; // options (timeout, alert…) ignorées
    const l = this.cfg.inspect[name] || (this.cfg.inspect[name] = []);
    if (!l.includes(p)) l.push(p);
    if (p === 'ftp') this.tip('FTP ouvre une 2e connexion pour les données : avec un filtrage avec état, privilégie le mode passif.');
    const used = IFACES.some(i => this.cfg.ifaces[i.id].inspectIn === name || this.cfg.ifaces[i.id].inspectOut === name);
    if (!used && l.length === 1) this.tip(`Règle ${name} créée. Applique-la ensuite sur une interface : ip inspect ${name} in|out (dans le sens des requêtes).`);
  }

  ipNatGlobal(c, neg) {
    const help = 'ip nat inside source list ACL interface S0/0 overload · ip nat inside source static tcp IP_privée port IP_publique port';
    const side = c.kw(['inside', 'outside'], help);
    if (side === 'outside') { c.i--; c.fail('Le rôle outside se donne dans l\'interface : interface S0/0 puis ip nat outside.'); }
    if (c.done()) c.incomplete("« ip nat inside » seul s'écrit dans une interface. En configuration globale : " + help);
    c.kw(['source'], help);
    const kind = c.kw(['list', 'static'], help);
    if (kind === 'list') {
      const list = c.word("Nom ou numéro de l'ACL qui désigne les adresses privées à traduire.");
      const how = c.kw(['interface', 'pool'], 'ip nat inside source list ACL interface S0/0 overload');
      if (how === 'pool') { c.i--; c.fail("Pas de pool dans ce simulateur : utilise l'adresse de l'interface publique, « interface S0/0 overload »."); }
      const ifId = this.parseIface(c);
      const overload = !!c.optKw(['overload']);
      c.endOrFail();
      const k = this.cfg.natDyn.findIndex(d => d.list === list);
      if (neg) {
        if (k >= 0) this.cfg.natDyn.splice(k, 1);
        return;
      }
      const rule = { list, iface: ifId, overload };
      if (k >= 0) this.cfg.natDyn[k] = rule; else this.cfg.natDyn.push(rule);
      if (!overload) this.tip('Sans overload, une seule machine à la fois peut utiliser l\'adresse publique. Avec overload (PAT), toutes la partagent grâce aux ports.');
      if (!this.cfg.acls[list]) this.warn(`L'ACL ${list} n'existe pas encore : crée-la pour désigner les adresses à traduire (ex. ip access-list standard ${list} puis permit 172.16.0.0 0.0.255.255).`);
      if (this.cfg.ifaces[ifId].nat !== 'outside') this.warn(`Pense à marquer ${ifId} avec « ip nat outside » et les interfaces privées avec « ip nat inside ».`);
      return;
    }
    const proto = c.optKw(['tcp', 'udp']);
    const ipArg = what => {
      const t = c.peek();
      if (!t) c.incomplete(help);
      const n = IP.toInt(t.text);
      if (n === null) c.fail(`Adresse IP ${what} attendue.`);
      c.i++;
      return n;
    };
    const portArg = () => this.intArg(c, 1, 65535, 'Numéro de port attendu (1-65535).');
    const inIp = ipArg('privée (inside)');
    const inPort = proto ? portArg() : null;
    let outIp, outIface = null;
    if (c.optKw(['interface'])) {
      outIface = this.parseIface(c);
      outIp = IFACE_BY_ID[outIface].ipn;
    } else {
      outIp = ipArg('publique (outside)');
    }
    const outPort = proto ? portArg() : null;
    c.optKw(['extendable']);
    c.endOrFail();
    const same = s => s.proto === proto && s.inIp === inIp && s.inPort === inPort && s.outIp === outIp && s.outPort === outPort;
    if (neg) {
      const k = this.cfg.natStatic.findIndex(same);
      if (k >= 0) this.cfg.natStatic.splice(k, 1);
      else this.warn('Aucune redirection identique trouvée (voir do show run).');
      return;
    }
    if (this.cfg.natStatic.some(same)) return;
    const clash = this.cfg.natStatic.find(s => s.proto === proto && s.outIp === outIp && s.outPort === outPort);
    if (clash) {
      this.err('% similar static entry already exists',
        `Le port public ${outPort} est déjà redirigé vers ${IP.toStr(clash.inIp)}. Retire l'ancienne redirection avec « no ip nat inside source static … ».`);
    }
    this.cfg.natStatic.push({ proto, inIp, inPort, outIp, outPort, outIface });
    if (outIp !== PUBLIC_IP) this.warn(`Dans le TD, l'adresse publique de Ro est 200.0.0.254 (S0/0). Depuis Internet, personne ne visera ${IP.toStr(outIp)}.`);
    if (!IP.isPrivate(inIp)) this.warn(`${IP.toStr(inIp)} n'est pas une adresse privée : la redirection va d'une IP publique vers une IP privée (inside).`);
  }

  c_config_no(c) {
    const help = 'no access-list N · no ip access-list {standard|extended} NOM · no time-range NOM · no ip inspect name NOM · no ip nat inside source …';
    const w = c.kw(['access-list', 'ip', 'time-range', 'hostname', 'interface'], help);
    if (w === 'interface') { c.i--; c.fail('Une interface ne se supprime pas. Pour retirer une ACL : interface X puis no ip access-group NOM in|out.'); }
    if (w === 'hostname') { c.i = c.toks.length; this.cfg.hostname = 'Router'; return; }
    if (w === 'access-list') {
      const t = c.peek();
      if (!t) c.incomplete(help);
      if (!/^\d+$/.test(t.text)) c.fail("Numéro d'ACL attendu. Pour une ACL nommée : no ip access-list standard|extended NOM.");
      c.i++;
      const more = !c.done();
      c.i = c.toks.length;
      if (!this.cfg.acls[t.text]) { this.warn(`L'ACL ${t.text} n'existe pas.`); return; }
      delete this.cfg.acls[t.text];
      if (more) this.warn(`Piège classique : « no access-list ${t.text} … » supprime TOUTE l'ACL ${t.text}, pas seulement cette ligne. Pour une seule ligne : ip access-list ${aclTypeForNumber(+t.text) === 'standard' ? 'standard' : 'extended'} ${t.text} puis no SEQ.`);
      else this.tip(`ACL ${t.text} supprimée en entier.`);
      this.appliedNote(t.text);
      return;
    }
    if (w === 'time-range') {
      const name = c.word('no time-range NOM');
      c.endOrFail();
      if (!this.cfg.timeRanges[name]) this.warn(`La plage ${name} n'existe pas.`);
      else delete this.cfg.timeRanges[name];
      return;
    }
    const w2 = c.kw(['access-list', 'nat', 'inspect', 'access-group'], help);
    if (w2 === 'access-group') { c.i--; c.fail("Pour retirer une ACL d'une interface : interface X puis no ip access-group NOM in|out."); }
    if (w2 === 'nat') return this.ipNatGlobal(c, true);
    if (w2 === 'inspect') return this.ipInspectName(c, true);
    const kind = c.kw(['standard', 'extended'], 'no ip access-list {standard|extended} NOM');
    const name = c.word('no ip access-list {standard|extended} NOM');
    c.endOrFail();
    const a = this.cfg.acls[name];
    if (!a) { this.warn(`L'ACL ${name} n'existe pas.`); return; }
    if (a.type !== kind) this.err(`% ${name} is a ${a.type} access list`, `L'ACL ${name} est de type ${a.type}.`);
    delete this.cfg.acls[name];
    this.tip(`ACL ${name} supprimée.`);
    this.appliedNote(name);
  }
  appliedNote(name) {
    const where = [];
    for (const i of IFACES) for (const d of ['in', 'out']) if (this.cfg.ifaces[i.id][d] === name) where.push(`${i.id} ${d}`);
    if (where.length) this.warn(`Elle reste référencée sur ${where.join(', ')} : une ACL inexistante laisse tout passer.`);
  }

  /* ===== interface ===== */
  c_if_exit() { this.mode = 'config'; }
  c_if_end() { this.mode = 'priv'; }
  c_if_do(c) { this.doCmd(c); }
  c_if_shutdown(c) {
    c.i = c.toks.length;
    this.tip('Dans ce simulateur, les interfaces restent toujours actives.');
  }
  c_if_description(c) { this.cfg.ifaces[this.curIf].desc = c.rest(); }

  c_if_ip(c) {
    const start = c.i - 1;
    const w = c.kw(['access-group', 'access-list', 'nat', 'inspect', 'address'],
      'Dans une interface : ip access-group NOM in|out · ip nat inside|outside · ip inspect NOM in|out.');
    if (w === 'access-list') {
      if (c.match(['standard', 'extended', 'resequence'])) return this.toConfig(c, start);
      c.i--;
      c.fail("Pour appliquer une ACL sur l'interface, la commande est ip access-GROUP : « ip access-group NOM in|out ».");
    }
    if (w === 'address') {
      c.i = c.toks.length;
      this.tip("L'adressage du TD est déjà configuré (voir do show ip interface brief).");
      return;
    }
    const ifc = this.cfg.ifaces[this.curIf];
    if (w === 'access-group') {
      const name = c.word('ip access-group NOM in|out');
      const dir = c.kw(['in', 'out'], 'Précise le sens : in (le paquet entre dans le routeur par cette interface) ou out (il en ressort).');
      c.endOrFail();
      const prev = ifc[dir];
      ifc[dir] = name;
      if (prev && prev !== name) this.tip(`${prev} était appliquée en ${dir} sur ${this.curIf} : elle est remplacée (une seule ACL par sens et par interface).`);
      if (!this.cfg.acls[name]) {
        const alt = Object.keys(this.cfg.acls).find(k => k.toLowerCase() === name.toLowerCase());
        this.warn(alt
          ? `L'ACL « ${name} » n'existe pas. Les noms sont sensibles à la casse : tu voulais ${alt} ?`
          : `L'ACL ${name} n'existe pas encore. Tant qu'elle n'existe pas, elle laisse tout passer.`);
      } else if (this.cfg.acls[name].type === 'standard' && dir === 'in' && this.curIf !== 'S0/0') {
        this.tip(`Rappel : une ACL standard filtre seulement la source. En entrée de ${this.curIf}, elle bloque ces sources vers TOUTES les destinations. On la place plutôt près de la destination.`);
      }
      return;
    }
    if (w === 'nat') {
      const save = c.i;
      if (c.optKw(['inside']) && c.match(['source'])) return this.toConfig(c, start);
      c.i = save;
      const r = c.kw(['inside', 'outside'], 'ip nat inside (côté réseau privé) ou ip nat outside (côté Internet).');
      c.endOrFail();
      ifc.nat = r;
      return;
    }
    // inspect
    if (c.match(['name'])) return this.toConfig(c, start);
    const name = c.word('ip inspect NOM in|out');
    const dir = c.kw(['in', 'out'], 'Précise le sens des requêtes à inspecter : in ou out.');
    c.endOrFail();
    if (!this.cfg.inspect[name]) this.warn(`La règle ${name} n'existe pas encore : crée-la en config globale, ex. ip inspect name ${name} tcp.`);
    ifc[dir === 'in' ? 'inspectIn' : 'inspectOut'] = name;
  }

  c_if_no(c) {
    const start = c.i - 1;
    const help = 'no ip access-group [NOM] in|out · no ip nat inside|outside · no ip inspect NOM in|out';
    const w = c.kw(['ip', 'shutdown', 'description', 'access-list', 'time-range'], help);
    if (w === 'access-list' || w === 'time-range') return this.toConfig(c, start);
    if (w === 'shutdown' || w === 'description') { c.i = c.toks.length; return; }
    const w2 = c.kw(['access-group', 'nat', 'inspect', 'access-list'], help);
    if (w2 === 'access-list') return this.toConfig(c, start);
    const ifc = this.cfg.ifaces[this.curIf];
    if (w2 === 'access-group') {
      if (!c.done() && !c.match(['in', 'out'])) c.next();
      const dir = c.kw(['in', 'out'], 'Précise le sens : in ou out.');
      c.endOrFail();
      if (!ifc[dir]) this.warn(`Aucune ACL n'est appliquée en ${dir} sur ${this.curIf}.`);
      else ifc[dir] = null;
      return;
    }
    if (w2 === 'nat') {
      const save = c.i;
      if (c.optKw(['inside']) && c.match(['source'])) return this.toConfig(c, start);
      c.i = save;
      const r = c.kw(['inside', 'outside'], help);
      c.endOrFail();
      if (ifc.nat === r) ifc.nat = null;
      return;
    }
    if (c.match(['name'])) return this.toConfig(c, start);
    c.word(help);
    const dir = c.kw(['in', 'out'], help);
    c.endOrFail();
    ifc[dir === 'in' ? 'inspectIn' : 'inspectOut'] = null;
  }

  /* ===== ACL nommée ===== */
  c_nacl_exit() { this.mode = 'config'; }
  c_nacl_end() { this.mode = 'priv'; }
  c_nacl_do(c) { this.doCmd(c); }
  c_nacl_permit(c) { this.naclAdd(c, 'permit', null); }
  c_nacl_deny(c) { this.naclAdd(c, 'deny', null); }
  c_nacl_remark(c) { this.naclAdd(c, 'remark', null); }
  naclSeq(c) {
    const seq = this.intArg(c, 1, 2147483647, 'Numéro de séquence attendu (ex. 15).');
    const act = c.kw(['permit', 'deny', 'remark'], `${seq} permit|deny …`);
    this.naclAdd(c, act, seq);
  }
  naclAdd(c, act, seq) {
    const acl = this.cfg.acls[this.curAcl];
    if (act === 'remark') return this.addEntry(acl.name, acl.type, { remark: c.rest() }, seq);
    const e = this.parseEntry(c, acl.type, act);
    this.addEntry(acl.name, acl.type, e, seq);
  }
  c_nacl_no(c) {
    const start = c.i - 1;
    const acl = this.cfg.acls[this.curAcl];
    const t = c.peek();
    if (!t) c.incomplete('no SEQ (ex. no 20) ou no permit|deny … (la règle exacte)');
    if (/^\d+$/.test(t.text)) {
      c.i++;
      c.endOrFail();
      const k = acl.entries.findIndex(e => e.seq === +t.text);
      if (k < 0) this.warn(`Il n'y a pas de ligne ${t.text} dans ${acl.name} (voir do show access-lists ${acl.name}).`);
      else acl.entries.splice(k, 1);
      return;
    }
    const g = c.match(['permit', 'deny', 'remark', 'access-list', 'ip', 'time-range']);
    if (g === 'access-list' || g === 'ip' || g === 'time-range') return this.toConfig(c, start);
    const act = c.kw(['permit', 'deny', 'remark'], 'no SEQ (ex. no 20) ou no permit|deny … (la règle exacte)');
    if (act === 'remark') {
      const txt = c.rest();
      const k = acl.entries.findIndex(e => e.remark === txt);
      if (k >= 0) acl.entries.splice(k, 1);
      return;
    }
    const e = this.parseEntry(c, acl.type, act);
    const txt = fmtEntry(e, acl.type);
    const k = acl.entries.findIndex(x => x.remark == null && fmtEntry(x, acl.type) === txt);
    if (k < 0) this.warn('Aucune règle identique : utilise plutôt « no NUMÉRO » (numéros visibles avec do show access-lists).');
    else acl.entries.splice(k, 1);
  }

  addEntry(name, type, e, seq = null) {
    const acl = this.cfg.acls[name] || { name, type, entries: [] };
    if (e.remark == null) {
      const txt = fmtEntry(e, type);
      const dup = acl.entries.find(x => x.remark == null && fmtEntry(x, type) === txt);
      if (dup) {
        this.cfg.acls[name] = acl;
        this.warn(`Cette règle existe déjà (ligne ${dup.seq}) : elle n'est pas ajoutée.`);
        return;
      }
    }
    if (seq == null) seq = (acl.entries.length ? acl.entries[acl.entries.length - 1].seq : 0) + 10;
    else if (acl.entries.some(x => x.seq === seq)) {
      this.err('% Duplicate sequence number', `La ligne ${seq} existe déjà. Retire-la avec « no ${seq} » ou prends un numéro libre (ex. ${seq + 5}).`);
    }
    this.cfg.acls[name] = acl;
    if (e.remark == null) {
      const shadow = acl.entries.find(x => x.remark == null && x.seq < seq && !x.timeRange && covers(x, e, type));
      if (shadow) {
        this.warn(`Attention : la ligne ${shadow.seq} « ${fmtEntry(shadow, type)} » capture déjà tout ce trafic. Cette règle ne sera jamais atteinte : seule la première ligne qui correspond s'applique.`);
      }
    }
    const notes = e.notes || [];
    delete e.notes;
    e.seq = seq;
    e.matches = 0;
    acl.entries.push(e);
    acl.entries.sort((a, b) => a.seq - b.seq);
    for (const n of notes) this.say(n.t, n.cls);
  }

  parseAddr(c, std, role, notes) {
    const tok = c.peek();
    const help = std
      ? 'Source attendue : any, host IP, ou IP + masque générique (ex. 172.16.1.0 0.0.0.255).'
      : `Adresse ${role} attendue : any, host IP, ou réseau + masque générique (ex. 172.16.1.0 0.0.0.255).`;
    if (!tok) c.incomplete(help);
    const kw = /^[a-z]/i.test(tok.text) ? c.match(['any', 'host']) : null;
    if (kw === 'any') { c.i++; return { base: 0, wild: 0xFFFFFFFF }; }
    if (kw === 'host') {
      c.i++;
      const t = c.peek();
      const h = 'Après host, donne une adresse IP (ex. host 172.16.1.20).';
      if (!t) c.incomplete(h);
      const n = IP.toInt(t.text);
      if (n === null) c.fail(h);
      c.i++;
      return { base: n, wild: 0 };
    }
    const base = IP.toInt(tok.text);
    if (base === null) {
      if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(tok.text)) c.fail(`Les ACL Cisco n'acceptent pas la notation /préfixe. Écris l'adresse puis le masque générique : ${tok.text.split('/')[0]} ${IP.toStr(IP.wildOf(Math.min(32, +tok.text.split('/')[1])))}.`);
      c.fail(help);
    }
    c.i++;
    const t2 = c.peek();
    const w = t2 ? IP.toInt(t2.text) : null;
    if (w === null) {
      if (std) {
        if ((base & 0xFF) === 0) notes.push({ cls: 'warn', t: `Sans masque générique, ${tok.text} désigne un seul hôte. Pour le réseau entier : ${tok.text} 0.0.0.255 (pour un /24).` });
        return { base, wild: 0 };
      }
      c.fail(`En ACL étendue, une adresse réseau est suivie de son masque générique (ex. ${tok.text} 0.0.0.255). Pour un seul poste : host ${tok.text}.`);
    }
    c.i++;
    if (IP.looksLikeMask(w)) {
      notes.push({ cls: 'warn', t: `${t2.text} ressemble à un masque de sous-réseau. Une ACL attend un masque générique (inversé) : ${IP.toStr((~w) >>> 0)}.` });
    } else if (!IP.contiguousWild(w)) {
      notes.push({ cls: 'warn', t: `${t2.text} est pris comme masque générique de ${tok.text}. Si c'était une deuxième adresse, il manque « host » : host ${tok.text}.` });
    }
    const norm = (base & ~w) >>> 0;
    if (norm !== base && !IP.looksLikeMask(w)) notes.push({ cls: 'tip', t: `${tok.text} ${t2.text} est enregistré comme ${IP.toStr(norm)} ${t2.text} (les bits libres du masque générique sont mis à 0).` });
    return { base: norm, wild: w };
  }

  portValue(text, proto) {
    if (/^\d+$/.test(text)) return +text <= 65535 ? +text : null;
    const n = PORT_NAMES[proto] && PORT_NAMES[proto][text.toLowerCase()];
    return n == null ? null : n;
  }

  parsePortOpt(c, proto) {
    if (c.done()) return null;
    const isWord = /^[a-z]/i.test(c.peek().text);
    if (proto !== 'tcp' && proto !== 'udp') {
      if (isWord && c.match(PORT_OPS)) {
        c.fail(`Les ports n'existent qu'avec tcp ou udp. Avec « ${proto} », tout le trafic est concerné : remplace ${proto} par tcp ou udp pour viser un service.`);
      }
      return null;
    }
    const op = isWord ? c.match(PORT_OPS) : null;
    if (!op) return null;
    c.i++;
    const port = () => {
      const t = c.peek();
      if (!t) c.incomplete(`Donne un numéro de port après ${op} (ex. ${op} 443).`);
      const v = this.portValue(t.text, proto);
      if (v === null) c.fail(`Port invalide pour ${proto} : un numéro (0-65535) ou un nom Cisco (www, domain, smtp…).`);
      c.i++;
      return v;
    };
    if (op === 'range') {
      const a = port();
      const b = port();
      if (a > b) this.err('% Invalid port range', `Dans « range ${a} ${b} », le premier port doit être le plus petit.`);
      return { op, a, b };
    }
    if (op === 'eq') {
      const ports = [port()];
      while (!c.done() && /^\d+$/.test(c.peek().text) && this.portValue(c.peek().text, proto) !== null) ports.push(port());
      return { op, ports };
    }
    return { op, a: port() };
  }

  parseEntry(c, type, action) {
    const e = { action, proto: 'ip', src: null, srcPort: null, dst: null, dstPort: null, established: false, icmp: null, log: false, timeRange: null, notes: [] };
    if (type === 'standard') {
      if (c.done()) c.incomplete('ACL standard : {permit|deny} source — ex. permit 172.16.1.0 0.0.0.255 · deny host 172.16.1.20 · permit any');
      if (['ip', 'tcp', 'udp', 'icmp'].includes(c.peekLow())) {
        c.fail("Une ACL standard ne filtre que l'adresse SOURCE : pas de protocole, de destination ni de port. Pour ça, utilise une ACL étendue (100-199 ou ip access-list extended NOM).");
      }
      e.src = this.parseAddr(c, true, 'source', e.notes);
      while (!c.done()) {
        if (c.match(['log'])) { c.i++; e.log = true; continue; }
        const t = c.peekLow();
        if (IP.toInt(t) !== null || t === 'any' || t === 'host') {
          c.fail("Une ACL standard n'a pas d'adresse de destination : elle ne regarde que la source. Pour préciser la destination, passe à une ACL étendue.");
        }
        if (/^\d+$/.test(t) || PORT_OPS.includes(t)) c.fail("Une ACL standard ne connaît pas les ports. Pour filtrer un service, utilise une ACL étendue.");
        c.fail("Après la source, seul « log » est accepté dans une ACL standard.");
      }
      return e;
    }
    e.proto = c.kw(['ip', 'tcp', 'udp', 'icmp', 'esp', 'gre', 'ahp', 'ospf', 'eigrp'],
      'ACL étendue : après permit/deny vient le protocole : ip (tout), tcp, udp ou icmp. Ex. permit tcp any host 172.17.0.1 eq 443');
    e.src = this.parseAddr(c, false, 'source', e.notes);
    e.srcPort = this.parsePortOpt(c, e.proto);
    if (c.done()) c.incomplete("Il manque l'adresse de destination : any, host IP, ou réseau + masque générique.");
    e.dst = this.parseAddr(c, false, 'destination', e.notes);
    e.dstPort = this.parsePortOpt(c, e.proto);
    while (!c.done()) {
      const low = c.peekLow();
      if (/^\d+$/.test(low) && (e.proto === 'tcp' || e.proto === 'udp')) {
        c.fail(`Pour un port, ajoute l'opérateur : eq ${low} (égal), range 20 21, gt 1023, lt 1024, neq 23.`);
      }
      const opts = ['log', 'log-input', 'time-range'];
      if (e.proto === 'tcp') opts.push('established');
      if (e.proto === 'icmp') opts.push(...ICMP_TYPES);
      const w = c.match(opts);
      if (!w) {
        if (PORT_OPS.includes(low)) {
          c.fail(e.proto === 'tcp' || e.proto === 'udp'
            ? 'Le port de destination est déjà donné. Plusieurs ports : eq 80 443, ou une plage : range 20 21.'
            : `Les ports n'existent qu'avec tcp ou udp. Avec « ${e.proto} », remplace par tcp ou udp.`);
        }
        if (low === 'established') c.fail('« established » ne s\'applique qu\'à tcp (bit ACK des réponses).');
        if (ICMP_TYPES.includes(low)) c.fail(`« ${low} » est un type ICMP : il faut le protocole icmp.`);
        c.fail('Options possibles en fin de règle : ' + opts.join(', ') + '.');
      }
      c.i++;
      if (w === 'log' || w === 'log-input') e.log = true;
      else if (w === 'established') e.established = true;
      else if (w === 'time-range') {
        e.timeRange = c.word('Donne le nom de la plage horaire, définie avec time-range NOM.');
        if (!this.cfg.timeRanges[e.timeRange]) e.notes.push({ cls: 'warn', t: `La plage ${e.timeRange} n'existe pas encore : crée-la avec « time-range ${e.timeRange} ». En attendant, cette règle reste inactive.` });
      } else e.icmp = w;
    }
    if (e.srcPort && !e.dstPort) {
      e.notes.push({ cls: 'tip', t: "Le port est placé juste après la SOURCE : c'est un port source. Le service visé (port de destination) se place après l'adresse destination." });
    }
    return e;
  }

  /* ===== plage horaire ===== */
  c_tr_exit() { this.mode = 'config'; }
  c_tr_end() { this.mode = 'priv'; }
  c_tr_do(c) { this.doCmd(c); }
  c_tr_periodic(c) {
    const p = this.parsePeriodic(c);
    const tr = this.cfg.timeRanges[this.curTr];
    if (!tr.periodic.some(x => x.text === p.text)) tr.periodic.push(p);
  }
  c_tr_absolute(c) {
    this.cfg.timeRanges[this.curTr].absolute = this.parseAbsolute(c);
  }
  c_tr_no(c) {
    const start = c.i - 1;
    const g = c.match(['periodic', 'absolute', 'access-list', 'ip', 'time-range']);
    if (g === 'access-list' || g === 'ip' || g === 'time-range') return this.toConfig(c, start);
    const w = c.kw(['periodic', 'absolute'], 'no periodic … · no absolute');
    const tr = this.cfg.timeRanges[this.curTr];
    if (w === 'absolute') { c.i = c.toks.length; tr.absolute = null; return; }
    const p = this.parsePeriodic(c);
    const k = tr.periodic.findIndex(x => x.text === p.text);
    if (k < 0) this.warn('Aucun créneau identique (voir do show time-range).');
    else tr.periodic.splice(k, 1);
  }
  parseHHMM(c, help) {
    const t = c.peek();
    if (!t) c.incomplete(help);
    const m = /^(\d{1,2}):(\d{2})$/.exec(t.text);
    if (!m || +m[1] > 23 || +m[2] > 59) c.fail('Heure au format HH:MM sur 24 h, ex. 08:00 ou 14:30.');
    c.i++;
    return +m[1] * 60 + +m[2];
  }
  parsePeriodic(c) {
    const help = 'periodic {weekdays|weekend|daily|monday…sunday} HH:MM to HH:MM — ex. periodic weekdays 12:00 to 14:00';
    const days = [];
    while (!c.done() && /^[a-z]/i.test(c.peek().text)) {
      const d = c.match(DAY_WORDS);
      if (!d) break;
      c.i++;
      days.push(d);
    }
    if (!days.length) {
      if (c.done()) c.incomplete(help);
      c.fail('Jours en anglais : weekdays (lun-ven), weekend, daily, monday, tuesday… ' + help);
    }
    const from = this.parseHHMM(c, help);
    c.kw(['to'], 'Il manque « to » entre les deux heures. ' + help);
    let endDay = null;
    if (!c.done() && /^[a-z]/i.test(c.peek().text)) endDay = c.kw(DAY_WORDS.slice(0, 7), help);
    const to = this.parseHHMM(c, help);
    c.endOrFail(help);
    const hm = m => `${pad2(Math.floor(m / 60))}:${pad2(m % 60)}`;
    if (endDay) {
      if (days.length !== 1 || !(days[0] in DAY_INDEX)) {
        this.err('% Invalid periodic range', 'La forme « periodic monday 08:00 to friday 18:00 » prend un seul jour de départ et un jour d\'arrivée.');
      }
      return { span: true, startDay: DAY_INDEX[days[0]], endDay: DAY_INDEX[endDay], from, to, text: `periodic ${days[0]} ${hm(from)} to ${endDay} ${hm(to)}` };
    }
    if (from > to) {
      this.err('% End time must be later than start time', 'Le créneau doit finir après son début. Pour passer minuit, fais deux lignes (22:00 to 23:59 puis 00:00 to 06:00).');
    }
    const set = new Set();
    for (const d of days) {
      if (d === 'daily') [0, 1, 2, 3, 4, 5, 6].forEach(x => set.add(x));
      else if (d === 'weekdays') [1, 2, 3, 4, 5].forEach(x => set.add(x));
      else if (d === 'weekend') [0, 6].forEach(x => set.add(x));
      else set.add(DAY_INDEX[d]);
    }
    return { span: false, days: [...set], from, to, text: `periodic ${days.join(' ')} ${hm(from)} to ${hm(to)}` };
  }
  parseAbsolute(c) {
    const help = 'absolute [start HH:MM JJ Mois AAAA] [end HH:MM JJ Mois AAAA] — ex. absolute start 08:00 15 Mar 2024 end 18:00 21 Apr 2024';
    let start = null, end = null;
    const parts = [];
    while (!c.done()) {
      const w = c.kw(['start', 'end'], help);
      const d = this.parseDateTime(c, help);
      if (w === 'start') start = d; else end = d;
      parts.push(`${w} ${fmtIosDate(d)}`);
    }
    if (!start && !end) c.incomplete(help);
    if (start && end && end < start) this.err('% End time must be later than start time', 'La date de fin doit être après la date de début.');
    return { start, end, text: 'absolute ' + parts.join(' ') };
  }
  parseDateTime(c, help) {
    const m = this.parseHHMM(c, help);
    const dTok = c.peek();
    if (!dTok) c.incomplete(help);
    if (!/^\d{1,2}$/.test(dTok.text) || +dTok.text < 1 || +dTok.text > 31) c.fail('Jour du mois attendu (1-31). ' + help);
    c.i++;
    const monTok = c.peek();
    if (!monTok) c.incomplete(help);
    const mi = MONTHS_EN.findIndex(x => monTok.text.toLowerCase().startsWith(x));
    if (mi < 0) c.fail('Mois en anglais, 3 lettres : Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec.');
    c.i++;
    const yTok = c.peek();
    if (!yTok) c.incomplete(help);
    if (!/^\d{4}$/.test(yTok.text)) c.fail('Année sur 4 chiffres (ex. 2026).');
    c.i++;
    return new Date(+yTok.text, mi, +dTok.text, Math.floor(m / 60), m % 60);
  }

  /* ===== show ===== */
  show(c) {
    const help = 'show access-lists · show running-config · show ip interface brief · show time-range · show ip nat translations · show clock';
    const w = c.kw(['access-lists', 'running-config', 'startup-config', 'ip', 'time-range', 'clock', 'interfaces', 'version'], help);
    switch (w) {
      case 'access-lists': return this.showAcls(c.done() ? null : c.next().text);
      case 'running-config':
      case 'startup-config': c.i = c.toks.length; return this.showRun();
      case 'time-range': return this.showTimeRanges();
      case 'clock': return this.say('*' + fmtIosDate(this.clock).replace(/^(\d\d:\d\d)/, '$1:00.000') + ' (horloge du simulateur)');
      case 'interfaces': return this.showIpIntBrief();
      case 'version': return this.say('Cisco IOS Software, ACL·train simulator — Ro (routeur du TD R5.Cyber.09)');
    }
    const w2 = c.kw(['interface', 'access-lists', 'nat', 'inspect', 'route'], help);
    if (w2 === 'access-lists') return this.showAcls(c.done() ? null : c.next().text);
    if (w2 === 'interface') {
      if (c.optKw(['brief'])) return this.showIpIntBrief();
      return this.showIpInt(c.done() ? null : this.parseIface(c));
    }
    if (w2 === 'nat') { c.kw(['translations', 'statistics'], 'show ip nat translations'); return this.showNat(); }
    if (w2 === 'inspect') { c.i = c.toks.length; return this.showInspect(); }
    return this.showRoute();
  }

  showAcls(name) {
    const list = Object.values(this.cfg.acls).filter(a => !name || a.name === name).sort(aclSort);
    if (name && !list.length) { this.warn(`Aucune ACL nommée ${name} (les noms sont sensibles à la casse).`); return; }
    if (!list.length) { this.say('(aucune ACL configurée)', 'dim'); return; }
    for (const a of list) {
      this.say(`${a.type === 'standard' ? 'Standard' : 'Extended'} IP access list ${a.name}`);
      if (!a.entries.length) this.say('    (vide : tout est refusé par le deny implicite)', 'dim');
      for (const e of a.entries) {
        const s = fmtEntryShow(e, a.type);
        if (s == null) continue;
        let extra = '';
        if (e.timeRange) {
          const tr = this.cfg.timeRanges[e.timeRange];
          extra += tr ? (trActive(tr, this.clock) ? ' (active)' : ' (inactive)') : ' (plage inexistante)';
        }
        if (e.matches) extra += ` (${e.matches} match${e.matches > 1 ? 'es' : ''})`;
        this.say(`    ${e.seq} ${s}${extra}`, 'acl');
      }
    }
  }

  showRun() {
    const cfg = this.cfg;
    const L = ['Building configuration...', '', 'Current configuration :', '!', `hostname ${cfg.hostname}`, '!'];
    const insp = Object.keys(cfg.inspect);
    for (const n of insp) for (const p of cfg.inspect[n]) L.push(`ip inspect name ${n} ${p}`);
    if (insp.length) L.push('!');
    for (const i of IFACES) {
      const f = cfg.ifaces[i.id];
      L.push(`interface ${i.full}`);
      if (f.desc) L.push(` description ${f.desc}`);
      if (i.id.includes('.')) L.push(` encapsulation dot1Q ${10 + +i.id.split('.')[1]}`);
      L.push(` ip address ${i.ip} ${IP.toStr(IP.maskOf(i.prefix))}`);
      if (f.in) L.push(` ip access-group ${f.in} in`);
      if (f.out) L.push(` ip access-group ${f.out} out`);
      if (f.nat) L.push(` ip nat ${f.nat}`);
      if (f.inspectIn) L.push(` ip inspect ${f.inspectIn} in`);
      if (f.inspectOut) L.push(` ip inspect ${f.inspectOut} out`);
      L.push('!');
    }
    for (const d of cfg.natDyn) L.push(`ip nat inside source list ${d.list} interface ${IFACE_BY_ID[d.iface].full}${d.overload ? ' overload' : ''}`);
    for (const s of cfg.natStatic) {
      const out = s.outIface ? `interface ${IFACE_BY_ID[s.outIface].full}` : IP.toStr(s.outIp);
      L.push(s.proto
        ? `ip nat inside source static ${s.proto} ${IP.toStr(s.inIp)} ${s.inPort} ${out} ${s.outPort} extendable`
        : `ip nat inside source static ${IP.toStr(s.inIp)} ${out}`);
    }
    L.push('ip route 0.0.0.0 0.0.0.0 Serial0/0', '!');
    const acls = Object.values(cfg.acls).sort(aclSort);
    for (const a of acls) {
      if (/^\d+$/.test(a.name)) {
        for (const e of a.entries) L.push(`access-list ${a.name} ${fmtEntry(e, a.type)}`);
      } else {
        L.push(`ip access-list ${a.type} ${a.name}`);
        for (const e of a.entries) L.push(` ${fmtEntry(e, a.type)}`);
      }
    }
    if (acls.length) L.push('!');
    for (const tr of Object.values(cfg.timeRanges)) {
      L.push(`time-range ${tr.name}`);
      for (const p of tr.periodic) L.push(` ${p.text}`);
      if (tr.absolute) L.push(` ${tr.absolute.text}`);
      L.push('!');
    }
    L.push('end');
    for (const l of L) this.say(l, l.startsWith('access-list') || l.startsWith(' permit') || l.startsWith(' deny') ? 'acl' : 'out');
  }

  showIpIntBrief() {
    this.say('Interface              IP-Address      OK? Method Status                Protocol', 'dim');
    for (const i of IFACES) this.say(`${i.full.padEnd(23)}${i.ip.padEnd(16)}YES manual up                    up`);
    this.say('GigabitEthernet0/1     unassigned      YES unset  up                    up');
  }

  showIpInt(id) {
    for (const i of IFACES) {
      if (id && i.id !== id) continue;
      const f = this.cfg.ifaces[i.id];
      this.say(`${i.full} is up, line protocol is up`);
      this.say(`  Internet address is ${i.ip}/${i.prefix}  (${ZONES[i.zone].name})`);
      this.say(`  Outgoing access list is ${f.out || 'not set'}`, f.out ? 'acl' : 'out');
      this.say(`  Inbound  access list is ${f.in || 'not set'}`, f.in ? 'acl' : 'out');
      if (f.nat) this.say(`  IP NAT ${f.nat}`);
      if (f.inspectIn) this.say(`  Inbound inspection rule is ${f.inspectIn}`);
      if (f.inspectOut) this.say(`  Outgoing inspection rule is ${f.inspectOut}`);
    }
  }

  showNat() {
    const cfg = this.cfg;
    const rows = [];
    for (const s of cfg.natStatic) {
      rows.push([s.proto || '---', `${IP.toStr(s.outIp)}${s.proto ? ':' + s.outPort : ''}`, `${IP.toStr(s.inIp)}${s.proto ? ':' + s.inPort : ''}`, '---', '---']);
    }
    for (const t of cfg.natTable.slice(-8)) rows.push(t);
    if (!rows.length) {
      this.say('(aucune traduction : envoie un paquet vers Internet ou configure une redirection)', 'dim');
      return;
    }
    this.say('Pro Inside global         Inside local          Outside local         Outside global', 'dim');
    for (const r of rows) this.say(`${r[0].padEnd(4)}${r[1].padEnd(22)}${r[2].padEnd(22)}${r[3].padEnd(22)}${r[4]}`);
  }

  showTimeRanges() {
    const trs = Object.values(this.cfg.timeRanges);
    if (!trs.length) { this.say('(aucune plage horaire)', 'dim'); return; }
    for (const tr of trs) {
      this.say(`time-range entry: ${tr.name} (${trActive(tr, this.clock) ? 'active' : 'inactive'})`);
      if (tr.absolute) this.say(`   ${tr.absolute.text}`);
      for (const p of tr.periodic) this.say(`   ${p.text}`);
      const used = Object.values(this.cfg.acls).some(a => a.entries.some(e => e.timeRange === tr.name));
      if (used) this.say('   used in: IP ACL entry');
    }
    this.say(`(horloge du simulateur : ${fmtWhen(this.clock)})`, 'dim');
  }

  showInspect() {
    const names = Object.keys(this.cfg.inspect);
    if (!names.length) { this.say('(aucune règle d\'inspection)', 'dim'); return; }
    this.say('Inspection Rule Configuration');
    for (const n of names) {
      this.say(` Inspection name ${n}`);
      for (const p of this.cfg.inspect[n]) this.say(`    ${p} alert is on audit-trail is off timeout 3600`);
    }
    this.say('Interface Configuration');
    for (const i of IFACES) {
      const f = this.cfg.ifaces[i.id];
      if (!f.inspectIn && !f.inspectOut) continue;
      this.say(` Interface ${i.full}`);
      if (f.inspectIn) this.say(`  Inbound inspection rule is ${f.inspectIn}`);
      if (f.inspectOut) this.say(`  Outgoing inspection rule is ${f.inspectOut}`);
    }
  }

  showRoute() {
    this.say('Gateway of last resort is 0.0.0.0 to network 0.0.0.0', 'dim');
    this.say('');
    this.say('S*    0.0.0.0/0 is directly connected, Serial0/0');
    for (const i of IFACES) this.say(`C     ${IP.toStr(i.net)}/${i.prefix} is directly connected, ${i.full}`);
  }

  /* ===== aide ===== */
  helpKey() {
    if (this.mode === 'nacl') return this.curAclType() === 'standard' ? 'nacl-std' : 'nacl-ext';
    return this.mode;
  }
  contextHelp(before) {
    if (!before.trim()) {
      for (const [cmd, d] of MODE_HELP[this.helpKey()]) this.say(`  ${cmd.padEnd(42)} ${d}`, 'help');
      return;
    }
    const h = this.hint(before);
    this.say('  ' + h.syntax, 'help');
    if (h.info) this.say('  ' + h.info, 'dim');
  }

  // syntaxe attendue pour ce qui est en train d'être tapé
  hint(text) {
    let toks = text.trim().split(/\s+/).filter(Boolean).map(s => s.toLowerCase());
    const is = (k, full) => toks[k] !== undefined && full.startsWith(toks[k]) && toks[k].length >= Math.min(2, full.length);
    let mode = this.mode;
    if (toks.length && is(0, 'do') && mode !== 'user' && mode !== 'priv') { toks = toks.slice(1); mode = 'priv'; }
    if (toks.length && is(0, 'show')) {
      return { syntax: 'show {access-lists [NOM] | running-config | ip interface [brief|G0/0] | time-range | ip nat translations | clock}', info: mode === this.mode && !['user', 'priv'].includes(this.mode) ? 'En mode configuration, préfixe par do.' : null };
    }
    const acl = this.cfg.acls[this.curAcl];
    switch (mode) {
      case 'user':
        return { syntax: 'enable', info: 'Passe en mode privilégié (Ro#).' };
      case 'priv':
        if (is(0, 'configure')) return { syntax: 'configure terminal', info: 'Entre en configuration globale.' };
        return { syntax: 'configure terminal · show access-lists · show running-config · show ip interface brief', info: 'Mode privilégié (#). Tape ? pour la liste.' };
      case 'nacl':
        if (is(0, 'no')) return { syntax: 'no SEQ  —  ex. no 20', info: 'Supprime une ligne. Les numéros sont visibles avec do show access-lists.' };
        return acl && acl.type === 'standard'
          ? { syntax: '[seq] {permit|deny} source [masque générique]', info: `ACL standard ${this.curAcl}. Ex. : permit 172.16.1.0 0.0.0.255 · deny host 172.16.1.20 · 15 permit any · no 20` }
          : { syntax: '[seq] {permit|deny} protocole source [port] destination [port] [established] [time-range NOM]', info: `ACL étendue ${this.curAcl}. Ex. : permit tcp any host 172.17.0.1 eq 443 · 15 deny ip any any · no 20` };
      case 'tr':
        if (is(0, 'absolute')) return { syntax: 'absolute [start HH:MM JJ Mois AAAA] [end HH:MM JJ Mois AAAA]', info: 'Ex. : absolute start 08:00 02 Nov 2026 end 18:00 18 Dec 2026 (mois en anglais)' };
        return { syntax: 'periodic {weekdays|weekend|daily|monday…sunday} HH:MM to HH:MM', info: `Plage ${this.curTr}. Ex. : periodic weekdays 12:00 to 14:00` };
      case 'if': {
        const i = IFACE_BY_ID[this.curIf];
        if (is(0, 'ip') && is(1, 'access-group')) return { syntax: 'ip access-group {NOM|numéro} {in|out}', info: 'in : paquets qui entrent dans Ro par cette interface · out : paquets qui en ressortent.' };
        if (is(0, 'ip') && is(1, 'nat')) return { syntax: 'ip nat {inside|outside}', info: 'inside : côté adresses privées · outside : côté Internet (S0/0).' };
        if (is(0, 'ip') && is(1, 'inspect')) return { syntax: 'ip inspect NOM {in|out}', info: "Dans le sens des requêtes : les réponses seront acceptées dans l'autre sens sur cette interface." };
        if (is(0, 'no')) return { syntax: 'no ip access-group NOM {in|out} · no ip nat {inside|outside} · no ip inspect NOM {in|out}', info: null };
        return { syntax: 'ip access-group NOM {in|out} · ip nat {inside|outside} · ip inspect NOM {in|out} · exit', info: `Interface ${i.id} : ${ZONES[i.zone].name}, ${i.ip}/${i.prefix}.` };
      }
      default: break;
    }
    // configuration globale
    if (is(0, 'access-list')) {
      const n = toks[1] && /^\d+$/.test(toks[1]) ? +toks[1] : null;
      const t = n == null ? null : aclTypeForNumber(n);
      if (t === 'standard') return { syntax: `access-list ${n} {permit|deny} source [masque générique]`, info: "ACL standard : seule l'adresse source compte. À placer près de la destination." };
      if (t === 'extended') return { syntax: `access-list ${n} {permit|deny} protocole source [port] destination [port] [established] [time-range NOM]`, info: 'ACL étendue : protocole (ip, tcp, udp, icmp), adresses et ports. À placer près de la source.' };
      return { syntax: 'access-list {1-99 | 100-199} {permit|deny} …', info: 'Le numéro fixe le type : 1-99 standard, 100-199 étendue.' };
    }
    if (is(0, 'ip') && is(1, 'access-list')) {
      if (is(2, 'resequence')) return { syntax: 'ip access-list resequence NOM DÉBUT PAS', info: 'Renumérote les lignes (ex. 10, 20, 30…).' };
      return { syntax: 'ip access-list {standard|extended} NOM', info: 'Crée ou rouvre une ACL nommée ; les règles se tapent ensuite une par ligne.' };
    }
    if (is(0, 'ip') && is(1, 'nat')) {
      if (is(4, 'static')) return { syntax: 'ip nat inside source static {tcp|udp} IP_privée PORT IP_publique PORT', info: 'Redirection de port : ex. … static tcp 172.17.0.1 443 200.0.0.254 443' };
      if (is(4, 'list')) return { syntax: 'ip nat inside source list ACL interface S0/0 overload', info: "NAT/PAT : les adresses permises par l'ACL sortent avec l'IP de S0/0." };
      return { syntax: 'ip nat inside source {list ACL interface S0/0 overload | static tcp IP PORT IP PORT}', info: null };
    }
    if (is(0, 'ip') && is(1, 'inspect')) return { syntax: 'ip inspect name NOM {tcp|udp|icmp|http|dns|smtp|ftp…}', info: 'Une ligne par protocole, puis ip inspect NOM in|out sur une interface.' };
    if (is(0, 'interface')) return { syntax: 'interface {G0/0 | G0/1.0 | G0/1.1 | G0/1.2 | S0/0}', info: 'G0/0 DMZ · G0/1.0 serveurs · G0/1.1 filaire · G0/1.2 wifi · S0/0 Internet' };
    if (is(0, 'time-range')) return { syntax: 'time-range NOM', info: "Puis, à l'intérieur : periodic … ou absolute …" };
    if (is(0, 'no')) return { syntax: 'no access-list N · no ip access-list {standard|extended} NOM · no time-range NOM', info: "Attention : no access-list N supprime toute l'ACL." };
    return { syntax: 'access-list … · ip access-list … · interface … · time-range … · ip inspect name … · ip nat inside source …', info: 'Configuration globale. Tape ? pour la liste détaillée.' };
  }

  // complétion par Tab
  complete(text) {
    const m = /^(.*?)(\S*)$/.exec(text);
    const head = m[1], part = m[2].toLowerCase();
    const prev = head.trim() ? head.trim().split(/\s+/) : [];
    const cands = this.candidates(prev);
    const opts = [...new Set(cands)].filter(o => o.toLowerCase().startsWith(part));
    if (!opts.length) return { value: text, options: [] };
    if (opts.length === 1) return { value: head + opts[0] + ' ', options: [] };
    let cp = opts[0];
    for (const o of opts) while (!o.toLowerCase().startsWith(cp.toLowerCase())) cp = cp.slice(0, -1);
    return { value: cp.length > part.length ? head + cp : text, options: opts };
  }
  candidates(prev) {
    let mode = this.mode;
    let toks = prev.map(s => s.toLowerCase());
    if (toks[0] && toks[0].length >= 2 && 'do'.startsWith(toks[0]) && mode !== 'user' && mode !== 'priv') { toks = toks.slice(1); mode = 'priv'; }
    const tree = Object.assign({}, COMPLETE[mode], COMPLETE.common);
    const resolveList = v => {
      if (v === '@ifaces') return IFACES.map(i => i.id);
      if (v === '@acls') return Object.keys(this.cfg.acls);
      if (v === '@inspects') return Object.keys(this.cfg.inspect);
      return v;
    };
    let path = [];
    for (const t of toks) {
      const opts = resolveList(tree[path.join(' ')]);
      if (!Array.isArray(opts)) { path = null; break; }
      const w = opts.find(o => o.toLowerCase() === t) || (opts.filter(o => o.toLowerCase().startsWith(t)).length === 1 ? opts.find(o => o.toLowerCase().startsWith(t)) : null);
      if (!w) { path = null; break; }
      path.push(w);
    }
    if (path) {
      const v = resolveList(tree[path.join(' ')]);
      if (Array.isArray(v)) return v;
    }
    return [...GENERIC_WORDS, ...Object.keys(this.cfg.acls), ...Object.keys(this.cfg.timeRanges), ...IFACES.map(i => i.id)];
  }
}
