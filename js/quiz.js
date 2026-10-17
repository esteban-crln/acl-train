'use strict';
/* quiz.js : questions éclair (masques génériques, « quelle ligne s'applique ? », cours, ports) */

const rnd = n => Math.floor(Math.random() * n);
const pick = a => a[rnd(a.length)];
function shuffle(a) {
  const b = [...a];
  for (let i = b.length - 1; i > 0; i--) { const j = rnd(i + 1); [b[i], b[j]] = [b[j], b[i]]; }
  return b;
}
const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const QUIZ_FACTS = [
  { q: 'Quelle plage de numéros désigne une ACL standard ?', o: ['1 à 99 (et 1300 à 1999)', '100 à 199', '1 à 199', '200 à 299'], x: 'Standard : 1-99 et 1300-1999. Étendue : 100-199 et 2000-2699.' },
  { q: 'Où place-t-on une ACL standard ?', o: ['Au plus près de la destination', 'Au plus près de la source', 'Toujours sur S0/0', "N'importe où"], x: "Elle ne connaît que la source : près de la source, elle couperait cette source de toutes les destinations." },
  { q: 'Où place-t-on une ACL étendue ?', o: ['Au plus près de la source', 'Au plus près de la destination', 'Toujours en sortie', 'Sur toutes les interfaces'], x: 'Elle est précise (source, destination, port) : on jette le trafic interdit dès son entrée dans le réseau.' },
  { q: 'Un paquet ne correspond à aucune ligne de l\'ACL. Que se passe-t-il ?', o: ['Il est refusé (deny implicite)', 'Il est autorisé', 'Il est journalisé puis autorisé', 'Le routeur le renvoie à l\'émetteur'], x: 'Toute ACL se termine par un deny implicite. Pour tout autoriser par défaut : permit any (standard) ou permit ip any any (étendue).' },
  { q: 'Combien d\'ACL IPv4 peut-on appliquer sur une même interface ?', o: ['Une par sens : une in et une out', 'Une seule en tout', 'Autant qu\'on veut', 'Deux par sens'], x: 'Une seule ACL par protocole (IPv4/IPv6), par sens et par interface. Une nouvelle remplace l\'ancienne.' },
  { q: 'Sur S0/0 (NAT outside), une ACL appliquée en sortie (out) voit comme adresse source…', o: ['L\'adresse déjà traduite (200.0.0.254)', 'L\'adresse privée d\'origine', 'Les deux à la suite', 'Aucune adresse source'], x: 'Sens OUT : la NAT passe d\'abord, puis l\'ACL.' },
  { q: 'Sur S0/0, l\'ACL d\'entrée (in) voit un client qui vise la redirection 200.0.0.254:443 → 172.17.0.1:443. Quelle destination voit-elle ?', o: ['200.0.0.254 port 443', '172.17.0.1 port 443', '172.17.0.1 port 80', 'Aucune, la redirection passe avant'], x: 'Sens IN : l\'ACL passe d\'abord, puis la redirection de ports.' },
  { q: '« host 172.16.1.10 » est équivalent à…', o: ['172.16.1.10 0.0.0.0', '172.16.1.10 255.255.255.255', '172.16.1.0 0.0.0.255', 'any'], x: 'Masque générique 0.0.0.0 : tous les bits doivent correspondre, donc une seule adresse.' },
  { q: '« any » est équivalent à…', o: ['0.0.0.0 255.255.255.255', '0.0.0.0 0.0.0.0', '255.255.255.255 0.0.0.0', '0.0.0.0 0.0.0.255'], x: 'Masque générique 255.255.255.255 : aucun bit n\'est vérifié, toutes les adresses correspondent.' },
  { q: 'Que laisse passer le mot-clé established ?', o: ['Les segments TCP avec ACK ou RST : les réponses d\'une connexion déjà ouverte', 'Toutes les connexions TCP', 'Les réponses UDP et ICMP', 'Le trafic inspecté par CBAC'], x: 'established ne marche qu\'avec tcp. Pour UDP et ICMP, il faut le filtrage avec état (ip inspect).' },
  { q: 'Avec ip inspect, où les réponses sont-elles autorisées ?', o: ['Dans l\'autre sens, sur la même interface, même si une ACL les interdit', 'Sur toutes les interfaces du routeur', 'Seulement si l\'ACL les autorise', 'Seulement pour TCP'], x: 'On inspecte dans le sens des requêtes ; la réponse est acceptée en sens inverse sur la même interface.' },
  { q: 'Avec un filtrage avec état, quel mode FTP faut-il privilégier ?', o: ['Le mode passif', 'Le mode actif', 'TFTP', 'Peu importe'], x: 'En mode actif, c\'est le serveur qui ouvre la connexion de données vers le client : le pare-feu la voit comme une nouvelle connexion entrante.' },
  { q: 'Filtrage par niveau de sécurité : trafic du LAN (100) vers Internet (0) ?', o: ['Autorisé implicitement', 'Refusé implicitement', 'Toujours interdit', 'Autorisé seulement en HTTP'], x: 'Permit implicite vers une zone de confiance plus faible ou égale.' },
  { q: 'Filtrage par niveau de sécurité : trafic d\'Internet (0) vers la DMZ (50) ?', o: ['Refusé implicitement, à ouvrir par ACL', 'Autorisé implicitement', 'Autorisé pour HTTP seulement', 'Toujours impossible'], x: 'Deny implicite vers une zone de confiance plus forte : il faut une ACL pour ouvrir les services publiés.' },
  { q: '« periodic weekdays 08:00 to 18:00 » couvre…', o: ['Du lundi au vendredi, de 8h à 18h chaque jour', 'Tous les jours de 8h à 18h', 'Le samedi et le dimanche', 'Du lundi 8h au vendredi 18h sans interruption'], x: 'weekdays = lundi à vendredi, weekend = samedi et dimanche, daily = tous les jours.' },
  { q: 'Dans une ACL nommée, comment insérer une règle entre les lignes 10 et 20 ?', o: ['15 permit …', 'insert 10 permit …', 'Il faut tout réécrire', 'permit … before 20'], x: 'On préfixe la règle par un numéro de séquence libre. ip access-list resequence renumérote ensuite proprement.' },
  { q: 'Que fait « no access-list 110 deny tcp any any eq 23 » ?', o: ['Supprime toute l\'ACL 110', 'Supprime seulement cette ligne', 'Ajoute une exception', 'Rien, la syntaxe est fausse'], x: 'Piège classique des ACL numérotées : le no supprime l\'ACL entière. Pour une ligne : ip access-list extended 110 puis no SEQ.' },
  { q: 'Pourquoi l\'ordre des lignes d\'une ACL compte-t-il ?', o: ['La première ligne qui correspond s\'applique, les suivantes sont ignorées', 'Le routeur applique la règle la plus précise', 'Les deny passent toujours avant les permit', 'Il ne compte pas'], x: 'On écrit donc les exceptions précises avant les règles générales.' },
  { q: 'Quelle commande montre les compteurs de correspondance des ACL ?', o: ['show access-lists', 'show ip route', 'show ip nat translations', 'show time-range'], x: 'Chaque ligne affiche (N matches). clear access-list counters les remet à zéro.' },
  { q: 'Une ACL est appliquée sur une interface mais n\'existe pas. Effet ?', o: ['Tout passe', 'Tout est bloqué', 'Le routeur refuse la commande', 'Seul le trafic sortant passe'], x: 'Une ACL inexistante ne filtre rien. Pense à vérifier les noms : ils sont sensibles à la casse.' },
  { q: 'Un IDS par rapport à un IPS…', o: ['Analyse une copie du trafic et alerte, sans bloquer', 'Bloque le trafic en coupure', 'Remplace le pare-feu', 'Chiffre le trafic'], x: 'L\'IDS est passif (copie du trafic), l\'IPS est actif : le trafic le traverse et il peut couper un flux.' },
];

const QUIZ_PORTS = [
  ['HTTPS', 'TCP 443'], ['SMTPs', 'TCP 465'], ['IMAPs', 'TCP 993'], ['POPs', 'TCP 995'], ['LDAP', 'TCP 389'],
  ['LDAPs', 'TCP 636'], ['DNS', 'UDP/TCP 53'], ['SSH', 'TCP 22'], ['Telnet', 'TCP 23'], ['SMTP', 'TCP 25'],
  ['HTTP', 'TCP 80'], ['POP3', 'TCP 110'], ['IMAP', 'TCP 143'], ['NTP', 'UDP 123'], ['SNMP', 'UDP 161'],
  ['RADIUS', 'UDP 1812'], ['Kerberos', 'UDP 88'], ['SMB', 'TCP 445'], ['MySQL', 'TCP 3306'], ['SIP', 'TCP 5060'],
  ['TFTP', 'UDP 69'], ['FTP (contrôle)', 'TCP 21'],
];

/* ----- générateurs ----- */
function qWildcard() {
  const kind = rnd(3);
  const prefix = pick([8, 12, 16, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]);
  const w = IP.wildOf(prefix);
  const nets = { 8: '10.0.0.0', 12: '172.16.0.0', 16: '172.17.0.0', 20: '172.16.16.0', 21: '172.16.8.0', 22: '172.16.4.0', 23: '172.16.2.0', 24: '172.16.1.0', 25: '172.16.1.128', 26: '172.16.2.64', 27: '172.16.0.224', 28: '172.16.0.240', 29: '192.168.1.8', 30: '200.0.0.252' };
  const net = nets[prefix];
  if (kind === 0) {
    return { cat: 'Masque générique', html: `Quel masque générique correspond à un <b>/${prefix}</b> (masque ${IP.toStr(IP.maskOf(prefix))}) ?`, input: '0.0.0.255', check: v => IP.toInt(v.trim()) === w, answer: IP.toStr(w), x: `255.255.255.255 − ${IP.toStr(IP.maskOf(prefix))} = ${IP.toStr(w)}.` };
  }
  if (kind === 1) {
    const base = IP.toInt(net);
    const last = IP.toStr((base | w) >>> 0);
    return { cat: 'Masque générique', html: `Écris le couple adresse + masque générique qui couvre <b>${net}</b> à <b>${last}</b>.`, input: '172.16.0.0 0.0.0.255', check: v => { const p = v.trim().split(/\s+/); return p.length === 2 && IP.toInt(p[0]) === base && IP.toInt(p[1]) === w; }, answer: `${net} ${IP.toStr(w)}`, x: `${net}/${prefix} : ${2 ** (32 - prefix)} adresses, masque générique ${IP.toStr(w)}.` };
  }
  const base = IP.toInt(net);
  const inside = Math.random() < 0.5;
  let probe;
  if (inside) probe = (base + rnd(Math.min(2 ** (32 - prefix), 4000))) >>> 0;
  else probe = (base + 2 ** (32 - prefix) + rnd(200)) >>> 0;
  const ok = IP.match(probe, base, w);
  return { cat: 'Masque générique', html: `L'adresse <b>${IP.toStr(probe)}</b> correspond-elle à <code>${net} ${IP.toStr(w)}</code> ?`, options: ['Oui', 'Non'], correct: ok ? 0 : 1, x: `${net} ${IP.toStr(w)} couvre ${net} à ${IP.toStr((base | w) >>> 0)}.` };
}

function qFact() {
  const f = pick(QUIZ_FACTS);
  const order = shuffle(f.o.map((t, i) => ({ t, i })));
  return { cat: 'Cours', html: esc(f.q), options: order.map(o => o.t), correct: order.findIndex(o => o.i === 0), x: f.x };
}

function qPort() {
  const [svc, ans] = pick(QUIZ_PORTS);
  const others = shuffle(QUIZ_PORTS.filter(p => p[1] !== ans)).slice(0, 3).map(p => p[1]);
  const opts = shuffle([ans, ...others]);
  return { cat: 'Ports', html: `Quel port utilise <b>${svc}</b> ?`, options: opts, correct: opts.indexOf(ans), x: `${svc} : ${ans}.` };
}

const QZ_SVCS = [['tcp', 80], ['tcp', 443], ['udp', 53], ['tcp', 25], ['tcp', 22], ['icmp', null], ['tcp', 993]];
function qVerdict() {
  const std = Math.random() < 0.3;
  const internal = HOSTS.filter(h => h.zone !== 'inet');
  const srcH = pick(internal);
  const dstH = pick(HOSTS.filter(h => h !== srcH && h.zone !== srcH.zone));
  const [proto, port] = pick(QZ_SVCS);
  const p = { src: srcH.ipn, dst: dstH.ipn, proto, sport: proto === 'icmp' ? null : 50123, dport: port, icmp: proto === 'icmp' ? 'echo' : null, ack: false };
  const netsFor = h => {
    const z = connectedIface(h.ipn);
    const list = [{ base: 0, wild: 0xFFFFFFFF }, { base: h.ipn, wild: 0 }];
    if (z) list.push({ base: z.net, wild: IP.wildOf(z.prefix) });
    if (h.zone !== 'inet' && h.zone !== 'dmz') list.push({ base: IP.toInt('172.16.0.0'), wild: IP.toInt('0.0.255.255') });
    return list;
  };
  const otherAddr = () => pick([
    { base: IP.toInt('172.16.2.0'), wild: 255 }, { base: IP.toInt('172.16.1.0'), wild: 255 }, { base: IP.toInt('172.17.0.0'), wild: 0xFFFF },
    { base: IP.toInt('172.16.0.0'), wild: 255 }, { base: pick(HOSTS).ipn, wild: 0 },
  ]);
  const n = 3 + rnd(2);
  const entries = [];
  for (let k = 0; k < n; k++) {
    const near = Math.random() < 0.55;
    const e = { seq: (k + 1) * 10, action: Math.random() < 0.5 ? 'permit' : 'deny', proto: 'ip', src: near ? pick(netsFor(srcH)) : otherAddr(), srcPort: null, dst: null, dstPort: null, established: false, icmp: null, log: false, timeRange: null };
    if (!std) {
      e.dst = Math.random() < 0.6 ? pick(netsFor(dstH)) : otherAddr();
      const r = Math.random();
      if (r < 0.3) e.proto = 'ip';
      else if (r < 0.75 && proto !== 'icmp') { e.proto = proto; e.dstPort = { op: 'eq', ports: [Math.random() < 0.6 ? port : pick([80, 443, 25, 22, 53])] }; }
      else { const [pp, po] = pick(QZ_SVCS); e.proto = pp; if (po) e.dstPort = { op: 'eq', ports: [po] }; }
      if (e.proto === 'udp' && e.dstPort && e.dstPort.ports[0] !== 53 && Math.random() < 0.7) e.dstPort.ports = [53];
    }
    entries.push(e);
  }
  if (Math.random() < 0.15) entries[entries.length - 1] = Object.assign(entries[entries.length - 1], std ? { src: { base: 0, wild: 0xFFFFFFFF } } : { proto: 'ip', src: { base: 0, wild: 0xFFFFFFFF }, dst: { base: 0, wild: 0xFFFFFFFF }, dstPort: null });
  const type = std ? 'standard' : 'extended';
  const hit = entries.findIndex(e => entryMatch(type, e, p));
  const lines = entries.map(e => ` ${e.seq} ${fmtEntry(e, type)}`);
  const title = std ? 'ip access-list standard QUIZ' : 'ip access-list extended QUIZ';
  const svc = serviceLabel(proto, port);
  const html = `<p>Le paquet <b>${esc(srcH.name)}</b> (${srcH.ip}) → <b>${esc(dstH.name)}</b> (${dstH.ip}), ${esc(svc)}, traverse cette ACL. Quelle ligne décide de son sort ?</p><pre class="qz-code">${esc(title)}\n${esc(lines.join('\n'))}</pre>`;
  const options = [...entries.map(e => `Ligne ${e.seq}`), 'Aucune : deny implicite'];
  const correct = hit < 0 ? entries.length : hit;
  const why = entries.slice(0, hit < 0 ? entries.length : hit).map(e => `ligne ${e.seq} : ${entryMismatch(type, e, p)} ne correspond pas`);
  const verdict = hit < 0 ? 'deny implicite → bloqué' : `ligne ${entries[hit].seq} → ${entries[hit].action === 'permit' ? 'autorisé' : 'bloqué'}`;
  return { cat: 'Quelle ligne ?', html, options, correct, x: `${why.length ? why.join(' · ') + ' · ' : ''}${verdict}.` };
}

const QUIZ_CATS = [
  { id: 'verdict', label: "Quelle ligne s'applique ?", gen: qVerdict },
  { id: 'wild', label: 'Masques génériques', gen: qWildcard },
  { id: 'fact', label: 'Questions de cours', gen: qFact },
  { id: 'port', label: 'Numéros de ports', gen: qPort },
];

/* ----- partie ----- */
const Quiz = {
  qs: [], k: 0, score: 0, streak: 0, best: 0, answered: false, good: 0,
  init() {
    this.best = store.get('quizBest', 0);
    const box = $('#quiz-cats');
    box.innerHTML = QUIZ_CATS.map(c => `<label class="check"><input type="checkbox" id="qc-${c.id}" value="${c.id}" checked><span>${c.label}</span></label>`).join('');
    $('#quiz-go').addEventListener('click', () => this.start());
    $('#qz-next').addEventListener('click', () => this.next());
    $('#quiz-best').textContent = `Record : ${this.best} pts`;
  },
  start() {
    const cats = QUIZ_CATS.filter(c => $('#qc-' + c.id).checked);
    if (!cats.length) { $('#quiz-best').textContent = 'Coche au moins une catégorie.'; return; }
    this.qs = Array.from({ length: 10 }, (_, i) => cats[i % cats.length].gen());
    this.qs = shuffle(this.qs);
    this.k = 0; this.score = 0; this.streak = 0; this.good = 0;
    $('#quiz-start').hidden = true; $('#quiz-end').hidden = true; $('#quiz-play').hidden = false;
    this.show();
  },
  show() {
    const q = this.qs[this.k];
    this.answered = false;
    $('#qz-n').textContent = `${this.k + 1} / ${this.qs.length}`;
    $('#qz-prog').style.width = `${(this.k / this.qs.length) * 100}%`;
    $('#qz-cat').textContent = q.cat;
    this.bar();
    $('#qz-q').innerHTML = q.html;
    $('#qz-fb').innerHTML = '';
    $('#qz-fb').className = 'qz-fb';
    $('#qz-next').hidden = true;
    const a = $('#qz-a');
    if (q.options) {
      a.innerHTML = q.options.map((o, i) => `<button type="button" class="qz-opt" data-i="${i}"><span class="qz-key">${'ABCDE'[i]}</span><span>${esc(o)}</span></button>`).join('');
      a.querySelectorAll('.qz-opt').forEach(b => b.addEventListener('click', () => this.answer(+b.dataset.i)));
    } else {
      a.innerHTML = `<form class="qz-form" id="qz-form"><input id="qz-input" class="qz-input" autocomplete="off" spellcheck="false" placeholder="${esc(q.input)}"><button class="btn primary" type="submit">Valider</button></form>`;
      $('#qz-form').addEventListener('submit', e => { e.preventDefault(); this.answer($('#qz-input').value); });
      $('#qz-input').focus();
    }
  },
  bar() {
    $('#qz-score').textContent = `${this.score} pts`;
    const mult = this.mult();
    $('#qz-streak').textContent = this.streak >= 2 ? `série ×${this.streak}${mult > 1 ? ` · points ×${mult}` : ''}` : '';
  },
  mult() { return this.streak >= 6 ? 3 : this.streak >= 3 ? 2 : 1; },
  answer(v) {
    if (this.answered) return;
    this.answered = true;
    const q = this.qs[this.k];
    const ok = q.options ? v === q.correct : q.check(String(v));
    if (q.options) {
      $('#qz-a').querySelectorAll('.qz-opt').forEach(b => {
        const i = +b.dataset.i;
        b.disabled = true;
        if (i === q.correct) b.classList.add('right');
        else if (i === v) b.classList.add('wrong');
      });
    } else {
      $('#qz-input').disabled = true;
      $('#qz-input').classList.add(ok ? 'right' : 'wrong');
    }
    if (ok) { this.streak++; this.good++; this.score += 100 * this.mult(); } else this.streak = 0;
    this.bar();
    const fb = $('#qz-fb');
    fb.className = 'qz-fb ' + (ok ? 'ok' : 'ko');
    fb.innerHTML = `<b>${ok ? 'Exact.' : 'Raté.'}</b> ${!ok && !q.options ? `Réponse : <code>${esc(q.answer)}</code>. ` : ''}${esc(q.x)}`;
    const nb = $('#qz-next');
    nb.hidden = false;
    nb.textContent = this.k + 1 < this.qs.length ? 'Question suivante' : 'Voir le résultat';
    nb.focus();
  },
  next() {
    this.k++;
    if (this.k < this.qs.length) return this.show();
    $('#qz-prog').style.width = '100%';
    const rec = this.score > this.best;
    if (rec) { this.best = this.score; store.set('quizBest', this.best); }
    const msg = this.good === 10 ? 'Sans faute. Le DS peut venir.'
      : this.good >= 8 ? 'Très solide. Encore une partie pour le sans-faute ?'
      : this.good >= 5 ? 'Bonne base. Relis le mémo sur les points ratés.'
      : 'À retravailler : fais un tour dans le mémo puis rejoue.';
    $('#quiz-play').hidden = true;
    const end = $('#quiz-end');
    end.hidden = false;
    end.innerHTML = `<p class="eyebrow">Partie terminée</p><p class="qz-final">${this.score} <span>pts</span></p><p>${this.good} bonne${this.good > 1 ? 's' : ''} réponse${this.good > 1 ? 's' : ''} sur 10. ${rec ? '<b>Nouveau record !</b>' : `Record : ${this.best} pts.`}</p><p class="muted">${msg}</p><div class="row"><button class="btn primary" id="qz-again" type="button">Rejouer</button><button class="btn" id="qz-cats" type="button">Changer les catégories</button></div>`;
    $('#qz-again').addEventListener('click', () => this.start());
    $('#qz-cats').addEventListener('click', () => { end.hidden = true; $('#quiz-start').hidden = false; $('#quiz-best').textContent = `Record : ${this.best} pts`; });
    if (rec || this.good === 10) confetti();
  },
};
