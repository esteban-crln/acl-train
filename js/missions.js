'use strict';
/* missions.js : parcours d'exercices inspiré du TD (exercice 1), avec flux de test et contraintes */

const BASE_NAT_DYN = [
  'interface G0/0', 'ip nat inside',
  'interface G0/1.0', 'ip nat inside',
  'interface G0/1.1', 'ip nat inside',
  'interface G0/1.2', 'ip nat inside',
  'interface S0/0', 'ip nat outside', 'exit',
  'ip access-list standard NAT-PRIVE', 'permit 172.16.0.0 0.0.255.255', 'permit 172.17.0.0 0.0.255.255', 'exit',
  'ip nat inside source list NAT-PRIVE interface S0/0 overload',
];
const BASE_FWD = [
  'ip nat inside source static tcp 172.17.0.1 80 200.0.0.254 80',
  'ip nat inside source static tcp 172.17.0.1 443 200.0.0.254 443',
  'ip nat inside source static tcp 172.17.0.2 25 200.0.0.254 25',
  'ip nat inside source static tcp 172.17.0.2 465 200.0.0.254 465',
  'ip nat inside source static tcp 172.17.0.2 993 200.0.0.254 993',
  'ip nat inside source static tcp 172.17.0.2 995 200.0.0.254 995',
];
const BASE_TD = [...BASE_NAT_DYN, ...BASE_FWD];
const BASE_TD_NOTE = 'Déjà en place : NAT/PAT de tous les réseaux privés sur S0/0, et redirections 200.0.0.254 → Web DMZ (80, 443) et Mail DMZ (25, 465, 993, 995). Vérifie avec show run.';

function T(from, to, svc, expect, o) {
  o = o || {};
  return { from, to, svc, expect, when: o.when || 'mar 10:00', reply: o.reply || null, at: o.at || null };
}

/* contrôles de configuration */
const CHK = {
  applied(cfg) {
    const r = [];
    for (const i of IFACES) {
      for (const dir of ['in', 'out']) {
        const n = cfg.ifaces[i.id][dir];
        if (n && cfg.acls[n]) r.push({ iface: i.id, dir, name: n, acl: cfg.acls[n] });
      }
    }
    return r;
  },
  isNum: n => /^\d+$/.test(n),
  stdNumbered: cfg => CHK.applied(cfg).some(a => a.acl.type === 'standard' && CHK.isNum(a.name)),
  stdAny: cfg => CHK.applied(cfg).some(a => a.acl.type === 'standard'),
  stdNamed: cfg => CHK.applied(cfg).some(a => a.acl.type === 'standard' && !CHK.isNum(a.name)),
  extAny: cfg => CHK.applied(cfg).some(a => a.acl.type === 'extended'),
  extNamed: cfg => CHK.applied(cfg).some(a => a.acl.type === 'extended' && !CHK.isNum(a.name)),
  timeRangeUsed: (cfg, abs) => CHK.applied(cfg).some(a => a.acl.entries.some(e => {
    const tr = e.timeRange && cfg.timeRanges[e.timeRange];
    return tr && (!abs || tr.absolute);
  })),
};

const CHAPTERS = [
  { id: 'std',  name: 'ACL standard' },
  { id: 'ext',  name: 'ACL étendue' },
  { id: 'time', name: 'Plages horaires' },
  { id: 'nat',  name: 'NAT et redirections' },
  { id: 'cbac', name: 'Filtrage avec état' },
  { id: 'td',   name: 'TD complet' },
];

const MISSIONS = [
  /* ---------------- ACL standard ---------------- */
  {
    id: 'm1', chapter: 'std', title: 'Premier filtre',
    brief: 'Le réseau <b>wifi</b> (172.16.2.0/24) ne doit plus atteindre le <b>réseau serveurs</b> (172.16.0.0/24). Tout le reste continue de fonctionner, y compris l\'accès du wifi à Internet et à la DMZ.',
    objectives: ['Bloquer wifi → serveurs', 'Ne rien casser d\'autre'],
    constraints: [{ text: 'ACL standard numérotée (1-99)', check: CHK.stdNumbered }],
    base: BASE_TD, baseNote: BASE_TD_NOTE,
    tests: [
      T('wifi1', 'intra', 'http', 'block'),
      T('wifi1', 'ldap', 'ldaps', 'block'),
      T('pc1', 'intra', 'http', 'pass'),
      T('wifi1', 'http1', 'https', 'pass'),
      T('wifi1', 'web', 'https', 'pass'),
      T('pc2', 'proxy', 'proxy', 'pass'),
    ],
    hints: [
      "Une ACL standard ne regarde que l'adresse source. Ici la source à bloquer est le réseau wifi : 172.16.2.0 avec le masque générique d'un /24.",
      "Masque générique d'un /24 : 0.0.0.255. N'oublie pas la dernière ligne « permit any », sinon le deny implicite bloque tout le reste.",
      "Une ACL standard se place près de la destination : sur G0/1.0 (vers les serveurs), dans le sens out. Si tu la mets en entrée du wifi, le wifi perd aussi Internet.",
    ],
    solution: ['configure terminal', 'access-list 10 deny 172.16.2.0 0.0.0.255', 'access-list 10 permit any', 'interface G0/1.0', 'ip access-group 10 out', 'end'],
    learn: "L'ACL standard ne connaît que la source : on la pose au plus près de la destination, en sortie (out). Et chaque ACL se termine par un deny implicite, d'où le permit any final.",
  },
  {
    id: 'm2', chapter: 'std', title: 'Un seul poste',
    brief: 'Le <b>PC filaire 2</b> (172.16.1.20) n\'a plus le droit de joindre la <b>DMZ</b>. Les autres postes filaires gardent l\'accès, et les clients Internet doivent toujours voir le site web.',
    objectives: ['Bloquer 172.16.1.20 → DMZ', 'Laisser passer les autres, Internet compris'],
    constraints: [{ text: 'ACL standard (numérotée ou nommée)', check: CHK.stdAny }],
    base: BASE_TD, baseNote: BASE_TD_NOTE,
    tests: [
      T('pc2', 'web', 'https', 'block'),
      T('pc2', 'mail', 'imaps', 'block'),
      T('pc1', 'web', 'https', 'pass'),
      T('pc2', 'http1', 'http', 'pass'),
      T('wifi1', 'mail', 'smtps', 'pass'),
      T('client', 'pub', 'https', 'pass', { at: 'web' }),
    ],
    hints: [
      'Pour viser une seule machine : « host 172.16.1.20 » (équivalent de 172.16.1.20 0.0.0.0).',
      'La destination (la DMZ) est derrière G0/0. Une ACL standard se place près de la destination.',
      'access-list 20 deny host 172.16.1.20, puis access-list 20 permit any, appliquée sur G0/0 en out.',
    ],
    solution: ['configure terminal', 'access-list 20 deny host 172.16.1.20', 'access-list 20 permit any', 'interface G0/0', 'ip access-group 20 out', 'end'],
    learn: '« host X » vaut X 0.0.0.0, et « any » vaut 0.0.0.0 255.255.255.255. En sortie de G0/0, la règle ne touche que le trafic qui va vers la DMZ.',
  },
  {
    id: 'm3', chapter: 'std', title: "L'ordre compte",
    brief: 'Plus aucune machine du LAN (172.16.0.0/16) ne joint la <b>DMZ</b>, <b>sauf</b> le <b>proxy</b> (172.16.0.253) et le poste admin <b>PC filaire 1</b> (172.16.1.10). Internet doit toujours accéder aux services de la DMZ.',
    objectives: ['Exceptions : proxy et PC filaire 1', 'Bloquer le reste du LAN vers la DMZ', 'Internet garde l\'accès'],
    constraints: [{ text: 'ACL standard nommée', check: CHK.stdNamed }],
    base: BASE_TD, baseNote: BASE_TD_NOTE,
    tests: [
      T('proxy', 'web', 'https', 'pass'),
      T('pc1', 'mail', 'imaps', 'pass'),
      T('pc2', 'web', 'https', 'block'),
      T('wifi1', 'web', 'https', 'block'),
      T('intra', 'mail', 'smtp', 'block'),
      T('client', 'pub', 'https', 'pass', { at: 'web' }),
    ],
    hints: [
      'ACL nommée : « ip access-list standard DMZ-ACCES », puis une règle par ligne. Le LAN entier 172.16.0.0/16 a pour masque générique 0.0.255.255.',
      "Les exceptions passent AVANT le deny général : la première ligne qui correspond est la seule appliquée. Si le deny est en premier, le proxy est bloqué aussi.",
      'permit host 172.16.0.253 · permit host 172.16.1.10 · deny 172.16.0.0 0.0.255.255 · permit any, puis sur G0/0 : ip access-group DMZ-ACCES out.',
    ],
    solution: ['configure terminal', 'ip access-list standard DMZ-ACCES', 'permit host 172.16.0.253', 'permit host 172.16.1.10', 'deny 172.16.0.0 0.0.255.255', 'permit any', 'exit', 'interface G0/0', 'ip access-group DMZ-ACCES out', 'end'],
    learn: "Dans une ACL, l'ordre est tout : on écrit les exceptions précises d'abord, la règle générale ensuite. Si tu te trompes, une ACL nommée permet d'insérer une ligne avec un numéro (ex. 5 permit host …).",
  },

  /* ---------------- ACL étendue ---------------- */
  {
    id: 'm4', chapter: 'ext', title: 'Wifi : web seulement',
    brief: 'Les clients <b>wifi</b> n\'ont droit qu\'au <b>web</b> (HTTP, HTTPS) et au <b>DNS</b>. Tout le reste leur est interdit, ping compris. Les autres réseaux ne sont pas concernés.',
    objectives: ['Wifi : TCP 80 et 443, UDP 53', 'Wifi : tout le reste bloqué', 'Les autres réseaux inchangés'],
    constraints: [{ text: 'ACL étendue', check: CHK.extAny }],
    base: BASE_TD, baseNote: BASE_TD_NOTE,
    tests: [
      T('wifi1', 'http1', 'http', 'pass'),
      T('wifi1', 'http2', 'https', 'pass'),
      T('wifi1', 'dns', 'dns', 'pass'),
      T('wifi1', 'imail', 'smtp', 'block'),
      T('wifi1', 'intra', 'ssh', 'block'),
      T('wifi1', 'http1', 'ping', 'block'),
      T('pc1', 'imail', 'smtp', 'pass'),
      T('pc1', 'http1', 'ping', 'pass'),
    ],
    hints: [
      "Une ACL étendue précise protocole, source, destination et port : permit tcp 172.16.2.0 0.0.0.255 any eq 80. Attention, le DNS est en UDP.",
      'Une ACL étendue se place près de la source : en entrée (in) de G0/1.2, l\'interface du wifi.',
      "Piège : sur S0/0 en sortie, la NAT a déjà remplacé la source par 200.0.0.254 (sens OUT : NAT puis ACL). L'ACL n'y reconnaîtrait plus le wifi.",
    ],
    solution: ['configure terminal', 'access-list 110 permit tcp 172.16.2.0 0.0.0.255 any eq 80', 'access-list 110 permit tcp 172.16.2.0 0.0.0.255 any eq 443', 'access-list 110 permit udp 172.16.2.0 0.0.0.255 any eq 53', 'access-list 110 deny ip any any', 'interface G0/1.2', 'ip access-group 110 in', 'end'],
    learn: "L'ACL étendue filtre finement, donc on la pose près de la source pour jeter le trafic interdit tout de suite. Le DNS passe en UDP 53, le ping en ICMP : chaque protocole a sa ligne.",
  },
  {
    id: 'm5', chapter: 'ext', title: 'Les réponses aussi',
    brief: 'La <b>DMZ</b> ne doit jamais <b>ouvrir</b> de connexion vers le LAN (172.16.0.0/16), sauf le <b>serveur mail</b> qui interroge l\'annuaire <b>LDAPs</b> (172.16.0.250, TCP 636). Les utilisateurs du LAN doivent pourtant continuer à utiliser la DMZ : <b>les réponses</b> des serveurs doivent revenir, ping compris.',
    objectives: ['Mail DMZ → LDAPs autorisé', 'DMZ → LAN interdit', 'Les réponses DMZ → LAN passent'],
    constraints: [],
    base: BASE_TD, baseNote: BASE_TD_NOTE,
    tests: [
      T('mail', 'ldap', 'ldaps', 'pass'),
      T('mail', 'ldap', 'ldap', 'block'),
      T('web', 'intra', 'http', 'block'),
      T('web', 'auth', 'radius', 'block'),
      T('pc1', 'web', 'https', 'pass', { reply: 'pass' }),
      T('wifi1', 'mail', 'imaps', 'pass', { reply: 'pass' }),
      T('pc1', 'web', 'ping', 'pass', { reply: 'pass' }),
      T('web', 'cert', 'https', 'pass', { reply: 'pass' }),
    ],
    hints: [
      'Filtre ce qui ENTRE dans Ro depuis la DMZ : une ACL étendue en entrée (in) de G0/0.',
      "Sans état, l'ACL ne sait pas qu'un paquet est une réponse. Pour TCP, le mot-clé established laisse passer les segments avec ACK : permit tcp 172.17.0.0 0.0.255.255 172.16.0.0 0.0.255.255 established.",
      "Pour le ping, la réponse est un ICMP echo-reply : permit icmp 172.17.0.0 0.0.255.255 172.16.0.0 0.0.255.255 echo-reply. Puis deny DMZ → LAN, puis permit ip any any pour le reste.",
    ],
    solution: ['configure terminal', 'ip access-list extended DMZ-IN', 'permit tcp host 172.17.0.2 host 172.16.0.250 eq 636', 'permit tcp 172.17.0.0 0.0.255.255 172.16.0.0 0.0.255.255 established', 'permit icmp 172.17.0.0 0.0.255.255 172.16.0.0 0.0.255.255 echo-reply', 'deny ip 172.17.0.0 0.0.255.255 172.16.0.0 0.0.255.255', 'permit ip any any', 'exit', 'interface G0/0', 'ip access-group DMZ-IN in', 'end'],
    learn: "Un filtrage sans état juge chaque paquet seul. established (TCP avec ACK) et echo-reply (ICMP) sont les astuces pour laisser revenir les réponses. Le filtrage avec état (chapitre 5) fait ça proprement.",
  },
  {
    id: 'm6', chapter: 'ext', title: 'Le piège de la NAT',
    brief: 'Un collègue veut forcer les postes <b>filaires et wifi</b> à passer par le <b>proxy</b> (172.16.0.253, port 8080) pour le web vers Internet. Seul le proxy sort en HTTP/HTTPS. Il a écrit l\'ACL <b>WEB-PROXY</b> sur S0/0 en sortie… et plus personne ne navigue, même pas le proxy. Répare. Les accès web internes (DMZ, intranet) et le reste (DNS…) restent autorisés.',
    objectives: ['Le proxy navigue sur Internet', 'Postes filaires et wifi : web Internet direct interdit', 'Web interne, proxy et DNS toujours OK'],
    constraints: [],
    base: [...BASE_TD, 'ip access-list extended WEB-PROXY', 'permit tcp host 172.16.0.253 any eq 80', 'permit tcp host 172.16.0.253 any eq 443', 'deny tcp any any eq 80', 'deny tcp any any eq 443', 'permit ip any any', 'exit', 'interface S0/0', 'ip access-group WEB-PROXY out', 'exit'],
    baseNote: BASE_TD_NOTE + ' Plus l\'ACL WEB-PROXY appliquée sur S0/0 out (c\'est elle le problème).',
    tests: [
      T('proxy', 'http1', 'http', 'pass'),
      T('proxy', 'http2', 'https', 'pass'),
      T('pc1', 'http1', 'http', 'block'),
      T('wifi1', 'http2', 'https', 'block'),
      T('pc1', 'proxy', 'proxy', 'pass'),
      T('wifi1', 'proxy', 'proxy', 'pass'),
      T('pc1', 'web', 'https', 'pass'),
      T('wifi1', 'intra', 'http', 'pass'),
      T('pc2', 'dns', 'dns', 'pass'),
    ],
    hints: [
      "Envoie un paquet du proxy vers HTTP1 et lis la trace : sur S0/0 out, quelle est l'adresse source quand l'ACL la regarde ?",
      "Sens OUT : NAT puis ACL. Sur S0/0 out, toutes les sources valent 200.0.0.254, l'ACL ne peut plus distinguer le proxy. Retire-la (no ip access-group WEB-PROXY out dans S0/0).",
      "Filtre plutôt à l'entrée des postes (G0/1.1 in et G0/1.2 in) : d'abord autoriser TCP vers 172.16.0.0/16 et 172.17.0.0/16 (interne), puis deny tcp any any eq 80 et eq 443, puis permit ip any any.",
    ],
    solution: ['configure terminal', 'interface S0/0', 'no ip access-group WEB-PROXY out', 'exit', 'ip access-list extended USERS-WEB', 'permit tcp any 172.16.0.0 0.0.255.255', 'permit tcp any 172.17.0.0 0.0.255.255', 'deny tcp any any eq 80', 'deny tcp any any eq 443', 'permit ip any any', 'exit', 'interface G0/1.1', 'ip access-group USERS-WEB in', 'interface G0/1.2', 'ip access-group USERS-WEB in', 'end'],
    learn: "Sur l'interface NAT outside, une ACL out voit les adresses déjà traduites. Pour filtrer selon l'adresse privée d'une machine, place l'ACL côté inside, en entrée près de la source.",
  },

  /* ---------------- Plages horaires ---------------- */
  {
    id: 'm7', chapter: 'time', title: 'Pause déjeuner',
    brief: 'Question du TD : les clients <b>filaires et wifi</b> n\'accèdent au serveur <b>HTTP2</b> (203.0.0.1, le réseau social) que <b>de 12h à 14h les jours ouvrés</b>. Le reste du trafic n\'est pas concerné, et les serveurs non plus.',
    objectives: ['HTTP2 ouvert lun-ven 12h-14h', 'HTTP2 fermé le reste du temps', 'Le reste inchangé'],
    constraints: [{ text: 'Règle liée à une time-range', check: cfg => CHK.timeRangeUsed(cfg, false) }],
    base: BASE_TD, baseNote: BASE_TD_NOTE,
    tests: [
      T('pc1', 'http2', 'https', 'pass', { when: 'mar 12:30' }),
      T('wifi1', 'http2', 'https', 'pass', { when: 'jeu 13:15' }),
      T('pc1', 'http2', 'https', 'block', { when: 'mar 10:00' }),
      T('wifi1', 'http2', 'http', 'block', { when: 'sam 12:30' }),
      T('pc2', 'http2', 'https', 'block', { when: 'ven 15:00' }),
      T('pc1', 'http1', 'https', 'pass', { when: 'mar 10:00' }),
      T('proxy', 'http2', 'https', 'pass', { when: 'mar 10:00' }),
    ],
    hints: [
      "Crée la plage : time-range MIDI, puis periodic weekdays 12:00 to 14:00 (weekdays = du lundi au vendredi).",
      "Dans une ACL étendue : permit ip any host 203.0.0.1 time-range MIDI, puis deny ip any host 203.0.0.1 (hors créneau), puis permit ip any any.",
      'Applique-la en entrée des deux réseaux utilisateurs : G0/1.1 in et G0/1.2 in (la même ACL peut servir sur deux interfaces).',
    ],
    solution: ['configure terminal', 'time-range MIDI', 'periodic weekdays 12:00 to 14:00', 'exit', 'ip access-list extended SOCIAL', 'permit ip any host 203.0.0.1 time-range MIDI', 'deny ip any host 203.0.0.1', 'permit ip any any', 'exit', 'interface G0/1.1', 'ip access-group SOCIAL in', 'interface G0/1.2', 'ip access-group SOCIAL in', 'end'],
    learn: "Hors de sa plage, une règle avec time-range est simplement ignorée : le paquet continue vers les lignes suivantes. D'où le deny juste après, pour fermer HTTP2 le reste du temps. Change l'heure du testeur et regarde show access-lists : (active) / (inactive).",
  },
  {
    id: 'm8', chapter: 'time', title: 'Le prestataire du weekend',
    brief: 'Le <b>prestataire</b> (81.250.0.7) administre le serveur mail en SSH via une redirection : <b>200.0.0.254:2222 → 172.17.0.2:22</b>. Il ne doit pouvoir le faire que <b>le weekend de 9h à 12h</b>. Personne d\'autre depuis Internet ne passe par le port 2222. Filtre à l\'entrée de S0/0, sans couper le reste.',
    objectives: ['Prestataire : SSH le weekend 9h-12h', 'Port 2222 fermé aux autres', 'Les autres flux continuent'],
    constraints: [{ text: 'ACL en entrée de S0/0 avec une time-range', check: cfg => { const n = cfg.ifaces['S0/0'].in; const a = n && cfg.acls[n]; return !!a && a.entries.some(e => e.timeRange && cfg.timeRanges[e.timeRange]); } }],
    base: [...BASE_TD, 'ip nat inside source static tcp 172.17.0.2 22 200.0.0.254 2222'],
    baseNote: BASE_TD_NOTE + ' Plus la redirection tcp 200.0.0.254:2222 → 172.17.0.2:22.',
    tests: [
      T('presta', 'pub', 'ssh2222', 'pass', { when: 'sam 10:00', at: 'mail' }),
      T('presta', 'pub', 'ssh2222', 'pass', { when: 'dim 11:30', at: 'mail' }),
      T('presta', 'pub', 'ssh2222', 'block', { when: 'lun 10:00' }),
      T('presta', 'pub', 'ssh2222', 'block', { when: 'sam 14:00' }),
      T('client', 'pub', 'ssh2222', 'block', { when: 'sam 10:00' }),
      T('client', 'pub', 'https', 'pass', { at: 'web' }),
      T('pc1', 'http1', 'https', 'pass', { reply: 'pass' }),
    ],
    hints: [
      'time-range WEEKEND puis periodic weekend 09:00 to 12:00.',
      "Sens IN : l'ACL passe AVANT la redirection de ports. Sur S0/0 in, le paquet vise encore 200.0.0.254 port 2222, pas 172.17.0.2 port 22.",
      'permit tcp host 81.250.0.7 host 200.0.0.254 eq 2222 time-range WEEKEND · deny tcp any any eq 2222 · permit ip any any, sur S0/0 in.',
    ],
    solution: ['configure terminal', 'time-range WEEKEND', 'periodic weekend 09:00 to 12:00', 'exit', 'ip access-list extended INTERNET-IN', 'permit tcp host 81.250.0.7 host 200.0.0.254 eq 2222 time-range WEEKEND', 'deny tcp any any eq 2222', 'permit ip any any', 'exit', 'interface S0/0', 'ip access-group INTERNET-IN in', 'end'],
    learn: "Sur l'interface outside, l'ACL d'entrée voit l'adresse publique et le port public : la redirection n'a pas encore eu lieu. C'est la règle du cours : IN = ACL puis redirection de ports.",
  },
  {
    id: 'm9', chapter: 'time', title: 'Le stagiaire',
    brief: 'Le stagiaire utilise le <b>PC filaire 2</b> (172.16.1.20). Il accède au <b>web intranet</b> (172.16.0.252, HTTP et HTTPS) uniquement pendant son stage, <b>du 2 novembre 2026 8h au 18 décembre 2026 18h</b>, et seulement <b>en semaine de 8h à 18h</b>. Le reste de son trafic et les autres postes ne sont pas concernés.',
    objectives: ['Intranet ouvert pendant le stage, en semaine 8h-18h', 'Intranet fermé avant, après, le soir et le weekend', 'Le reste inchangé'],
    constraints: [{ text: 'time-range avec absolute', check: cfg => CHK.timeRangeUsed(cfg, true) }],
    base: BASE_TD, baseNote: BASE_TD_NOTE,
    tests: [
      T('pc2', 'intra', 'https', 'pass', { when: '2026-11-05 10:00' }),
      T('pc2', 'intra', 'http', 'block', { when: '2026-10-15 10:00' }),
      T('pc2', 'intra', 'https', 'block', { when: '2026-11-07 10:00' }),
      T('pc2', 'intra', 'https', 'block', { when: '2026-11-05 19:00' }),
      T('pc2', 'intra', 'https', 'block', { when: '2026-12-21 10:00' }),
      T('pc1', 'intra', 'https', 'pass', { when: '2026-10-15 10:00' }),
      T('pc2', 'http1', 'https', 'pass', { when: '2026-10-15 10:00' }),
    ],
    hints: [
      'Une même time-range peut combiner absolute (les dates de début et de fin) et periodic (le créneau) : les deux doivent être vrais.',
      'Dates au format IOS, mois en anglais : absolute start 08:00 02 Nov 2026 end 18:00 18 Dec 2026, puis periodic weekdays 08:00 to 18:00.',
      'permit tcp host 172.16.1.20 host 172.16.0.252 eq 80 443 time-range STAGE · deny ip host 172.16.1.20 host 172.16.0.252 · permit ip any any, sur G0/1.1 in.',
    ],
    solution: ['configure terminal', 'time-range STAGE', 'absolute start 08:00 02 Nov 2026 end 18:00 18 Dec 2026', 'periodic weekdays 08:00 to 18:00', 'exit', 'ip access-list extended STAGIAIRE', 'permit tcp host 172.16.1.20 host 172.16.0.252 eq 80 443 time-range STAGE', 'deny ip host 172.16.1.20 host 172.16.0.252', 'permit ip any any', 'exit', 'interface G0/1.1', 'ip access-group STAGIAIRE in', 'end'],
    learn: 'absolute borne la période dans le calendrier, periodic découpe les créneaux récurrents. Dans la même time-range, une règle est active seulement si les deux conditions sont vraies.',
  },

  /* ---------------- NAT ---------------- */
  {
    id: 'm10', chapter: 'nat', title: 'NAT/PAT',
    brief: 'Question 1 du TD. Le routeur est vierge : aucune NAT. Mets en place la <b>traduction d\'adresses et de ports (PAT)</b> pour que tous les réseaux privés (LAN 172.16.0.0/16 et DMZ 172.17.0.0/16) sortent sur Internet avec l\'adresse de <b>S0/0</b>. Les réponses doivent revenir.',
    objectives: ['Interfaces inside / outside', 'ACL des adresses à traduire', 'PAT sur S0/0 (overload)'],
    constraints: [{ text: 'PAT avec overload', check: cfg => cfg.natDyn.some(d => d.overload && d.iface === 'S0/0') }],
    base: [], baseNote: 'Routeur sans NAT ni ACL.',
    tests: [
      T('pc1', 'http1', 'http', 'pass', { reply: 'pass' }),
      T('wifi1', 'dns', 'dns', 'pass', { reply: 'pass' }),
      T('proxy', 'http2', 'https', 'pass', { reply: 'pass' }),
      T('web', 'imail', 'smtp', 'pass', { reply: 'pass' }),
      T('pc1', 'web', 'https', 'pass', { reply: 'pass' }),
    ],
    hints: [
      "Sans NAT, le paquet part avec une source privée et la réponse se perd sur Internet. Teste PC filaire 1 → HTTP1 pour le voir.",
      'Marque chaque interface : ip nat inside sur G0/0, G0/1.0, G0/1.1, G0/1.2 et ip nat outside sur S0/0.',
      'ACL standard des adresses privées (permit 172.16.0.0 0.0.255.255 et permit 172.17.0.0 0.0.255.255), puis ip nat inside source list NOM interface S0/0 overload.',
    ],
    solution: ['configure terminal', 'interface G0/0', 'ip nat inside', 'interface G0/1.0', 'ip nat inside', 'interface G0/1.1', 'ip nat inside', 'interface G0/1.2', 'ip nat inside', 'interface S0/0', 'ip nat outside', 'exit', 'ip access-list standard NAT', 'permit 172.16.0.0 0.0.255.255', 'permit 172.17.0.0 0.0.255.255', 'exit', 'ip nat inside source list NAT interface S0/0 overload', 'end'],
    learn: "La PAT remplace la source privée par l'IP publique de S0/0 et garde la trace du port pour renvoyer chaque réponse au bon poste. Elle se met en place sur le routeur de bordure, celui qui touche Internet.",
  },
  {
    id: 'm11', chapter: 'nat', title: 'Redirection de ports',
    brief: 'Question 2 du TD. Rends accessibles depuis Internet, via <b>200.0.0.254</b> : le <b>Web DMZ</b> en HTTP et HTTPS, le <b>Mail DMZ</b> en SMTP (25), SMTPs (465) et IMAPs (993). Rien d\'autre.',
    objectives: ['Web : 80 et 443', 'Mail : 25, 465 et 993', 'Rien d\'autre depuis Internet'],
    constraints: [],
    base: BASE_NAT_DYN, baseNote: 'Déjà en place : NAT/PAT des réseaux privés sur S0/0 (interfaces inside/outside marquées). Aucune redirection.',
    tests: [
      T('client', 'pub', 'http', 'pass', { at: 'web', reply: 'pass' }),
      T('client', 'pub', 'https', 'pass', { at: 'web', reply: 'pass' }),
      T('client', 'pub', 'smtp', 'pass', { at: 'mail' }),
      T('client', 'pub', 'smtps', 'pass', { at: 'mail' }),
      T('client', 'pub', 'imaps', 'pass', { at: 'mail', reply: 'pass' }),
      T('client', 'pub', 'ssh', 'block'),
      T('client', 'pub', 'rdp', 'block'),
    ],
    hints: [
      "Depuis Internet, le client vise l'adresse publique 200.0.0.254 et un port. La table de redirection dit vers quel serveur privé envoyer chaque port.",
      'Syntaxe : ip nat inside source static tcp IP_privée PORT IP_publique PORT.',
      'Exemple : ip nat inside source static tcp 172.17.0.1 443 200.0.0.254 443. Une ligne par port.',
    ],
    solution: ['configure terminal', 'ip nat inside source static tcp 172.17.0.1 80 200.0.0.254 80', 'ip nat inside source static tcp 172.17.0.1 443 200.0.0.254 443', 'ip nat inside source static tcp 172.17.0.2 25 200.0.0.254 25', 'ip nat inside source static tcp 172.17.0.2 465 200.0.0.254 465', 'ip nat inside source static tcp 172.17.0.2 993 200.0.0.254 993', 'end'],
    learn: "La redirection de ports (NAT/PAT statique) publie un service privé sur l'adresse publique. Un port non redirigé s'arrête au routeur : c'est déjà une forme de filtrage.",
  },

  /* ---------------- Filtrage avec état ---------------- */
  {
    id: 'm12', chapter: 'cbac', title: 'Inspection IP',
    brief: 'Question 4 du TD. L\'ACL <b>INTERNET-IN</b> (S0/0 in) ne laisse entrer que les services publiés… et du coup, les <b>réponses</b> aux utilisateurs du LAN sont bloquées. Sans toucher à INTERNET-IN, active le <b>filtrage avec état</b> pour que les réponses TCP, UDP et ICMP reviennent.',
    objectives: ['Les réponses Internet → LAN reviennent', 'Internet reste limité à 443, 465, 993'],
    constraints: [{ text: 'INTERNET-IN inchangée sur S0/0 in', check: cfg => { const a = cfg.acls['INTERNET-IN']; return cfg.ifaces['S0/0'].in === 'INTERNET-IN' && !!a && a.entries.length === 4 && fmtEntry(a.entries[3], 'extended') === 'deny ip any any'; } }],
    base: [...BASE_TD, 'ip access-list extended INTERNET-IN', 'permit tcp any host 200.0.0.254 eq 443', 'permit tcp any host 200.0.0.254 eq 465', 'permit tcp any host 200.0.0.254 eq 993', 'deny ip any any', 'exit', 'interface S0/0', 'ip access-group INTERNET-IN in', 'exit'],
    baseNote: BASE_TD_NOTE + ' Plus l\'ACL INTERNET-IN sur S0/0 in.',
    tests: [
      T('pc1', 'http1', 'https', 'pass', { reply: 'pass' }),
      T('wifi1', 'dns', 'dns', 'pass', { reply: 'pass' }),
      T('pc2', 'http1', 'ping', 'pass', { reply: 'pass' }),
      T('proxy', 'http2', 'http', 'pass', { reply: 'pass' }),
      T('client', 'pub', 'https', 'pass', { at: 'web', reply: 'pass' }),
      T('client', 'pub', 'ssh', 'block'),
      T('client', 'pub', 'http', 'block'),
    ],
    hints: [
      "Définis ce qu'il faut inspecter : ip inspect name LEGITIME tcp, puis udp, puis icmp (une ligne chacun).",
      "On inspecte dans le sens des requêtes. Les requêtes du LAN sortent vers Internet par S0/0 : c'est le sens out de S0/0.",
      'interface S0/0 puis ip inspect LEGITIME out : les réponses seront acceptées en entrée de S0/0 même si INTERNET-IN les refuse.',
    ],
    solution: ['configure terminal', 'ip inspect name LEGITIME tcp', 'ip inspect name LEGITIME udp', 'ip inspect name LEGITIME icmp', 'interface S0/0', 'ip inspect LEGITIME out', 'end'],
    learn: "Le filtrage avec état mémorise chaque requête sortante. La réponse est acceptée dans l'autre sens sur la même interface, même si l'ACL l'interdit. Plus besoin d'established, et ça marche aussi pour UDP et ICMP.",
  },

  /* ---------------- TD complet ---------------- */
  {
    id: 'm13', chapter: 'td', title: 'Exercice 1, question 3',
    brief: 'Le filtrage complet du TD. 1) Les clients Internet n\'atteignent du réseau privé que les services publiés. 2) Tout le monde (LAN et Internet) n\'accède qu\'aux services <b>Web et Mail sécurisés</b> de la DMZ : HTTPS 443, SMTPs 465, IMAPs 993, POPs 995. 3) Les accès web des postes filaires et wifi vers Internet doivent passer par le <b>proxy</b> (port 8080) pour être journalisés. 4) Comme le web passe par le proxy, c\'est le <b>proxy</b> qui n\'atteint <b>HTTP2</b> que de 12h à 14h les jours ouvrés. 5) Tout le reste est autorisé, réponses comprises.',
    objectives: ['DMZ : services sécurisés seulement', 'Web Internet des postes : via le proxy', 'Proxy → HTTP2 : 12h-14h en semaine', 'Le reste autorisé'],
    constraints: [],
    base: BASE_TD, baseNote: BASE_TD_NOTE,
    tests: [
      T('client', 'pub', 'https', 'pass', { at: 'web' }),
      T('client', 'pub', 'imaps', 'pass', { at: 'mail' }),
      T('client', 'pub', 'http', 'block'),
      T('client', 'pub', 'smtp', 'block'),
      T('pc1', 'web', 'https', 'pass', { reply: 'pass' }),
      T('wifi1', 'web', 'http', 'block'),
      T('pc2', 'mail', 'smtp', 'block'),
      T('wifi1', 'mail', 'pops', 'pass'),
      T('pc1', 'http1', 'https', 'block'),
      T('pc1', 'proxy', 'proxy', 'pass'),
      T('proxy', 'http1', 'https', 'pass', { reply: 'pass' }),
      T('proxy', 'http2', 'https', 'pass', { when: 'mar 12:30' }),
      T('proxy', 'http2', 'https', 'block', { when: 'mar 16:00' }),
      T('proxy', 'http2', 'https', 'block', { when: 'sam 12:30' }),
      T('pc1', 'dns', 'dns', 'pass', { reply: 'pass' }),
      T('web', 'cert', 'https', 'pass', { reply: 'pass' }),
      T('wifi1', 'intra', 'http', 'pass'),
    ],
    hints: [
      "Découpe en trois ACL : une en sortie de G0/0 (tout ce qui va vers la DMZ, Internet compris, après redirection), une en entrée des postes (G0/1.1 et G0/1.2), une en entrée des serveurs (G0/1.0) pour le proxy.",
      "Vers la DMZ : permit les 4 services sécurisés, puis deny ip any 172.17.0.0 0.0.255.255. Attention aux réponses que reçoivent les serveurs DMZ quand ce sont eux qui sortent : established.",
      "Postes : permit tcp vers 172.16.0.0/16 et 172.17.0.0/16, deny tcp any any eq 80 et eq 443, permit ip any any. Proxy : permit tcp host 172.16.0.253 host 203.0.0.1 time-range MIDI, deny ip any host 203.0.0.1, permit ip any any.",
    ],
    solution: ['configure terminal', 'time-range MIDI', 'periodic weekdays 12:00 to 14:00', 'exit',
      'ip access-list extended DMZ-OUT', 'permit tcp any host 172.17.0.1 eq 443', 'permit tcp any host 172.17.0.2 eq 465', 'permit tcp any host 172.17.0.2 eq 993', 'permit tcp any host 172.17.0.2 eq 995', 'permit tcp any 172.17.0.0 0.0.255.255 established', 'deny ip any 172.17.0.0 0.0.255.255', 'permit ip any any', 'exit',
      'ip access-list extended USERS-IN', 'permit tcp any 172.16.0.0 0.0.255.255', 'permit tcp any 172.17.0.0 0.0.255.255', 'deny tcp any any eq 80', 'deny tcp any any eq 443', 'permit ip any any', 'exit',
      'ip access-list extended PROXY-IN', 'permit tcp host 172.16.0.253 host 203.0.0.1 time-range MIDI', 'deny ip any host 203.0.0.1', 'permit ip any any', 'exit',
      'interface G0/0', 'ip access-group DMZ-OUT out', 'interface G0/1.1', 'ip access-group USERS-IN in', 'interface G0/1.2', 'ip access-group USERS-IN in', 'interface G0/1.0', 'ip access-group PROXY-IN in', 'end'],
    learn: 'Une vraie politique de filtrage se découpe par interface et par sens. Une ACL en sortie de la DMZ protège ses serveurs pour tout le monde à la fois, car elle voit les adresses après la redirection de ports.',
  },
];
const MISSION_BY_ID = Object.fromEntries(MISSIONS.map(m => [m.id, m]));

function testSpec(t) {
  const a = endpoint(t.from), b = endpoint(t.to), s = SERVICE_BY_ID[t.svc];
  return { src: a.ipn, dst: b.ipn, proto: s.proto, dport: s.port };
}
function testLabel(t) {
  const a = endpoint(t.from), b = endpoint(t.to), s = SERVICE_BY_ID[t.svc];
  return { from: a.name, to: b.id === 'pub' ? '200.0.0.254' : b.name, svc: serviceLabel(s.proto, s.port) };
}

function runTest(cfg, t) {
  const date = parseWhen(t.when);
  const R = sendRequest(cfg, testSpec(t), date, false);
  const atOk = !t.at || R.atIp === HOST_BY_ID[t.at].ipn;
  let ok = t.expect === 'pass' ? R.delivered && atOk : !R.delivered;
  let Q = null, why = null;
  if (t.expect === 'pass' && !R.delivered) {
    const s = [...R.steps].reverse().find(x => x.ok === false);
    why = 'Bloqué : ' + (s ? s.text : 'le paquet n\'arrive pas.');
  } else if (t.expect === 'pass' && !atOk) {
    const h = HOST_BY_IP[R.atIp];
    why = `Arrivé chez ${h ? h.name : IP.toStr(R.atIp)} au lieu de ${HOST_BY_ID[t.at].name}.`;
  } else if (t.expect === 'block' && R.delivered) {
    why = 'Le paquet est arrivé alors qu\'il aurait dû être bloqué.';
  }
  if (ok && t.reply) {
    Q = sendReply(cfg, R, date, false);
    const back = !!(Q && Q.delivered);
    if (back !== (t.reply === 'pass')) {
      ok = false;
      const s = Q && [...Q.steps].reverse().find(x => x.ok === false);
      why = 'Aller OK, mais la réponse est bloquée : ' + (s ? s.text : '');
    }
  }
  return { ok, R, Q, why, date };
}
