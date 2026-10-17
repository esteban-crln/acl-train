'use strict';
/* net.js : outils IPv4, topologie du TD (exercice 1), services usuels et dates de simulation */

const IP = {
  toInt(s) {
    if (typeof s !== 'string') return null;
    const p = s.split('.');
    if (p.length !== 4) return null;
    let n = 0;
    for (const x of p) {
      if (!/^\d{1,3}$/.test(x)) return null;
      const v = Number(x);
      if (v > 255) return null;
      n = n * 256 + v;
    }
    return n;
  },
  toStr(n) {
    return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  },
  maskOf(prefix) {
    return prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  },
  wildOf(prefix) {
    return (~IP.maskOf(prefix)) >>> 0;
  },
  // l'adresse ip correspond-elle au couple base / masque générique ?
  match(ip, base, wild) {
    return (((ip ^ base) & ~wild) >>> 0) === 0;
  },
  inNet(ip, net, prefix) {
    return IP.match(ip, net, IP.wildOf(prefix));
  },
  isPrivate(n) {
    return IP.match(n, 0x0A000000, 0x00FFFFFF)
      || IP.match(n, 0xAC100000, 0x000FFFFF)
      || IP.match(n, 0xC0A80000, 0x0000FFFF);
  },
  // masque générique « propre » : des 0 puis des 1 (0.0.3.255)
  contiguousWild(w) {
    return ((w & (w + 1)) >>> 0) === 0;
  },
  // 255.255.255.0 tapé à la place de 0.0.0.255
  looksLikeMask(w) {
    return w !== 0 && !IP.contiguousWild(w) && IP.contiguousWild((~w) >>> 0);
  },
  prefixOfWild(w) {
    if (!IP.contiguousWild(w)) return null;
    let c = 0;
    while (c < 32 && ((w >>> c) & 1)) c++;
    return 32 - c;
  },
};

/* Interfaces de Ro (schéma du TD) */
const IFACES = [
  { id: 'G0/0',   full: 'GigabitEthernet0/0',   ip: '172.17.0.254', prefix: 16, zone: 'dmz' },
  { id: 'G0/1.0', full: 'GigabitEthernet0/1.0', ip: '172.16.0.254', prefix: 24, zone: 'srv' },
  { id: 'G0/1.1', full: 'GigabitEthernet0/1.1', ip: '172.16.1.254', prefix: 24, zone: 'lan' },
  { id: 'G0/1.2', full: 'GigabitEthernet0/1.2', ip: '172.16.2.254', prefix: 24, zone: 'wifi' },
  { id: 'S0/0',   full: 'Serial0/0',            ip: '200.0.0.254',  prefix: 24, zone: 'inet' },
];
for (const i of IFACES) {
  i.ipn = IP.toInt(i.ip);
  i.net = (i.ipn & IP.maskOf(i.prefix)) >>> 0;
}
const IFACE_BY_ID = Object.fromEntries(IFACES.map(i => [i.id, i]));

const ZONES = {
  srv:  { name: 'Serveurs', net: '172.16.0.0/24', iface: 'G0/1.0' },
  lan:  { name: 'Filaire',  net: '172.16.1.0/24', iface: 'G0/1.1' },
  wifi: { name: 'Wifi',     net: '172.16.2.0/24', iface: 'G0/1.2' },
  dmz:  { name: 'DMZ',      net: '172.17.0.0/16', iface: 'G0/0' },
  inet: { name: 'Internet', net: '',              iface: 'S0/0' },
};

const HOSTS = [
  { id: 'ldap',   name: 'Serveur utilisateurs (LDAP)', short: 'Utilisateurs LDAP', ip: '172.16.0.250', zone: 'srv' },
  { id: 'auth',   name: "Serveur d'authentification",  short: 'Authentification',  ip: '172.16.0.251', zone: 'srv' },
  { id: 'intra',  name: 'Web intranet',                short: 'Web intranet',      ip: '172.16.0.252', zone: 'srv' },
  { id: 'proxy',  name: 'Proxy',                       short: 'Proxy',             ip: '172.16.0.253', zone: 'srv' },
  { id: 'pc1',    name: 'PC filaire 1',                short: 'PC filaire 1',      ip: '172.16.1.10',  zone: 'lan' },
  { id: 'pc2',    name: 'PC filaire 2',                short: 'PC filaire 2',      ip: '172.16.1.20',  zone: 'lan' },
  { id: 'wifi1',  name: 'PC wifi',                     short: 'PC wifi',           ip: '172.16.2.10',  zone: 'wifi' },
  { id: 'web',    name: 'Web DMZ',                     short: 'Web',               ip: '172.17.0.1',   zone: 'dmz' },
  { id: 'mail',   name: 'Mail DMZ',                    short: 'Mail',              ip: '172.17.0.2',   zone: 'dmz' },
  { id: 'dns',    name: 'DNS Internet',                short: 'DNS',               ip: '201.0.0.1',    zone: 'inet' },
  { id: 'http1',  name: 'HTTP1',                       short: 'HTTP1',             ip: '202.0.0.1',    zone: 'inet' },
  { id: 'http2',  name: 'HTTP2 (réseau social)',       short: 'HTTP2 · social',    ip: '203.0.0.1',    zone: 'inet' },
  { id: 'imail',  name: 'Mail Internet',               short: 'Mail',              ip: '204.0.0.1',    zone: 'inet' },
  { id: 'cert',   name: 'Certificats',                 short: 'Certificats',       ip: '205.0.0.1',    zone: 'inet' },
  { id: 'client', name: 'Client Internet',             short: 'Client',            ip: '90.12.34.56',  zone: 'inet' },
  { id: 'presta', name: 'Prestataire',                 short: 'Prestataire',       ip: '81.250.0.7',   zone: 'inet' },
];
for (const h of HOSTS) h.ipn = IP.toInt(h.ip);
const HOST_BY_ID = Object.fromEntries(HOSTS.map(h => [h.id, h]));
const HOST_BY_IP = Object.fromEntries(HOSTS.map(h => [h.ipn, h]));
const PUBLIC_IP = IP.toInt('200.0.0.254');
const PUB = { id: 'pub', name: 'IP publique de Ro', short: 'Ro (public)', ip: '200.0.0.254', ipn: PUBLIC_IP, zone: 'inet' };

function endpoint(id) {
  return id === 'pub' ? PUB : HOST_BY_ID[id];
}
function zoneOfIp(ip) {
  const i = IFACES.find(x => x.id !== 'S0/0' && IP.inNet(ip, x.net, x.prefix));
  return i ? i.zone : 'inet';
}

/* Noms de ports acceptés par la syntaxe Cisco (et quelques tolérances) */
const PORT_NAMES = {
  tcp: { 'ftp-data': 20, ftp: 21, ssh: 22, telnet: 23, smtp: 25, domain: 53, www: 80, http: 80, pop3: 110, ident: 113, nntp: 119, bgp: 179, https: 443 },
  udp: { domain: 53, bootps: 67, bootpc: 68, tftp: 69, ntp: 123, snmp: 161, snmptrap: 162, isakmp: 500, syslog: 514, rip: 520 },
};
// ce que IOS affiche dans show access-lists
const PORT_DISPLAY = {
  tcp: { 20: 'ftp-data', 21: 'ftp', 23: 'telnet', 25: 'smtp', 53: 'domain', 80: 'www', 110: 'pop3', 179: 'bgp' },
  udp: { 53: 'domain', 67: 'bootps', 68: 'bootpc', 69: 'tftp', 123: 'ntp', 161: 'snmp', 162: 'snmptrap', 500: 'isakmp', 514: 'syslog', 520: 'rip' },
};

const SERVICES = [
  { id: 'http',    label: 'HTTP',          proto: 'tcp',  port: 80 },
  { id: 'https',   label: 'HTTPS',         proto: 'tcp',  port: 443 },
  { id: 'dns',     label: 'DNS',           proto: 'udp',  port: 53 },
  { id: 'ping',    label: 'Ping',          proto: 'icmp', port: null },
  { id: 'ssh',     label: 'SSH',           proto: 'tcp',  port: 22 },
  { id: 'ssh2222', label: 'SSH redirigé',  proto: 'tcp',  port: 2222 },
  { id: 'telnet',  label: 'Telnet',        proto: 'tcp',  port: 23 },
  { id: 'ftp',     label: 'FTP',           proto: 'tcp',  port: 21 },
  { id: 'smtp',    label: 'SMTP',          proto: 'tcp',  port: 25 },
  { id: 'smtps',   label: 'SMTPs',         proto: 'tcp',  port: 465 },
  { id: 'pop3',    label: 'POP3',          proto: 'tcp',  port: 110 },
  { id: 'pops',    label: 'POPs',          proto: 'tcp',  port: 995 },
  { id: 'imap',    label: 'IMAP',          proto: 'tcp',  port: 143 },
  { id: 'imaps',   label: 'IMAPs',         proto: 'tcp',  port: 993 },
  { id: 'ldap',    label: 'LDAP',          proto: 'tcp',  port: 389 },
  { id: 'ldaps',   label: 'LDAPs',         proto: 'tcp',  port: 636 },
  { id: 'radius',  label: 'RADIUS',        proto: 'udp',  port: 1812 },
  { id: 'kerberos',label: 'Kerberos',      proto: 'udp',  port: 88 },
  { id: 'ntp',     label: 'NTP',           proto: 'udp',  port: 123 },
  { id: 'snmp',    label: 'SNMP',          proto: 'udp',  port: 161 },
  { id: 'smb',     label: 'SMB',           proto: 'tcp',  port: 445 },
  { id: 'mysql',   label: 'MySQL',         proto: 'tcp',  port: 3306 },
  { id: 'rdp',     label: 'RDP',           proto: 'tcp',  port: 3389 },
  { id: 'proxy',   label: 'Proxy web',     proto: 'tcp',  port: 8080 },
];
const SERVICE_BY_ID = Object.fromEntries(SERVICES.map(s => [s.id, s]));

function serviceLabel(proto, port) {
  if (proto === 'icmp') return 'Ping (icmp)';
  const s = SERVICES.find(x => x.proto === proto && x.port === port);
  return s ? `${s.label} (${proto}/${port})` : `${proto}/${port}`;
}

/* Dates : les tests utilisent la semaine du lundi 12 octobre 2026 */
const DAYS_FR = ['dimanche', 'lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi'];
const MONTHS_FR = ['janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'];
const WEEK_KEYS = ['lun', 'mar', 'mer', 'jeu', 'ven', 'sam', 'dim'];

function parseWhen(w) {
  const s = w || 'mar 10:00';
  let m = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{1,2}):(\d{2})$/.exec(s);
  if (m) return new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]);
  m = /^(lun|mar|mer|jeu|ven|sam|dim) (\d{1,2}):(\d{2})$/.exec(s);
  if (!m) return new Date(2026, 9, 13, 10, 0);
  return new Date(2026, 9, 12 + WEEK_KEYS.indexOf(m[1]), +m[2], +m[3]);
}
const pad2 = n => String(n).padStart(2, '0');
function hhmm(d) {
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
}
function fmtWhen(d) {
  return `${DAYS_FR[d.getDay()]} ${d.getDate()} ${MONTHS_FR[d.getMonth()]} ${d.getFullYear()}, ${hhmm(d)}`;
}
// « mardi 12:30 » dans la semaine de référence, date complète sinon
function fmtWhenShort(d) {
  const ref = d.getFullYear() === 2026 && d.getMonth() === 9 && d.getDate() >= 12 && d.getDate() <= 18;
  return ref ? `${DAYS_FR[d.getDay()]} ${hhmm(d)}` : `${DAYS_FR[d.getDay()]} ${d.getDate()} ${MONTHS_SHORT_FR[d.getMonth()]} ${d.getFullYear()}, ${hhmm(d)}`;
}
const MONTHS_SHORT_FR = ['janv.', 'févr.', 'mars', 'avr.', 'mai', 'juin', 'juil.', 'août', 'sept.', 'oct.', 'nov.', 'déc.'];
