'use strict';
/* app.js : interface — terminal, topologie animée, testeur de paquets, missions, progression */

const $ = s => document.querySelector(s);
const SVGNS = 'http://www.w3.org/2000/svg';

const store = {
  get(k, d) {
    try { const v = localStorage.getItem('acltrain.' + k); return v == null ? d : JSON.parse(v); } catch (e) { return d; }
  },
  set(k, v) {
    try { localStorage.setItem('acltrain.' + k, JSON.stringify(v)); } catch (e) { /* stockage indisponible */ }
  },
  del(k) {
    try { localStorage.removeItem('acltrain.' + k); } catch (e) { /* idem */ }
  },
};
const reduceMotion = () => window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

const App = {
  view: 'missions',
  ctxs: {},
  ctx: null,
  missionId: store.get('mission', 'm1'),
  progress: store.get('progress', {}),   // id → { stars, done }
  mstate: {},                            // id → { hints, solution, attempts, results, cons, stale, armSol }
  sandboxBase: store.get('sandboxBase', 'td'),
  when: parseWhen('mar 10:00'),
  pickStep: 0,
};
if (!MISSION_BY_ID[App.missionId]) App.missionId = 'm1';

/* =================== contextes (une console par mission + bac à sable) =================== */
function baseFor(id) {
  if (id === 'sandbox') return App.sandboxBase === 'td' ? BASE_TD : [];
  return MISSION_BY_ID[id].base;
}
function getCtx(id) {
  if (!App.ctxs[id]) {
    const ctx = { id, router: null, cmds: [], log: [], hist: [], histPos: null, draft: '' };
    App.ctxs[id] = ctx;
    buildCtx(ctx, store.get('cmds.' + id, []));
  }
  return App.ctxs[id];
}
function buildCtx(ctx, cmds) {
  ctx.router = new Router();
  ctx.router.runSilently(['configure terminal', ...baseFor(ctx.id), 'end']);
  ctx.router.clock = App.when;
  ctx.log = [];
  ctx.cmds = [];
  ctx.hist = [];
  const title = ctx.id === 'sandbox' ? 'Bac à sable' : `Mission ${MISSIONS.indexOf(MISSION_BY_ID[ctx.id]) + 1} · ${MISSION_BY_ID[ctx.id].title}`;
  ctx.log.push({ t: `Console de Ro — ${title}`, cls: 'dim' });
  ctx.log.push({ t: 'Tape ? pour l\'aide, Tab pour compléter, ↑ ↓ pour l\'historique.', cls: 'dim' });
  ctx.log.push({ t: 'Pour commencer : configure terminal (ou conf t). La ligne jaune sous la saisie rappelle la syntaxe attendue.', cls: 'dim' });
  ctx.log.push({ t: '', cls: 'dim' });
  for (const l of cmds) runCmd(ctx, l, true);
}
function runCmd(ctx, line, replay) {
  const prompt = ctx.router.prompt();
  ctx.log.push({ t: prompt + line, cls: 'cmd' });
  const r = ctx.router.exec(line);
  if (r.caret != null) ctx.log.push({ t: ' '.repeat(prompt.length + r.caret) + '^', cls: 'caret' });
  for (const l of r.lines) ctx.log.push(l);
  if (!r.help) ctx.cmds.push(line);
  if (line.trim()) ctx.hist.push(line);
  if (ctx.log.length > 800) ctx.log.splice(3, ctx.log.length - 700);
  if (!replay) store.set('cmds.' + ctx.id, ctx.cmds);
  return r;
}

/* =================== terminal =================== */
const term = {
  out: null, input: null, prompt: null, hint: null, rendered: 0,
  init() {
    this.out = $('#term-out');
    this.input = $('#term-input');
    this.prompt = $('#term-prompt');
    this.hint = $('#term-hint');
    this.input.addEventListener('keydown', e => this.key(e));
    this.input.addEventListener('input', () => this.updateHint());
    $('#console').addEventListener('click', e => {
      if (!window.getSelection().toString() && !e.target.closest('button')) this.input.focus();
    });
    $('#term-tab').addEventListener('click', () => { this.complete(); this.input.focus(); });
    const chips = [['show access-lists', 'show access-lists'], ['show run', 'show running-config'], ['show ip int brief', 'show ip interface brief'], ['show time-range', 'show time-range'], ['show ip nat', 'show ip nat translations']];
    $('#term-chips').innerHTML = chips.map(([l, c]) => `<button type="button" class="chip" data-cmd="${c}">${l}</button>`).join('')
      + '<button type="button" class="chip ghost" data-clear="1">Effacer l\'écran</button>';
    $('#term-chips').addEventListener('click', e => {
      const b = e.target.closest('button');
      if (!b) return;
      if (b.dataset.clear) { App.ctx.log = []; this.render(); return; }
      const ctx = App.ctx;
      const m = ctx.router.mode;
      this.submit((m === 'user' || m === 'priv') ? b.dataset.cmd : 'do ' + b.dataset.cmd);
    });
  },
  render() {
    const ctx = App.ctx;
    this.out.innerHTML = '';
    this.rendered = 0;
    this.append();
    this.syncPrompt();
  },
  append() {
    const ctx = App.ctx;
    const frag = document.createDocumentFragment();
    if (this.rendered > ctx.log.length) { this.out.innerHTML = ''; this.rendered = 0; }
    for (let k = this.rendered; k < ctx.log.length; k++) {
      const l = ctx.log[k];
      const d = document.createElement('div');
      d.className = 'tl ' + l.cls;
      d.textContent = l.t || ' ';
      frag.appendChild(d);
    }
    this.rendered = ctx.log.length;
    this.out.appendChild(frag);
    this.out.scrollTop = this.out.scrollHeight;
  },
  syncPrompt() {
    const r = App.ctx.router;
    this.prompt.textContent = r.prompt();
    $('#console-mode').textContent = r.modeLabel();
    this.updateHint();
  },
  updateHint() {
    const h = App.ctx.router.hint(this.input.value);
    this.hint.innerHTML = `<span class="syn">${esc(h.syntax)}</span>${h.info ? `<span class="inf">${esc(h.info)}</span>` : ''}`;
  },
  submit(line) {
    const ctx = App.ctx;
    runCmd(ctx, line, false);
    ctx.histPos = null;
    this.input.value = '';
    this.append();
    this.syncPrompt();
    afterConfigChange();
  },
  key(e) {
    const ctx = App.ctx;
    if (e.key === 'Enter') {
      e.preventDefault();
      this.submit(this.input.value);
    } else if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
      e.preventDefault();
      if (!ctx.hist.length) return;
      if (ctx.histPos == null) { ctx.histPos = ctx.hist.length; ctx.draft = this.input.value; }
      ctx.histPos += e.key === 'ArrowUp' ? -1 : 1;
      ctx.histPos = Math.max(0, Math.min(ctx.hist.length, ctx.histPos));
      this.input.value = ctx.histPos === ctx.hist.length ? ctx.draft : ctx.hist[ctx.histPos];
      this.updateHint();
    } else if (e.key === 'Tab') {
      e.preventDefault();
      this.complete();
    } else if (e.key === '?') {
      e.preventDefault();
      const v = this.input.value;
      const prompt = ctx.router.prompt();
      ctx.log.push({ t: prompt + v + '?', cls: 'cmd' });
      for (const l of ctx.router.exec(v + '?').lines) ctx.log.push(l);
      this.append();
    } else if ((e.key === 'z' || e.key === 'Z') && e.ctrlKey) {
      e.preventDefault();
      this.submit('end');
    } else if ((e.key === 'l' || e.key === 'L') && e.ctrlKey) {
      e.preventDefault();
      ctx.log = [];
      this.render();
    }
  },
  complete() {
    const ctx = App.ctx;
    const r = ctx.router.complete(this.input.value);
    this.input.value = r.value;
    if (r.options.length > 1) {
      ctx.log.push({ t: ctx.router.prompt() + this.input.value, cls: 'cmd' });
      ctx.log.push({ t: r.options.join('   '), cls: 'help' });
      this.append();
    }
    this.updateHint();
  },
  // tape une liste de commandes avec un petit effet machine à écrire
  typeLines(lines) {
    const ctx = App.ctx;
    const seq = [...lines];
    if (!['priv', 'user'].includes(ctx.router.mode)) seq.unshift('end');
    if (ctx.router.mode === 'user') seq.unshift('enable');
    let k = 0;
    const step = () => {
      if (App.ctx !== ctx || k >= seq.length) return;
      this.submit(seq[k++]);
      setTimeout(step, reduceMotion() ? 0 : 110);
    };
    step();
  },
};

/* =================== topologie =================== */
const TP = {
  router: { x: 470, y: 262 },
  zones: {
    srv:  { x: 16,  y: 16,  w: 300, h: 140, anchor: { x: 316, y: 104 }, label: 'Serveurs · 172.16.0.0/24' },
    lan:  { x: 16,  y: 176, w: 300, h: 92,  anchor: { x: 316, y: 222 }, label: 'Filaire · 172.16.1.0/24' },
    wifi: { x: 16,  y: 288, w: 300, h: 92,  anchor: { x: 316, y: 334 }, label: 'Wifi · 172.16.2.0/24' },
    dmz:  { x: 352, y: 16,  w: 244, h: 104, anchor: { x: 470, y: 120 }, label: 'DMZ · 172.17.0.0/16' },
    inet: { x: 624, y: 16,  w: 160, h: 428, anchor: { x: 624, y: 262 }, label: 'Internet' },
  },
  labels: {
    'G0/1.0': { x: 326, y: 150 },
    'G0/1.1': { x: 326, y: 238 },
    'G0/1.2': { x: 326, y: 302 },
    'G0/0':   { x: 482, y: 140 },
    'S0/0':   { x: 506, y: 286 },
  },
  hostPos: {},
};
(function layoutHosts() {
  const put = (id, x, y, w, h) => { TP.hostPos[id] = { x, y, w, h }; };
  put('ldap', 28, 46, 136, 44); put('auth', 170, 46, 136, 44); put('intra', 28, 100, 136, 44); put('proxy', 170, 100, 136, 44);
  put('pc1', 28, 208, 136, 44); put('pc2', 170, 208, 136, 44);
  put('wifi1', 28, 320, 136, 44);
  put('web', 364, 46, 108, 44); put('mail', 478, 46, 108, 44);
  ['dns', 'http1', 'http2', 'imail', 'cert', 'client', 'presta'].forEach((id, k) => put(id, 636, 46 + k * 56, 136, 44));
})();
function ifPoint(id) {
  const z = TP.zones[IFACE_BY_ID[id].zone];
  const r = TP.router, a = z.anchor;
  return { x: a.x + (r.x - a.x) * 0.55, y: a.y + (r.y - a.y) * 0.55 };
}
function hostCenter(id) {
  const p = TP.hostPos[id];
  return { x: p.x + p.w / 2, y: p.y + p.h / 2 };
}

function svgEl(tag, attrs, text) {
  const el = document.createElementNS(SVGNS, tag);
  for (const k in attrs) el.setAttribute(k, attrs[k]);
  if (text != null) el.textContent = text;
  return el;
}

const topo = {
  svg: null, badges: null, anim: null, sel: { src: null, dst: null },
  init() {
    this.svg = $('#topo');
    const g = svgEl('g', { class: 'static' });
    for (const [zid, z] of Object.entries(TP.zones)) {
      g.appendChild(svgEl('line', { x1: z.anchor.x, y1: z.anchor.y, x2: TP.router.x, y2: TP.router.y, class: `link z-${zid}` }));
    }
    for (const [zid, z] of Object.entries(TP.zones)) {
      g.appendChild(svgEl('rect', { x: z.x, y: z.y, width: z.w, height: z.h, rx: 10, class: `zone z-${zid}` }));
      g.appendChild(svgEl('text', { x: z.x + 12, y: z.y + 20, class: `zone-label z-${zid}` }, z.label));
    }
    // routeur
    const r = TP.router;
    g.appendChild(svgEl('circle', { cx: r.x, cy: r.y, r: 30, class: 'router' }));
    g.appendChild(svgEl('path', { d: `M${r.x - 14} ${r.y - 6}h22l-6 -6M${r.x + 14} ${r.y + 6}h-22l6 6`, class: 'router-glyph' }));
    g.appendChild(svgEl('text', { x: r.x, y: r.y + 48, class: 'router-label', 'text-anchor': 'middle' }, 'Ro'));
    // AP wifi
    g.appendChild(svgEl('path', { d: 'M196 330 a14 14 0 0 1 20 0 M200 336 a8 8 0 0 1 12 0', class: 'ap' }));
    g.appendChild(svgEl('text', { x: 222, y: 342, class: 'ap-label' }, 'AP'));
    // machines
    for (const h of HOSTS) {
      const p = TP.hostPos[h.id];
      const hg = svgEl('g', { class: 'host', 'data-host': h.id, tabindex: 0, role: 'button', 'aria-label': `${h.name}, ${h.ip}` });
      hg.appendChild(svgEl('rect', { x: p.x, y: p.y, width: p.w, height: p.h, rx: 6 }));
      hg.appendChild(svgEl('text', { x: p.x + 9, y: p.y + 18, class: 'host-name' }, h.short));
      hg.appendChild(svgEl('text', { x: p.x + 9, y: p.y + 34, class: 'host-ip' }, h.ip));
      g.appendChild(hg);
    }
    this.svg.appendChild(g);
    this.badges = svgEl('g', { class: 'badges' });
    this.svg.appendChild(this.badges);
    this.anim = svgEl('g', { class: 'anim' });
    this.svg.appendChild(this.anim);
    this.svg.addEventListener('click', e => {
      const h = e.target.closest('.host');
      if (h) this.pick(h.dataset.host);
    });
    this.svg.addEventListener('keydown', e => {
      const h = e.target.closest && e.target.closest('.host');
      if (h && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); this.pick(h.dataset.host); }
    });
  },
  pick(id) {
    if (App.pickStep === 0) {
      $('#t-src').value = id;
      App.pickStep = 1;
      $('#topo-help').textContent = `Source : ${HOST_BY_ID[id].name}. Clique maintenant la destination.`;
    } else {
      $('#t-dst').value = id;
      App.pickStep = 0;
      $('#topo-help').textContent = 'Paquet prêt : choisis le service puis « Envoyer le paquet ».';
    }
    this.highlight();
  },
  highlight() {
    const s = $('#t-src').value, d = $('#t-dst').value;
    this.svg.querySelectorAll('.host').forEach(h => {
      h.classList.toggle('is-src', h.dataset.host === s);
      h.classList.toggle('is-dst', h.dataset.host === d);
    });
  },
  drawBadges(cfg) {
    this.badges.innerHTML = '';
    for (const i of IFACES) {
      const f = cfg.ifaces[i.id];
      const pos = TP.labels[i.id];
      const lines = [{ t: `${i.id}  .${i.ip.split('.')[3]}`, c: 'b-id' }];
      if (f.in) lines.push({ t: `in  ${f.in}`, c: cfg.acls[f.in] ? 'b-acl' : 'b-miss' });
      if (f.out) lines.push({ t: `out ${f.out}`, c: cfg.acls[f.out] ? 'b-acl' : 'b-miss' });
      if (f.nat) lines.push({ t: `nat ${f.nat}`, c: 'b-nat' });
      if (f.inspectIn) lines.push({ t: `insp in  ${f.inspectIn}`, c: 'b-insp' });
      if (f.inspectOut) lines.push({ t: `insp out ${f.inspectOut}`, c: 'b-insp' });
      const w = Math.max(...lines.map(l => l.t.length)) * 6.3 + 14;
      const h = lines.length * 13 + 8;
      const g = svgEl('g', { class: 'badge' });
      g.appendChild(svgEl('rect', { x: pos.x, y: pos.y, width: w, height: h, rx: 5 }));
      lines.forEach((l, k) => g.appendChild(svgEl('text', { x: pos.x + 7, y: pos.y + 15 + k * 13, class: l.c }, l.t)));
      this.badges.appendChild(g);
    }
  },
  points(hops) {
    const pts = [];
    const hostPt = (ip, first) => {
      const h = HOST_BY_IP[ip];
      const own = ownerIface(ip);
      const zone = TP.zones[zoneOfIp(ip)];
      if (own) return first ? [TP.router] : [TP.router];
      if (!h) return first ? [zone.anchor] : [zone.anchor];
      return first ? [hostCenter(h.id), zone.anchor] : [zone.anchor, hostCenter(h.id)];
    };
    hops.forEach((h, k) => {
      if (h.k === 'host') pts.push(...hostPt(h.ip, k === 0));
      else if (h.k === 'if') pts.push(ifPoint(h.id));
      else pts.push(TP.router);
    });
    return pts.filter((p, k) => k === 0 || p.x !== pts[k - 1].x || p.y !== pts[k - 1].y);
  },
  run(R, Q) {
    this.anim.innerHTML = '';
    const token = (this.token = {});
    const go = (res, cls, done) => {
      const pts = this.points(res.hops);
      if (pts.length < 2) { pts.push(pts[0]); }
      const poly = svgEl('polyline', { class: `trail ${cls}`, points: '' });
      const dot = svgEl('circle', { r: 7, class: `pkt ${cls}`, cx: pts[0].x, cy: pts[0].y });
      this.anim.appendChild(poly);
      this.anim.appendChild(dot);
      const seg = [];
      let total = 0;
      for (let k = 1; k < pts.length; k++) { const d = Math.hypot(pts[k].x - pts[k - 1].x, pts[k].y - pts[k - 1].y); seg.push(d); total += d; }
      const blocked = !res.delivered;
      const finish = () => {
        const end = pts[pts.length - 1];
        if (blocked) {
          this.anim.appendChild(svgEl('circle', { cx: end.x, cy: end.y, r: 13, class: 'stop-ring' }));
          this.anim.appendChild(svgEl('path', { d: `M${end.x - 6} ${end.y - 6}l12 12M${end.x + 6} ${end.y - 6}l-12 12`, class: 'stop-x' }));
          dot.remove();
        } else {
          dot.classList.add('arrived');
        }
        done && done();
      };
      const place = dist => {
        let rem = dist;
        const out = [pts[0]];
        for (let k = 0; k < seg.length; k++) {
          if (rem >= seg[k]) { out.push(pts[k + 1]); rem -= seg[k]; continue; }
          const t = seg[k] ? rem / seg[k] : 0;
          out.push({ x: pts[k].x + (pts[k + 1].x - pts[k].x) * t, y: pts[k].y + (pts[k + 1].y - pts[k].y) * t });
          break;
        }
        poly.setAttribute('points', out.map(p => `${p.x},${p.y}`).join(' '));
        const last = out[out.length - 1];
        dot.setAttribute('cx', last.x);
        dot.setAttribute('cy', last.y);
      };
      if (reduceMotion() || total === 0) { place(total); finish(); return; }
      const speed = 420;
      const t0 = performance.now();
      const frame = now => {
        if (this.token !== token) return;
        const d = Math.min(total, ((now - t0) / 1000) * speed);
        place(d);
        if (d < total) requestAnimationFrame(frame); else finish();
      };
      requestAnimationFrame(frame);
    };
    go(R, 'req', () => { if (Q) setTimeout(() => { if (this.token === token) go(Q, 'rep'); }, reduceMotion() ? 0 : 250); });
  },
};

/* =================== testeur de paquets =================== */
const tester = {
  init() {
    const opt = (h) => `<option value="${h.id}">${esc(h.name)} — ${h.ip}</option>`;
    const groups = ['lan', 'wifi', 'srv', 'dmz', 'inet'];
    const grouped = extra => groups.map(z => `<optgroup label="${ZONES[z].name}">${HOSTS.filter(h => h.zone === z).map(opt).join('')}${z === 'inet' && extra ? opt(PUB) : ''}</optgroup>`).join('');
    $('#t-src').innerHTML = grouped(false);
    $('#t-dst').innerHTML = grouped(true);
    $('#t-src').value = 'pc1';
    $('#t-dst').value = 'http1';
    $('#t-svc').innerHTML = SERVICES.map(s => `<option value="${s.id}">${esc(serviceLabel(s.proto, s.port))}</option>`).join('')
      + '<option value="custom-tcp">TCP, autre port…</option><option value="custom-udp">UDP, autre port…</option>';
    $('#t-svc').value = 'https';
    $('#t-svc').addEventListener('change', () => { $('#t-port-field').hidden = !$('#t-svc').value.startsWith('custom'); });
    $('#t-src').addEventListener('change', () => topo.highlight());
    $('#t-dst').addEventListener('change', () => topo.highlight());
    const w = $('#t-when');
    w.value = this.toLocal(App.when);
    w.addEventListener('change', () => this.setWhen(this.fromLocal(w.value)));
    $('#t-presets').addEventListener('click', e => {
      const b = e.target.closest('button');
      if (b) this.setWhen(parseWhen(b.dataset.when));
    });
    $('#tester').addEventListener('submit', e => { e.preventDefault(); this.send(); });
    this.showDay();
    topo.highlight();
  },
  toLocal(d) { return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}T${hhmm(d)}`; },
  fromLocal(v) { const d = parseWhen(v.replace('T', ' ')); return isNaN(d) ? App.when : d; },
  setWhen(d) {
    App.when = d;
    $('#t-when').value = this.toLocal(d);
    for (const c of Object.values(App.ctxs)) c.router.clock = d;
    this.showDay();
  },
  showDay() { $('#t-when-day').textContent = DAYS_FR[App.when.getDay()]; },
  spec() {
    const s = $('#t-svc').value;
    let proto, port;
    if (s.startsWith('custom')) { proto = s.slice(7); port = Math.max(1, Math.min(65535, +$('#t-port').value || 1)); } else ({ proto, port } = SERVICE_BY_ID[s]);
    return { src: endpoint($('#t-src').value).ipn, dst: endpoint($('#t-dst').value).ipn, proto, dport: port };
  },
  send() {
    const cfg = App.ctx.router.cfg;
    const spec = this.spec();
    if (spec.src === spec.dst) { trace.message('Choisis une destination différente de la source.'); return; }
    const R = sendRequest(cfg, spec, App.when, true);
    const Q = sendReply(cfg, R, App.when, true);
    trace.show(R, Q, { from: endpoint($('#t-src').value).name, to: endpoint($('#t-dst').value).name, svc: serviceLabel(spec.proto, spec.dport), when: App.when });
    topo.run(R, Q);
  },
  load(t) {
    $('#t-src').value = t.from;
    $('#t-dst').value = t.to;
    $('#t-svc').value = t.svc;
    $('#t-port-field').hidden = true;
    this.setWhen(parseWhen(t.when));
    topo.highlight();
  },
};

/* =================== trace =================== */
const STEP_ICON = { emit: '›', acl: '', pass: '·', nat: '⇄', route: '→', inspect: '◎', deliver: '●', drop: '✕', warn: '!', info: 'i' };
const trace = {
  message(t) { $('#trace').innerHTML = `<p class="muted">${esc(t)}</p>`; },
  stepHtml(s) {
    let icon = STEP_ICON[s.type];
    if (s.type === 'acl') icon = s.ok ? '✓' : '✕';
    const st = s.ok === true ? 'ok' : s.ok === false ? 'ko' : 'neutral';
    return `<li class="step ${s.type} ${st}"><span class="sic">${icon}</span><span>${esc(s.text)}</span></li>`;
  },
  show(R, Q, meta) {
    const verdict = R.delivered ? (Q && !Q.delivered ? 'half' : 'ok') : 'ko';
    const vtext = !R.delivered ? 'Bloqué' : Q && !Q.delivered ? 'Arrivé, mais la réponse est bloquée' : 'Arrivé, réponse reçue';
    let html = `<div class="trace-head ${verdict}"><span class="tv">${vtext}</span><span class="tm">${esc(meta.from)} → ${esc(meta.to)} · ${esc(meta.svc)} · ${esc(fmtWhenShort(meta.when))}</span></div>`;
    html += `<p class="trace-sub">Aller</p><ol class="steps">${R.steps.map(s => this.stepHtml(s)).join('')}</ol>`;
    if (Q) html += `<p class="trace-sub">Retour</p><ol class="steps">${Q.steps.map(s => this.stepHtml(s)).join('')}</ol>`;
    $('#trace').innerHTML = html;
  },
};

/* =================== missions =================== */
function mstate(id) {
  return App.mstate[id] || (App.mstate[id] = Object.assign({ hints: 0, solution: false, attempts: 0, results: null, cons: null, stale: false, armSol: false, armReset: false }, store.get('ms.' + id, {})));
}
function saveMstate(id) {
  const s = mstate(id);
  store.set('ms.' + id, { hints: s.hints, solution: s.solution, attempts: s.attempts });
}
function curMission() { return MISSION_BY_ID[App.missionId]; }

function renderMap() {
  let n = 0;
  $('#mission-map').innerHTML = CHAPTERS.map(ch => {
    const ms = MISSIONS.filter(m => m.chapter === ch.id);
    return `<div class="chap"><span class="chap-name">${ch.name}</span><div class="pills">${ms.map(m => {
      n++;
      const p = App.progress[m.id];
      const stars = p ? p.stars : 0;
      const cls = ['pill', m.id === App.missionId ? 'cur' : '', p && p.done ? 'done' : ''].join(' ');
      return `<button type="button" class="${cls}" data-m="${m.id}" title="${esc(m.title)}${p && p.done ? ` · ${stars}/3 étoiles` : ''}"><span class="pn">${n}</span>${p && p.done ? `<span class="ps">${'★'.repeat(stars)}${'☆'.repeat(3 - stars)}</span>` : ''}</button>`;
    }).join('')}</div></div>`;
  }).join('');
  const total = MISSIONS.reduce((a, m) => a + ((App.progress[m.id] && App.progress[m.id].stars) || 0), 0);
  $('#stars-total').innerHTML = `<span class="st-ic">★</span> ${total} / ${MISSIONS.length * 3}`;
}

function renderMission() {
  const m = curMission();
  const st = mstate(m.id);
  const idx = MISSIONS.indexOf(m);
  const ch = CHAPTERS.find(c => c.id === m.chapter);
  const res = st.results;
  const okCount = res ? res.filter(r => r.ok).length : 0;
  const testsHtml = m.tests.map((t, k) => {
    const L = testLabel(t);
    const r = res && res[k];
    const stc = r ? (r.ok ? 'ok' : 'ko') : 'todo';
    const icon = r ? (r.ok ? '✓' : '✕') : (k + 1);
    const when = t.when !== 'mar 10:00' ? `<span class="tw">${esc(fmtWhenShort(parseWhen(t.when)))}</span>` : '';
    return `<li class="test ${stc}${st.stale && r ? ' stale' : ''}">
      <span class="tstat">${icon}</span>
      <div class="tbody">
        <div class="tlabel">${esc(L.from)} → ${esc(L.to)}</div>
        <div class="tmeta"><span class="tsvc">${esc(L.svc)}</span>${when}<span class="exp ${t.expect}">${t.expect === 'pass' ? 'doit passer' : 'doit être bloqué'}</span>${t.at ? `<span class="exp at">arrive sur ${esc(HOST_BY_ID[t.at].short)}</span>` : ''}${t.reply ? '<span class="exp reply">réponse doit revenir</span>' : ''}</div>
        ${r && !r.ok && r.why ? `<div class="treason">${esc(r.why)}</div>` : ''}
      </div>
      <button type="button" class="tplay" data-play="${k}" aria-label="Rejouer ce flux dans le testeur" title="Rejouer ce flux">▶</button>
    </li>`;
  }).join('');
  const consHtml = m.constraints.length ? `<div class="cons">${m.constraints.map((c, k) => {
    const v = st.cons && st.cons[k];
    return `<span class="con ${v == null ? '' : v ? 'ok' : 'ko'}">${v == null ? '◇' : v ? '✓' : '✕'} ${esc(c.text)}</span>`;
  }).join('')}</div>` : '';
  const hintsHtml = m.hints.slice(0, st.hints).map((h, k) => `<li><span class="hn">Indice ${k + 1}</span>${esc(h)}</li>`).join('');
  const solHtml = st.solution ? `<div class="solution"><div class="sol-head"><span>Solution possible</span><button type="button" class="btn small" data-act="type-sol">Taper dans la console</button></div><pre>${esc(m.solution.join('\n'))}</pre></div>` : '';
  const prog = App.progress[m.id];
  const verdict = res
    ? (okCount === m.tests.length && (!st.cons || st.cons.every(Boolean))
      ? `<div class="verdict ok">Tous les flux sont corrects. Mission réussie.</div>`
      : `<div class="verdict ko">${okCount} flux sur ${m.tests.length} corrects${st.cons && !st.cons.every(Boolean) ? ', contrainte non respectée' : ''}. Clique ▶ sur un flux en échec pour voir où il coince.</div>`)
    : '';
  $('#mission-card').innerHTML = `
    <p class="eyebrow">Mission ${idx + 1} · ${esc(ch.name)}${prog && prog.done ? ` · <span class="got">${'★'.repeat(prog.stars)}${'☆'.repeat(3 - prog.stars)}</span>` : ''}</p>
    <h1>${esc(m.title)}</h1>
    <div class="brief">${m.brief}</div>
    <ul class="objectives">${m.objectives.map(o => `<li>${esc(o)}</li>`).join('')}</ul>
    ${consHtml}
    <p class="base-note">${esc(m.baseNote)}</p>
    ${hintsHtml ? `<ol class="hints">${hintsHtml}</ol>` : ''}
    ${solHtml}
    <div class="m-actions">
      <button type="button" class="btn" data-act="hint" ${st.hints >= m.hints.length ? 'disabled' : ''}>${st.hints >= m.hints.length ? 'Plus d\'indice' : `Indice ${st.hints + 1}/${m.hints.length}`}<span class="cost">−1 ★</span></button>
      <button type="button" class="btn ${st.armSol ? 'danger' : ''}" data-act="sol" ${st.solution ? 'disabled' : ''}>${st.solution ? 'Solution affichée' : st.armSol ? 'Confirmer : 0 étoile' : 'Voir la solution'}</button>
      <button type="button" class="btn ${st.armReset ? 'danger' : ''}" data-act="reset">${st.armReset ? 'Confirmer la remise à zéro' : 'Recommencer'}</button>
    </div>
    <h2 class="tests-title">Flux vérifiés <span>${m.tests.length}</span></h2>
    <ol class="tests">${testsHtml}</ol>
    <button type="button" class="btn primary big" data-act="verify">Vérifier ma configuration</button>
    ${verdict}
    <div class="m-nav">
      <button type="button" class="btn ghost" data-act="prev" ${idx === 0 ? 'disabled' : ''}>← Précédente</button>
      <button type="button" class="btn ghost" data-act="next" ${idx === MISSIONS.length - 1 ? 'disabled' : ''}>Suivante →</button>
    </div>`;
  renderMap();
}

function selectMission(id) {
  App.missionId = id;
  store.set('mission', id);
  App.ctx = getCtx(id);
  App.ctx.router.clock = App.when;
  term.render();
  topo.drawBadges(App.ctx.router.cfg);
  topo.anim.innerHTML = '';
  trace.message('Envoie un paquet pour voir son trajet : ACL rencontrées, NAT, verdict.');
  renderMission();
}

function verifyMission() {
  const m = curMission();
  const st = mstate(m.id);
  const cfg = App.ctx.router.cfg;
  st.attempts++;
  st.results = m.tests.map(t => runTest(cfg, t));
  st.cons = m.constraints.map(c => !!c.check(cfg));
  st.stale = false;
  saveMstate(m.id);
  const allOk = st.results.every(r => r.ok) && st.cons.every(Boolean);
  if (allOk) {
    const stars = st.solution ? 0 : Math.max(1, 3 - st.hints);
    const prev = App.progress[m.id];
    App.progress[m.id] = { done: true, stars: Math.max(stars, prev ? prev.stars : 0) };
    store.set('progress', App.progress);
    renderMission();
    success(m, stars);
  } else {
    renderMission();
    const firstKo = st.results.findIndex(r => !r.ok);
    if (firstKo >= 0) {
      const r = st.results[firstKo];
      tester.load(m.tests[firstKo]);
      trace.show(r.R, r.Q || (r.R.delivered ? sendReply(cfg, r.R, r.date, false) : null), { ...testLabel(m.tests[firstKo]), when: r.date });
      topo.run(r.R, r.Q);
    }
  }
}

function playTest(k) {
  const m = curMission();
  const t = m.tests[k];
  tester.load(t);
  const cfg = App.ctx.router.cfg;
  const date = parseWhen(t.when);
  const R = sendRequest(cfg, testSpec(t), date, true);
  const Q = sendReply(cfg, R, date, true);
  trace.show(R, Q, { ...testLabel(t), when: date });
  topo.run(R, Q);
  if (window.innerWidth < 1100) $('#lab').scrollIntoView({ behavior: reduceMotion() ? 'auto' : 'smooth', block: 'start' });
}

function success(m, stars) {
  const idx = MISSIONS.indexOf(m);
  const next = MISSIONS[idx + 1];
  $('#modal-body').innerHTML = `
    <p class="eyebrow">Mission ${idx + 1} réussie</p>
    <div class="modal-stars" aria-label="${stars} étoiles sur 3">${[0, 1, 2].map(k => `<span class="${k < stars ? 'on' : ''}" style="--d:${k * 120}ms">★</span>`).join('')}</div>
    <h2>${esc(m.title)}</h2>
    <p class="learn"><b>À retenir.</b> ${esc(m.learn)}</p>
    ${stars === 0 ? '<p class="muted">Solution consultée : mission validée sans étoile. Recommence-la plus tard pour gagner les étoiles.</p>' : stars < 3 ? '<p class="muted">Recommence sans indice pour décrocher les 3 étoiles.</p>' : ''}
    <div class="modal-actions">
      ${next ? `<button type="button" class="btn primary" data-modal="next">Mission suivante : ${esc(next.title)}</button>` : '<button type="button" class="btn primary" data-modal="quiz">Parcours terminé. Un quiz ?</button>'}
      <button type="button" class="btn" data-modal="close">Rester ici</button>
    </div>`;
  $('#modal').hidden = false;
  $('#modal').querySelector('[data-modal]').focus();
  if (stars > 0) confetti();
}

function resetMission(id) {
  store.del('cmds.' + id);
  store.del('ms.' + id);
  delete App.mstate[id];
  delete App.ctxs[id];
  if (id === 'sandbox') { App.ctx = getCtx('sandbox'); term.render(); topo.drawBadges(App.ctx.router.cfg); renderSandbox(); return; }
  selectMission(id);
}

function afterConfigChange() {
  topo.drawBadges(App.ctx.router.cfg);
  if (App.view === 'missions') {
    const st = mstate(App.missionId);
    if (st.results && !st.stale) { st.stale = true; renderMission(); }
  }
}

/* =================== bac à sable =================== */
function renderSandbox() {
  $('#sb-base').querySelectorAll('button').forEach(b => b.classList.toggle('on', b.dataset.base === App.sandboxBase));
}

/* =================== vues =================== */
function setView(v) {
  App.view = v;
  $('#app').dataset.view = v;
  document.querySelectorAll('.tab').forEach(t => t.setAttribute('aria-selected', String(t.dataset.view === v)));
  $('#pane-missions').hidden = v !== 'missions';
  $('#pane-sandbox').hidden = v !== 'sandbox';
  $('#work').hidden = v !== 'missions' && v !== 'sandbox';
  $('#view-quiz').hidden = v !== 'quiz';
  $('#view-memo').hidden = v !== 'memo';
  if (v === 'missions') selectMission(App.missionId);
  if (v === 'sandbox') {
    App.ctx = getCtx('sandbox');
    App.ctx.router.clock = App.when;
    term.render();
    topo.drawBadges(App.ctx.router.cfg);
    topo.anim.innerHTML = '';
    trace.message('Bac à sable : configure librement, puis envoie des paquets pour voir ce qui passe.');
    renderSandbox();
  }
  store.set('view', v);
  try { history.replaceState(null, '', '#' + v); } catch (e) { /* cadre sans historique */ }
}

/* =================== confettis =================== */
function confetti() {
  if (reduceMotion()) return;
  const cv = $('#confetti');
  const ctx2 = cv.getContext('2d');
  const W = cv.width = window.innerWidth, H = cv.height = window.innerHeight;
  cv.hidden = false;
  const css = getComputedStyle(document.documentElement);
  const cols = ['--accent', '--ok', '--warn', '--z-wifi', '--z-dmz'].map(v => css.getPropertyValue(v).trim() || '#3b82f6');
  const parts = Array.from({ length: 120 }, () => ({ x: W / 2 + (Math.random() - 0.5) * 200, y: H * 0.35, vx: (Math.random() - 0.5) * 12, vy: -Math.random() * 12 - 4, s: 4 + Math.random() * 5, r: Math.random() * 6, c: pick(cols) }));
  const t0 = performance.now();
  const frame = now => {
    const t = now - t0;
    ctx2.clearRect(0, 0, W, H);
    for (const p of parts) {
      p.vy += 0.35; p.x += p.vx; p.y += p.vy; p.r += 0.1;
      ctx2.save(); ctx2.translate(p.x, p.y); ctx2.rotate(p.r);
      ctx2.globalAlpha = Math.max(0, 1 - t / 1800);
      ctx2.fillStyle = p.c; ctx2.fillRect(-p.s / 2, -p.s / 4, p.s, p.s / 2);
      ctx2.restore();
    }
    if (t < 1800) requestAnimationFrame(frame); else { ctx2.clearRect(0, 0, W, H); cv.hidden = true; }
  };
  requestAnimationFrame(frame);
}

/* =================== calculateur du mémo =================== */
function wildCalc() {
  const v = $('#wc-in').value.trim();
  const out = $('#wc-out');
  let m = /^(\d+\.\d+\.\d+\.\d+)\s*\/\s*(\d{1,2})$/.exec(v);
  let base, wild;
  if (m && IP.toInt(m[1]) !== null && +m[2] <= 32) {
    wild = IP.wildOf(+m[2]);
    base = (IP.toInt(m[1]) & ~wild) >>> 0;
  } else {
    m = /^(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$/.exec(v);
    if (m && IP.toInt(m[1]) !== null && IP.toInt(m[2]) !== null) {
      let w = IP.toInt(m[2]);
      if (IP.looksLikeMask(w)) w = (~w) >>> 0;
      wild = w;
      base = (IP.toInt(m[1]) & ~wild) >>> 0;
    }
  }
  if (base == null) { out.innerHTML = '<p class="muted">Écris un réseau en /préfixe (172.16.4.0/22) ou une adresse suivie d\'un masque (172.16.4.0 255.255.252.0 ou 0.0.3.255).</p>'; return; }
  const pre = IP.prefixOfWild(wild);
  const last = (base | wild) >>> 0;
  const acl = wild === 0 ? `host ${IP.toStr(base)}` : wild === 0xFFFFFFFF ? 'any' : `${IP.toStr(base)} ${IP.toStr(wild)}`;
  out.innerHTML = `<dl class="wc-dl">
    <dt>Dans une ACL</dt><dd><code>${acl}</code></dd>
    <dt>Masque générique</dt><dd><code>${IP.toStr(wild)}</code></dd>
    ${pre != null ? `<dt>Masque réseau</dt><dd><code>${IP.toStr(IP.maskOf(pre))}</code> (/${pre})</dd>` : '<dt>Masque réseau</dt><dd>masque générique non contigu</dd>'}
    <dt>Adresses couvertes</dt><dd>${IP.toStr(base)} → ${IP.toStr(last)}${pre != null ? ` (${(2 ** (32 - pre)).toLocaleString('fr-FR')})` : ''}</dd>
  </dl>`;
}

/* =================== thème =================== */
function initTheme() {
  const saved = store.get('theme', null);
  if (saved) document.documentElement.dataset.theme = saved;
  $('#theme-btn').addEventListener('click', () => {
    const cur = document.documentElement.dataset.theme
      || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const nxt = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = nxt;
    store.set('theme', nxt);
  });
}

/* =================== démarrage =================== */
function init() {
  initTheme();
  term.init();
  topo.init();
  tester.init();
  Quiz.init();
  document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => setView(t.dataset.view)));
  $('#mission-map').addEventListener('click', e => {
    const b = e.target.closest('[data-m]');
    if (b) selectMission(b.dataset.m);
  });
  $('#mission-card').addEventListener('click', e => {
    const play = e.target.closest('[data-play]');
    if (play) return playTest(+play.dataset.play);
    const b = e.target.closest('[data-act]');
    if (!b) return;
    const m = curMission();
    const st = mstate(m.id);
    const act = b.dataset.act;
    if (act !== 'sol') st.armSol = false;
    if (act !== 'reset') st.armReset = false;
    if (act === 'verify') return verifyMission();
    if (act === 'hint') { st.hints = Math.min(m.hints.length, st.hints + 1); saveMstate(m.id); }
    if (act === 'sol') { if (st.armSol) { st.solution = true; st.armSol = false; saveMstate(m.id); } else st.armSol = true; }
    if (act === 'type-sol') { term.typeLines(m.solution); return; }
    if (act === 'reset') { if (st.armReset) return resetMission(m.id); st.armReset = true; }
    if (act === 'prev' || act === 'next') return selectMission(MISSIONS[MISSIONS.indexOf(m) + (act === 'next' ? 1 : -1)].id);
    renderMission();
  });
  $('#modal').addEventListener('click', e => {
    const b = e.target.closest('[data-modal]');
    if (!b && e.target !== $('#modal')) return;
    $('#modal').hidden = true;
    if (!b) return;
    if (b.dataset.modal === 'next') {
      const i = MISSIONS.indexOf(curMission());
      if (MISSIONS[i + 1]) selectMission(MISSIONS[i + 1].id);
    }
    if (b.dataset.modal === 'quiz') setView('quiz');
  });
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && !$('#modal').hidden) $('#modal').hidden = true; });
  $('#sb-base').addEventListener('click', e => {
    const b = e.target.closest('[data-base]');
    if (!b) return;
    App.sandboxBase = b.dataset.base;
    store.set('sandboxBase', App.sandboxBase);
    resetMission('sandbox');
  });
  $('#sb-reset').addEventListener('click', () => resetMission('sandbox'));
  $('#sb-ideas').addEventListener('click', e => {
    const b = e.target.closest('[data-type]');
    if (b) term.typeLines(b.dataset.type.split('|'));
  });
  $('#wc-in').addEventListener('input', wildCalc);
  wildCalc();
  const hashView = (location.hash || '').replace('#', '');
  setView(['missions', 'sandbox', 'quiz', 'memo'].includes(hashView) ? hashView : store.get('view', 'missions'));
}

document.addEventListener('DOMContentLoaded', init);
