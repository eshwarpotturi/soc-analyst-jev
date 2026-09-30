(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  const MAXROWS = 60;
  const USD_TO_INR = 88;     // approximate fixed rate, display only
  const FALLBACK_GAP = 390;  // ms, for older run.json files without gap_ms
  const FLIGHT_MS = 600;     // constant flight time keeps landing order == log order
  const BANNER_MS = 2800;    // pause between waves while the banner shows
  const UNLABELLED = 'unlabelled_attack';
  const SEMANTIC = new Set(['prompt_injection', 'data_exfiltration', 'abuse']);
  const NAMES = {
    sql_injection: 'SQL injection', xss: 'Cross-site scripting', path_traversal: 'Path traversal',
    command_injection: 'Command injection', ssrf: 'SSRF', auth_bruteforce: 'Login brute-force',
    scanner_probe: 'Scanner probe', other_exploit: 'Other exploit', prompt_injection: 'Prompt injection',
    data_exfiltration: 'Data exfiltration', abuse: 'Business-logic abuse', [UNLABELLED]: 'Unlabelled attack',
  };
  const nice = (c) => NAMES[c] || String(c || '').replace(/_/g, ' ');

  // Standalone builds inline the data as window.__RUN__; the hosted site fetches run.json.
  const load = window.__RUN__ ? Promise.resolve(window.__RUN__)
    : fetch('run.json').then((r) => { if (!r.ok) throw new Error('run.json HTTP ' + r.status); return r.json(); });
  load.then(init).catch((e) => {
    $('analytics').innerHTML = '<p class="empty">Could not load run.json: ' + esc(e.message) + '</p>';
  });

  function init(run) {
    const events = run.events || [];
    const timeline = run.category_timeline || [];
    const metrics = run.metrics || {};
    const byCat = run.by_category || {};
    const waves = (run.waves && run.waves.length) ? run.waves : [{label: 'Run', start: 0, count: events.length, metrics}];
    const total = events.length;
    const speed = () => +$('speed').value || 1;
    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
    const waveOf = (e) => (typeof e.wave === 'number' ? e.wave : 0);
    const gapOf = (e) => (typeof e.gap_ms === 'number' ? e.gap_ms : FALLBACK_GAP);

    // ================= lanes: the bar chart race, drawn on the castle wall =================
    // Lanes = every category that ever gets a block (both waves), so wave-2 lanes wait at 0 and then climb.
    const cats = Array.from(new Set(timeline.flatMap((t) => Object.keys(t.counts || {}))));
    const laneOf = (e) => (cats.includes(e.jev_category) ? e.jev_category : UNLABELLED);
    const classic = d3.schemeTableau10.filter((c, i) => i !== 4); // skip the green (green = allowed)
    let ci = 0;
    const color = {};
    for (const c of cats) color[c] = SEMANTIC.has(c) ? '#b18cff' : c === UNLABELLED ? '#8a93a6' : classic[ci++ % classic.length];

    const lanesEl = $('lanes');
    const rows = {};
    for (const c of cats) {
      const r = document.createElement('div');
      r.className = 'lane' + (SEMANTIC.has(c) ? ' ai' : '');
      r.setAttribute('role', 'listitem');
      r.innerHTML = '<span class="rk"></span><span class="nm">' + esc(nice(c)) +
        (SEMANTIC.has(c) ? ' <em>AI</em>' : '') + '</span><span class="track"><span class="fill"></span></span>' +
        '<span class="ct">0</span><span class="up" aria-hidden="true">&#9650;</span>';
      r.querySelector('.fill').style.background = color[c];
      lanesEl.appendChild(r);
      rows[c] = {el: r, rank: cats.indexOf(c), v: 0, upUntil: 0};
    }
    let laneGeo = {top: 0, h: 20};
    const laneY = (c) => laneGeo.top + (rows[c] ? rows[c].rank : 0) * laneGeo.h + laneGeo.h / 2;

    function drawLanes(n) {
      const counts = n > 0 && timeline[n - 1] ? timeline[n - 1].counts || {} : {};
      const data = cats.map((c) => ({c, v: counts[c] || 0})).sort((a, b) => b.v - a.v || d3.ascending(cats.indexOf(a.c), cats.indexOf(b.c)));
      const max = Math.max(1, d3.max(data, (d) => d.v) || 0);
      const now = performance.now();
      data.forEach((d, i) => {
        const r = rows[d.c];
        if (i < r.rank && d.v > 0 && n > 0) r.upUntil = now + 1200; // it overtook someone
        r.rank = i; r.v = d.v;
        r.el.style.transform = `translateY(${i * laneGeo.h}px)`;
        r.el.querySelector('.rk').textContent = d.v ? '#' + (i + 1) : '';
        r.el.querySelector('.ct').textContent = d.v;
        r.el.querySelector('.fill').style.width = (d.v / max * 100) + '%';
        r.el.classList.toggle('zero', d.v === 0);
        r.el.classList.toggle('rising', r.upUntil > now);
      });
    }
    function tickLanes() {
      const now = performance.now();
      for (const c of cats) if (rows[c].el.classList.contains('rising') && rows[c].upUntil <= now) rows[c].el.classList.remove('rising');
    }
    function flashLane(c, falseAlarm) {
      const r = rows[c]; if (!r) return;
      r.el.classList.remove('hit', 'hit-fa'); void r.el.offsetWidth; // restart the animation
      r.el.classList.add(falseAlarm ? 'hit-fa' : 'hit');
    }

    // ================= KPI cards (live) + accuracy panel (whole run) =================
    const fmtPct = (v) => (typeof v === 'number' && isFinite(v) ? (v * 100).toFixed(1) + '%' : 'n/a');
    const fmtNum = (v, d) => (typeof v === 'number' && isFinite(v) ? v.toFixed(d) : 'n/a');
    let live;
    function resetLive() { live = {tp: 0, fp: 0, att: 0, benign: 0, latSum: 0, latN: 0, faWaves: new Set(), faPaths: new Set()}; }
    function track(e) {
      const mal = e.true_label === 'malicious', blocked = e.action === 'block';
      if (mal) { live.att++; if (blocked) live.tp++; }
      else if (e.true_label === 'benign') {
        live.benign++;
        if (blocked) { live.fp++; live.faWaves.add(waveOf(e)); live.faPaths.add(e.path); }
      }
      if (typeof e.latency_ms === 'number') { live.latSum += e.latency_ms; live.latN++; }
    }
    function renderKpis() {
      $('k-caught').textContent = live.tp;
      $('k-att').textContent = live.att;
      $('k-caught-s').textContent = live.att ? `${(100 * live.tp / live.att).toFixed(1)}% of attacks judged so far` : 'of the attacks judged so far';
      const fa = $('k-fa');
      fa.textContent = live.fp;
      fa.className = 'kv ' + (live.fp ? 'a' : 'g');
      let s = `of ${live.benign} legitimate requests blocked`;
      if (live.fp) {
        const ws = Array.from(live.faWaves).map((w) => 'wave ' + (w + 1));
        const where = Array.from(live.faPaths).slice(0, 3).join(', ');
        s = `${live.fp === 1 ? 'it was' : 'all'} in ${ws.join(' & ')} &middot; legitimate requests on ${esc(where)}`;
      }
      $('k-fa-s').innerHTML = s;
      $('k-lat').textContent = live.latN ? Math.round(live.latSum / live.latN) : '—';
    }

    const kpi = (l, v, c) => `<div class="kpi"><div class="v ${c || ''}">${v}</div><div class="l">${l}</div></div>`;
    const m = metrics;
    const waveLine = waves.length > 1 ? '<div class="wavesum">' + waves.map((w, i) => {
      const wm = w.metrics || {};
      return `<div><b>${esc(w.label)}</b> &middot; ${esc(w.count)} requests &middot; caught ${esc(wm.TP)} / ${esc((wm.TP || 0) + (wm.FN || 0))} attacks &middot; ${esc(wm.FP)} false alarm${wm.FP === 1 ? '' : 's'} &middot; avg ${fmtNum(wm.avg_latency_ms, 0)} ms</div>`;
    }).join('') + '</div>' : '';
    $('accuracy').innerHTML =
      (run.note ? '<p class="note">' + esc(run.note) + '</p>' : '') + waveLine +
      '<div class="kpis">' +
      kpi('Precision (blocks that were real attacks)', fmtPct(m.precision), 'x') +
      kpi('Recall (attacks caught)', fmtPct(m.recall), 'x') +
      kpi('Jev detection recall (all Jev calls)', fmtPct(m.jev_detection_recall), 'x') + '</div>' +
      '<div class="cm"><div class="h"></div><div class="h">Actually attack</div><div class="h">Actually normal</div>' +
      `<div class="h">Blocked</div><div><span class="v g">${esc(m.TP)}</span><small>Attacks caught (TP)</small></div><div><span class="v a">${esc(m.FP)}</span><small>False alarms (FP)</small></div>` +
      `<div class="h">Allowed</div><div><span class="v r">${esc(m.FN)}</span><small>Missed attacks (FN)</small></div><div><span class="v g">${esc(m.TN)}</span><small>Correctly allowed (TN)</small></div></div>` +
      '<div class="kpis">' +
      kpi('Total requests', esc(m.total_requests)) + kpi('Blocked', esc(m.blocked), 'r') +
      kpi('Allowed', esc(m.allowed), 'g') + kpi('Errors', esc(m.errors), 'a') +
      kpi('Avg latency (ms)', fmtNum(m.avg_latency_ms, 0)) +
      kpi('Total cost', '&asymp; &#8377;' + fmtNum(m.total_cost * USD_TO_INR, 2) + '<div class="l">$' + fmtNum(m.total_cost, 4) + ' USD</div>') + '</div>' +
      (Object.keys(byCat).length ? '<p class="bycat">Caught, by true attack type: ' + Object.entries(byCat).filter(([, v]) => v.total)
        .map(([c, v]) => `${esc(nice(c))} <b>${esc(v.blocked)}/${esc(v.total)}</b>`).join(' &middot; ') + '</p>' : '');

    const stream = d3.select('#stream'), redlog = d3.select('#redlog');
    function addEvent(e) {
      const act = e.action === 'block' ? 'block' : e.action === 'allow' ? 'allow' : 'error';
      stream.insert('div', ':first-child').attr('class', 'tile ' + act)
        .html(`<span class="m">${esc(e.method)}</span><span class="p">${esc(e.path)}</span>`);
      stream.selectAll('.tile').filter((d, i) => i >= MAXROWS).remove();
      if (act === 'block') {
        redlog.select('#redempty').remove();
        const conf = typeof e.jev_confidence === 'number' ? (e.jev_confidence * 100).toFixed(0) + '%' : 'n/a';
        redlog.insert('div', ':first-child').attr('class', 'flag')
          .html(`<span class="c">${e.true_label === 'benign' ? 'false alarm &middot; ' : ''}${esc(nice(laneOf(e)))} &middot; ${conf}</span><b>BLOCK</b> <span class="p">${esc(e.method)} ${esc(e.path)}</span><span class="r">${esc(e.reason)}</span>`);
        redlog.selectAll('.flag').filter((d, i) => i >= MAXROWS).remove();
      }
    }

    // ================= castle =================
    const cv = $('castle'), ctx = cv.getContext('2d');
    let W = 0, H = 0, G = {}, stars = [];
    function resize() {
      const dpr = Math.min(devicePixelRatio || 1, 2);
      W = cv.clientWidth; H = cv.clientHeight;
      cv.width = W * dpr; cv.height = H * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const castleW = W < 700 ? W * 0.64 : Math.min(640, Math.max(360, W * 0.42));
      const castleX = W - castleW;
      const groundY = H * 0.9, wallTop = Math.max(64, H * 0.13);
      const gateH = Math.max(56, Math.min(104, (groundY - wallTop) * 0.24)), gateW = gateH * 0.72;
      const gateCX = castleX + castleW * 0.5, gateTop = groundY - gateH;
      G = {castleW, castleX, groundY, wallTop, gateW, gateH, gateCX, gateTop, gateCY: gateTop + gateH * 0.45};
      // lane area = the wall face between the battlements and the gate
      const inset = 30, top = wallTop + 26, bottom = gateTop - 12;
      laneGeo = {top, h: Math.max(14, (bottom - top) / Math.max(1, cats.length))};
      Object.assign(lanesEl.style, {left: (castleX + inset) + 'px', top: top + 'px', width: (castleW - inset * 2) + 'px',
        height: (laneGeo.h * cats.length) + 'px'});
      lanesEl.style.setProperty('--lane-h', laneGeo.h + 'px');
      drawLanes(judged);
      stars = [];
      const n = Math.round(W * H / 9000);
      for (let i = 0; i < n; i++) stars.push({x: Math.random() * W, y: Math.random() * H * 0.55, r: Math.random() * 1.3 + .2, tw: Math.random() * 6.28});
    }

    // ================= shared playback =================
    let spawned = 0, judged = 0, blockedSoFar = 0, admitted = 0, repelled = 0;
    let playing = false, acc = 0, last = performance.now(), hold = 0, curWave = 0;
    let arrows = [], sparks = [], folk = [], gateGlow = 0;

    function updateCounter() {
      $('counter').textContent = `${judged} / ${total} judged · ${blockedSoFar} blocked`;
      $('bar').style.width = (total ? (judged / total) * 100 : 0) + '%';
      $('s-seen').textContent = spawned; $('s-in').textContent = admitted; $('s-block').textContent = repelled;
      const w = waves[curWave];
      $('wave-pill').textContent = waves.length > 1 && w ? w.label : '';
      $('wave-pill').hidden = !(waves.length > 1);
    }

    function showBanner(wi) {
      const w = waves[wi] || {};
      const parts = String(w.label || '').split(' · ');
      $('wb-k').textContent = parts[0] || ('Wave ' + (wi + 1));
      $('wb-t').textContent = parts.slice(1).join(' · ');
      $('wb-s').textContent = `a separate real run · ${w.count} requests`;
      $('wave-banner').hidden = false;
      hold = BANNER_MS;
    }

    function spawn(ev) {
      spawned++;
      const sy = H * 0.14 + Math.random() * (G.groundY - 10 - H * 0.14);
      // Shape = what the request truly is; outcome (target) = Jev's decision.
      const kind = ev.true_label === 'malicious' ? 'arrow' : 'messenger';
      const passes = ev.action !== 'block'; // allow or fail-open error -> through the gate
      arrows.push({sx: -24, sy, t: 0, ev, kind, passes, lane: passes ? null : laneOf(ev)});
    }
    // Blocked arrows aim at their lane's *current* row, so a re-rank mid-flight is still a hit.
    const target = (ar) => (ar.passes ? {x: G.gateCX, y: G.gateCY} : {x: G.castleX + 4, y: laneY(ar.lane)});

    function burst(x0, y0, col, n) {
      for (let i = 0; i < n; i++) { const a = Math.random() * 6.28, s = 1 + Math.random() * 3.2;
        sparks.push({x: x0, y: y0, vx: Math.cos(a) * s - 1.2, vy: Math.sin(a) * s, life: 1, color: col}); }
    }

    function land(ar) {
      const ev = ar.ev, tg = target(ar);
      judged++;
      track(ev);
      if (ev.action === 'block') {
        repelled++; blockedSoFar++;
        // Red burst for a real attack stopped; amber for a legitimate request wrongly turned away.
        const falseAlarm = ar.kind === 'messenger';
        burst(tg.x, tg.y, falseAlarm ? '#e0b341' : '#ff7a54', falseAlarm ? 10 : 14);
        if (falseAlarm) sparks.push({x: tg.x - 6, y: tg.y, vx: 0, vy: 0, life: 1.6, fixed: true, color: '#e0b341', label: 'false alarm'});
        drawLanes(judged);
        flashLane(ar.lane, falseAlarm);
      } else {
        admitted++;
        gateGlow = 1; // green pulse on the gate as something passes through
        folk.push({x: G.gateCX, y: G.gateCY, vx: .8 + Math.random() * .5, life: 1, kind: ar.kind});
        burst(G.gateCX, G.gateCY, ar.kind === 'arrow' ? '#ff9a90' : '#8ee6b0', 5);
      }
      addEvent(ev);
      renderKpis();
      updateCounter();
    }

    function step(dt) {
      const k = playing ? 1 : 0;
      if (playing && hold > 0) {
        hold -= dt;
        if (hold <= 0) { hold = 0; $('wave-banner').hidden = true; }
      } else if (playing && spawned < total) {
        acc += dt * speed();
        while (spawned < total && hold === 0) {
          const ev = events[spawned];
          if (waveOf(ev) !== curWave) { curWave = waveOf(ev); acc = 0; showBanner(curWave); updateCounter(); break; }
          if (acc < gapOf(ev)) break;
          acc -= gapOf(ev); spawn(ev);
        }
      }
      for (let i = 0; i < arrows.length; i++) arrows[i].t += dt / FLIGHT_MS * k;
      while (arrows.length && arrows[0].t >= 1) land(arrows.shift());
      for (let i = sparks.length - 1; i >= 0; i--) { const p = sparks[i];
        if (!p.fixed && k) { p.x += p.vx; p.y += p.vy; p.vy += 0.12; }
        p.life -= dt / (p.fixed ? 1400 : 700) * k;
        if (p.life <= 0) sparks.splice(i, 1); }
      if (k && gateGlow > 0) gateGlow = Math.max(0, gateGlow - dt / 450);
      for (let i = folk.length - 1; i >= 0; i--) { const f = folk[i];
        if (k) { f.x += f.vx * Math.min(4, speed()); }
        if (f.x > G.gateCX + 40) f.life -= dt / 420 * k; // fade as it enters the keep
        if (f.life <= 0) folk.splice(i, 1); }
      tickLanes();
      if (playing && spawned >= total && !arrows.length && !folk.length && !sparks.length) { pause(); showDone(); }
    }

    const ease = (t) => (t < .5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2);

    function drawCastle() {
      const {castleX, castleW, groundY, wallTop, gateCX, gateTop, gateW} = G;
      ctx.fillStyle = '#141a2e'; ctx.fillRect(0, groundY, W, H - groundY);
      const g = ctx.createLinearGradient(castleX, 0, castleX + castleW, 0);
      g.addColorStop(0, '#454b60'); g.addColorStop(1, '#31364a');
      ctx.fillStyle = g; ctx.fillRect(castleX, wallTop, castleW, groundY - wallTop);
      ctx.fillStyle = '#3a3f52';
      const nb = 11, bw = castleW / nb;
      for (let i = 0; i < nb; i += 2) ctx.fillRect(castleX + i * bw, wallTop - 16, bw, 16);
      for (const tx of [castleX - 2, castleX + castleW - 26]) {
        ctx.fillStyle = '#3f4459'; ctx.fillRect(tx, wallTop - 40, 28, groundY - wallTop + 40);
        ctx.fillStyle = '#4a5068'; for (let i = 0; i < 3; i += 2) ctx.fillRect(tx + i * 9, wallTop - 54, 9, 16);
      }
      ctx.strokeStyle = 'rgba(0,0,0,.14)'; ctx.lineWidth = 1;
      for (let yy = wallTop + 18; yy < groundY; yy += 18) { ctx.beginPath(); ctx.moveTo(castleX, yy); ctx.lineTo(castleX + castleW, yy); ctx.stroke(); }
      // the wall doubles as the scoreboard
      ctx.fillStyle = 'rgba(232,189,106,.85)'; ctx.font = '600 10.5px system-ui, sans-serif'; ctx.textAlign = 'left'; ctx.textBaseline = 'middle';
      ctx.fillText('ATTACKS BLOCKED · RANKED BY JEV’S CATEGORY', castleX + 32, wallTop + 13);
      ctx.fillStyle = '#0d1120';
      ctx.beginPath();
      ctx.moveTo(gateCX - gateW / 2, groundY);
      ctx.lineTo(gateCX - gateW / 2, gateTop + gateW / 2);
      ctx.arc(gateCX, gateTop + gateW / 2, gateW / 2, Math.PI, 0);
      ctx.lineTo(gateCX + gateW / 2, groundY);
      ctx.closePath(); ctx.fill();
      const gg = ctx.createLinearGradient(0, gateTop, 0, groundY);
      gg.addColorStop(0, 'rgba(232,189,106,.18)'); gg.addColorStop(1, 'rgba(232,189,106,0)');
      ctx.fillStyle = gg; ctx.fill();
      // Jev's crest beside the gate
      const bx = gateCX + gateW / 2 + 14;
      ctx.fillStyle = '#7a2230'; ctx.fillRect(bx, gateTop + 4, 26, 36);
      ctx.beginPath(); ctx.moveTo(bx, gateTop + 40); ctx.lineTo(bx + 13, gateTop + 33); ctx.lineTo(bx + 26, gateTop + 40); ctx.closePath(); ctx.fill();
      ctx.fillStyle = '#e8bd6a'; ctx.font = '700 14px Cinzel, Georgia, serif'; ctx.textAlign = 'center';
      ctx.fillText('J', bx + 13, gateTop + 20);
    }

    function redArrow(angle) {
      ctx.rotate(angle);
      ctx.strokeStyle = '#c9553f'; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.moveTo(-16, 0); ctx.lineTo(6, 0); ctx.stroke();
      ctx.strokeStyle = '#8f3a2c';
      ctx.beginPath(); ctx.moveTo(-16, 0); ctx.lineTo(-20, -3); ctx.moveTo(-16, 0); ctx.lineTo(-20, 3); ctx.stroke();
      ctx.fillStyle = '#ff5a4d';
      ctx.beginPath(); ctx.moveTo(6, 0); ctx.lineTo(0, -3.2); ctx.lineTo(0, 3.2); ctx.closePath(); ctx.fill();
    }

    function greenMessenger(angle) {
      // a glowing orb with a short comet trail (a friendly "visitor", not a weapon)
      const tr = ctx.createRadialGradient(0, 0, 0, 0, 0, 9);
      tr.addColorStop(0, 'rgba(93,211,138,.9)'); tr.addColorStop(1, 'rgba(93,211,138,0)');
      ctx.fillStyle = tr; ctx.beginPath(); ctx.arc(0, 0, 9, 0, 6.28); ctx.fill();
      ctx.save(); ctx.rotate(angle);
      ctx.strokeStyle = 'rgba(140,230,176,.5)'; ctx.lineWidth = 3; ctx.lineCap = 'round';
      ctx.beginPath(); ctx.moveTo(-14, 0); ctx.lineTo(-2, 0); ctx.stroke();
      ctx.restore();
      ctx.fillStyle = '#8ee6b0'; ctx.beginPath(); ctx.arc(0, 0, 3.4, 0, 6.28); ctx.fill();
    }

    function drawArrow(ar) {
      const t = ease(Math.min(1, ar.t)), tg = target(ar);
      const ax = ar.sx + (tg.x - ar.sx) * t, ay = ar.sy + (tg.y - ar.sy) * t;
      const angle = Math.atan2(tg.y - ar.sy, tg.x - ar.sx);
      ctx.save(); ctx.translate(ax, ay);
      if (ar.kind === 'arrow') redArrow(angle); else greenMessenger(angle);
      ctx.restore();
    }

    function drawFolk(f) {
      // a request that was let in, gliding through the gate into the keep and fading
      ctx.save();
      ctx.globalAlpha = Math.max(0, Math.min(1, f.life));
      ctx.translate(f.x, f.y);
      if (f.kind === 'arrow') redArrow(0); else greenMessenger(0);
      ctx.restore();
      ctx.globalAlpha = 1;
    }

    function draw() {
      const sg = ctx.createLinearGradient(0, 0, 0, H);
      sg.addColorStop(0, '#0a1026'); sg.addColorStop(.7, '#1b2444'); sg.addColorStop(1, '#212a4d');
      ctx.fillStyle = sg; ctx.fillRect(0, 0, W, H);
      ctx.fillStyle = 'rgba(232,224,196,.9)'; ctx.beginPath(); ctx.arc(W * 0.16, H * 0.3, 24, 0, 6.28); ctx.fill();
      ctx.fillStyle = 'rgba(15,20,40,.6)'; ctx.beginPath(); ctx.arc(W * 0.16 + 9, H * 0.3 - 5, 22, 0, 6.28); ctx.fill();
      const now = performance.now() / 700;
      ctx.fillStyle = '#dfe6ff';
      for (const s of stars) { ctx.globalAlpha = reduce ? 0.7 : 0.4 + 0.4 * Math.abs(Math.sin(now + s.tw)); ctx.fillRect(s.x, s.y, s.r, s.r); }
      ctx.globalAlpha = 1;
      drawCastle();
      if (gateGlow > 0) {
        const gy = G.gateTop, gh = G.gateH, gw = G.gateW;
        const gr = ctx.createLinearGradient(0, gy, 0, gy + gh);
        gr.addColorStop(0, `rgba(93,211,138,${0.5 * gateGlow})`); gr.addColorStop(1, 'rgba(93,211,138,0)');
        ctx.fillStyle = gr; ctx.fillRect(G.gateCX - gw / 2, gy, gw, gh);
      }
      for (const f of folk) drawFolk(f);
      for (const ar of arrows) drawArrow(ar);
      for (const p of sparks) {
        ctx.globalAlpha = Math.max(0, Math.min(1, p.life));
        ctx.fillStyle = p.color;
        if (p.label) {
          ctx.font = '600 12px system-ui, sans-serif'; ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
          ctx.fillText('⚠ ' + p.label, p.x - 2, p.y);
        } else ctx.fillRect(p.x, p.y, 2.4, 2.4);
      }
      ctx.globalAlpha = 1;
    }

    function showDone() {
      const att = (m.TP || 0) + (m.FN || 0);
      $('done-line').innerHTML = 'Jev judged <span class="num">' + esc(m.total_requests) + '</span> requests' +
        (waves.length > 1 ? ' across ' + waves.length + ' waves' : '') + ': caught <span class="num r">' + esc(m.TP) +
        '</span> of ' + esc(att) + ' attacks, with <span class="num' + (m.FP ? ' a' : '') + '">' + esc(m.FP) +
        '</span> false alarm' + (m.FP === 1 ? '' : 's') + ', averaging <span class="num">' + fmtNum(m.avg_latency_ms, 0) + ' ms</span> per decision.';
      $('done').hidden = false;
    }

    function play() {
      if (!$('done').hidden) restart(); // replay only after the finish card; a pause mid-fade just resumes
      if (!total) return;
      playing = true; $('play').textContent = 'Pause'; last = performance.now();
    }
    function pause() { playing = false; $('play').textContent = (judged >= total && total) ? 'Replay' : 'Play'; }
    function restart() {
      spawned = judged = blockedSoFar = admitted = repelled = 0; acc = 0; hold = 0;
      curWave = total ? waveOf(events[0]) : 0;
      arrows = []; sparks = []; folk = []; gateGlow = 0;
      $('wave-banner').hidden = true;
      stream.selectAll('.tile').remove(); redlog.selectAll('.flag').remove();
      if (redlog.select('#redempty').empty()) redlog.append('div').attr('class', 'empty').attr('id', 'redempty').text('No blocked requests yet.');
      $('done').hidden = true;
      for (const c of cats) rows[c].upUntil = 0;
      resetLive(); renderKpis();
      drawLanes(0); updateCounter();
    }

    $('play').onclick = () => (playing ? pause() : play());
    $('restart').onclick = () => { restart(); play(); };
    new ResizeObserver(resize).observe(cv);

    function loop(now) { const dt = Math.min(now - last, 60); last = now; step(dt); draw(); requestAnimationFrame(loop); }
    resetLive(); resize(); restart(); play(); requestAnimationFrame(loop);
  }
})();

// ---- semantic comparison section (independent of the run replay) ----
(function () {
  'use strict';
  const sec = document.getElementById('semantic');
  if (!sec) return;
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  const load = window.__COMPARE__ ? Promise.resolve(window.__COMPARE__)
    : fetch('compare.json').then((r) => { if (!r.ok) throw new Error('compare.json HTTP ' + r.status); return r.json(); });
  load.then(render).catch(() => { sec.hidden = true; }); // no comparison data: hide the section cleanly

  function card(a, total) {
    const isJev = a.name.toLowerCase().includes('jev');
    const cls = a.caught === 0 ? 'miss' : (isJev ? 'win' : '');
    const pct = a.attacks ? Math.round(100 * a.caught / a.attacks) : 0;
    const v = a.caught === 0
      ? '<div class="verdict bad">Blind to this class &mdash; every semantic attack passed straight through.</div>'
      : (isJev ? `<div class="verdict good">Caught ${pct}% by weighing intent, not signatures.</div>` : '');
    return `<div class="cmpcard"><h4>${esc(a.name.split(' (')[0])}</h4>`
      + `<p class="sub">${esc(a.name.includes('(') ? a.name.split('(')[1].replace(')', '') : '')}</p>`
      + `<div class="big ${cls}">${a.caught}<span class="of"> / ${a.attacks}</span></div>`
      + `<div class="cap">semantic attacks caught</div>`
      + `<div class="mini"><div><b>${a.missed}</b><div class="k">missed</div></div>`
      + `<div><b>${a.false_alarms}</b><div class="k">false alarms</div></div></div>${v}</div>`;
  }

  function render(d) {
    const R = d.approaches.regex, J = d.approaches.jev;
    document.getElementById('sem-cols').innerHTML = card(R, d.attacks) + (J ? card(J, d.attacks)
      : '<div class="cmpcard"><h4>Jev</h4><p class="sub">judgment model</p><div class="big">&mdash;</div><div class="cap">pending a Jev run</div></div>');
    document.querySelector('#sem-ex tbody').innerHTML = (d.examples || []).map((e) => `<tr>`
      + `<td>${esc(e.text)}</td><td class="cat">${esc((e.category || '').replace(/_/g, ' '))}</td>`
      + `<td><span class="tag ${e.regex}">${e.regex}</span></td>`
      + `<td><span class="tag ${e.jev}">${e.jev}</span></td></tr>`).join('');
    // Plain-language explanation, including the honest false-alarm caveat.
    const note = document.getElementById('sem-note');
    if (!J) { note.innerHTML = 'Run Jev over the same set to fill in its column.'; return; }
    const fa = J.false_alarms;
    note.innerHTML =
      `<b>How to read this.</b> On ${d.total} requests (${d.attacks} semantic attacks, ${d.benign} legitimate), the signature WAF caught `
      + `<b>${R.caught} of ${d.attacks}</b> &mdash; these attacks carry no pattern to match, so its rules never fired. Jev caught `
      + `<b>${J.caught} of ${d.attacks}</b> by judging what the request is trying to do. This is the case for a judgment model: it defends against a whole class of attack a rule engine structurally cannot see. `
      + (fa > 0
          ? `The trade-off is honest &mdash; Jev raised <b>${fa} false alarm${fa === 1 ? '' : 's'}</b>, all on legitimate checkout and cart requests. Business-logic abuse and real business logic touch the same machinery (prices, orders), so the line between them is genuinely blurrier than for a SQL-injection payload. Those borderline requests scored near the block threshold; a higher threshold for that traffic, or a &ldquo;challenge&rdquo; step instead of an outright block, removes them.`
          : `And it did so with <b>no false alarms</b> on the legitimate traffic.`);
  }
})();
