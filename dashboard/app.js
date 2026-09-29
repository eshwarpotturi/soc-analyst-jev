(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  const MAXROWS = 60;
  const USD_TO_INR = 88; // approximate fixed rate, display only
  const SPAWN_MS = 150;  // ms between arrows at 1x
  const FLIGHT_MS = 600; // constant flight time keeps landing order == event order

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
    const total = events.length;
    const speed = () => +$('speed').value || 1;
    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;

    // ================= analytics =================
    const cats = Array.from(new Set(
      timeline.flatMap((t) => Object.keys(t.counts || {})).concat(Object.keys(byCat))));
    const color = d3.scaleOrdinal().domain(cats).range(d3.schemeTableau10);
    const stream = d3.select('#stream'), redlog = d3.select('#redlog');

    const RW = 520, rowH = 30, M = {l: 130, r: 50, t: 4, b: 4};
    const RH = Math.max(1, cats.length) * rowH + M.t + M.b;
    const svg = d3.select('#race').append('svg').attr('viewBox', `0 0 ${RW} ${RH}`);
    const x = d3.scaleLinear().range([0, RW - M.l - M.r]);
    const y = d3.scaleBand().domain(d3.range(cats.length)).range([M.t, RH - M.b]).padding(0.15);

    function drawRace(n, animate) {
      const counts = n > 0 && timeline[n - 1] ? timeline[n - 1].counts || {} : {};
      const data = cats.map((c) => ({c, v: counts[c] || 0})).sort((a, b) => b.v - a.v || d3.ascending(a.c, b.c));
      x.domain([0, Math.max(1, d3.max(data, (d) => d.v) || 0)]);
      const dur = animate ? Math.min(250, Math.max(30, 120 / speed())) : 0;
      svg.selectAll('g.bar').data(data, (d) => d.c).join((enter) => {
        const g = enter.append('g').attr('class', 'bar').attr('transform', (d, i) => `translate(${M.l},${y(i)})`);
        g.append('rect').attr('height', y.bandwidth()).attr('width', 0).attr('rx', 3).attr('fill', (d) => color(d.c));
        g.append('text').attr('x', -8).attr('y', y.bandwidth() / 2).attr('dy', '.35em').attr('text-anchor', 'end')
          .attr('fill', '#d5dde8').attr('font-size', 12).text((d) => d.c.replace(/_/g, ' '));
        g.append('text').attr('class', 'val').attr('y', y.bandwidth() / 2).attr('dy', '.35em').attr('fill', '#d5dde8').attr('font-size', 12);
        return g;
      }).call((g) => {
        g.transition().duration(dur).ease(d3.easeLinear).attr('transform', (d, i) => `translate(${M.l},${y(i)})`);
        g.select('rect').transition().duration(dur).ease(d3.easeLinear).attr('width', (d) => x(d.v));
        g.select('.val').transition().duration(dur).ease(d3.easeLinear).attr('x', (d) => x(d.v) + 6).text((d) => d.v);
      });
    }

    const fmtPct = (v) => (typeof v === 'number' && isFinite(v) ? (v * 100).toFixed(1) + '%' : 'n/a');
    const fmtNum = (v, d) => (typeof v === 'number' && isFinite(v) ? v.toFixed(d) : 'n/a');
    const kpi = (l, v, c) => `<div class="kpi"><div class="v ${c || ''}">${v}</div><div class="l">${l}</div></div>`;
    const m = metrics;
    $('accuracy').innerHTML =
      (run.note ? '<p class="note">' + esc(run.note) + '</p>' : '') +
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
      kpi('Total cost', '&asymp; &#8377;' + fmtNum(m.total_cost * USD_TO_INR, 2) + '<div class="l">$' + fmtNum(m.total_cost, 4) + ' USD</div>') + '</div>';

    function addEvent(e) {
      const act = e.action === 'block' ? 'block' : e.action === 'allow' ? 'allow' : 'error';
      stream.insert('div', ':first-child').attr('class', 'tile ' + act)
        .html(`<span class="m">${esc(e.method)}</span><span class="p">${esc(e.path)}</span>`);
      stream.selectAll('.tile').filter((d, i) => i >= MAXROWS).remove();
      if (act === 'block') {
        redlog.select('#redempty').remove();
        const conf = typeof e.jev_confidence === 'number' ? (e.jev_confidence * 100).toFixed(0) + '%' : 'n/a';
        redlog.insert('div', ':first-child').attr('class', 'flag')
          .html(`<span class="c">${esc(e.jev_category)} &middot; ${conf}</span><b>BLOCK</b> <span class="p">${esc(e.method)} ${esc(e.path)}</span><span class="r">${esc(e.reason)}</span>`);
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
      const castleW = Math.max(150, W * 0.34), castleX = W - castleW;
      const groundY = H * 0.86, wallTop = H * 0.34;
      const gateW = castleW * 0.24, gateH = (groundY - wallTop) * 0.52;
      const gateCX = castleX + castleW * 0.30, gateTop = groundY - gateH;
      G = {castleW, castleX, groundY, wallTop, gateW, gateH, gateCX, gateTop, gateCY: gateTop + gateH * 0.42};
      stars = [];
      const n = Math.round(W * H / 9000);
      for (let i = 0; i < n; i++) stars.push({x: Math.random() * W, y: Math.random() * H * 0.55, r: Math.random() * 1.3 + .2, tw: Math.random() * 6.28});
    }

    // ================= shared playback =================
    let spawned = 0, judged = 0, blockedSoFar = 0, admitted = 0, repelled = 0;
    let playing = false, acc = 0, last = performance.now();
    let arrows = [], sparks = [], folk = [], gateGlow = 0;

    function updateCounter() {
      $('counter').textContent = `${judged} / ${total} judged · ${blockedSoFar} blocked`;
      $('bar').style.width = (total ? (judged / total) * 100 : 0) + '%';
      $('s-seen').textContent = spawned; $('s-in').textContent = admitted; $('s-block').textContent = repelled;
    }

    function spawn(ev) {
      spawned++;
      const sy = H * 0.14 + Math.random() * (G.groundY - 10 - H * 0.14);
      // Shape = what the request truly is; outcome (target) = Jev's decision.
      const kind = ev.true_label === 'malicious' ? 'arrow' : 'messenger';
      const passes = ev.action !== 'block'; // allow or fail-open error -> through the gate
      let tx, ty;
      if (passes) { tx = G.gateCX; ty = G.gateCY; }
      else { tx = G.castleX + 6; ty = G.wallTop + 14 + Math.random() * (G.groundY - 24 - (G.wallTop + 14)); }
      arrows.push({sx: -24, sy, tx, ty, t: 0, ev, kind, passes});
    }

    function burst(x0, y0, col, n) {
      for (let i = 0; i < n; i++) { const a = Math.random() * 6.28, s = 1 + Math.random() * 3.2;
        sparks.push({x: x0, y: y0, vx: Math.cos(a) * s - 1.2, vy: Math.sin(a) * s, life: 1, color: col}); }
    }

    function land(ar) {
      const ev = ar.ev;
      judged++;
      if (ev.action === 'block') {
        repelled++; blockedSoFar++;
        // Red burst for a real attack stopped; amber for a legitimate request wrongly turned away.
        const falseAlarm = ar.kind === 'messenger';
        burst(ar.tx, ar.ty, falseAlarm ? '#e0b341' : '#ff7a54', falseAlarm ? 10 : 16);
        sparks.push({x: ar.tx - 4, y: ar.ty, vx: 0, vy: 0, life: 1.6, fixed: true,
          color: falseAlarm ? '#e0b341' : '#ff5a4d',
          label: (falseAlarm ? 'false alarm: ' : '') + (ev.jev_category || '').replace(/_/g, ' ')});
      } else {
        admitted++;
        gateGlow = 1; // green pulse on the gate as something passes through
        // It continues through the gate into the keep, then fades. Keeps its shape/colour.
        folk.push({x: G.gateCX, y: G.gateCY, vx: .8 + Math.random() * .5, life: 1, kind: ar.kind});
        burst(G.gateCX, G.gateCY, ar.kind === 'arrow' ? '#ff9a90' : '#8ee6b0', 5);
      }
      addEvent(ev);
      drawRace(judged, true);
      updateCounter();
    }

    function step(dt) {
      const k = playing ? 1 : 0;
      if (playing && spawned < total) {
        acc += dt;
        const iv = SPAWN_MS / speed();
        while (acc >= iv && spawned < total) { acc -= iv; spawn(events[spawned]); }
      }
      for (let i = 0; i < arrows.length; i++) arrows[i].t += dt / FLIGHT_MS * k;
      while (arrows.length && arrows[0].t >= 1) land(arrows.shift());
      for (let i = sparks.length - 1; i >= 0; i--) { const p = sparks[i];
        if (!p.fixed && k) { p.x += p.vx; p.y += p.vy; p.vy += 0.12; }
        p.life -= dt / (p.fixed ? 1400 : 700) * k;
        if (p.life <= 0) sparks.splice(i, 1); }
      if (k && gateGlow > 0) gateGlow = Math.max(0, gateGlow - dt / 450);
      for (let i = folk.length - 1; i >= 0; i--) { const f = folk[i];
        if (k) { f.x += f.vx * speed(); }
        if (f.x > G.castleX + G.castleW * 0.55) f.life -= dt / 420 * k; // fade as it enters the keep
        if (f.life <= 0) folk.splice(i, 1); }
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
      const bw = castleW / 9;
      for (let i = 0; i < 9; i += 2) ctx.fillRect(castleX + i * bw, wallTop - 16, bw, 16);
      for (const tx of [castleX - 2, castleX + castleW - 26]) {
        ctx.fillStyle = '#3f4459'; ctx.fillRect(tx, wallTop - 40, 28, groundY - wallTop + 40);
        ctx.fillStyle = '#4a5068'; for (let i = 0; i < 3; i += 2) ctx.fillRect(tx + i * 9, wallTop - 54, 9, 16);
      }
      ctx.strokeStyle = 'rgba(0,0,0,.18)'; ctx.lineWidth = 1;
      for (let yy = wallTop + 18; yy < groundY; yy += 18) { ctx.beginPath(); ctx.moveTo(castleX, yy); ctx.lineTo(castleX + castleW, yy); ctx.stroke(); }
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
      ctx.fillStyle = '#7a2230'; ctx.fillRect(gateCX - 16, wallTop + 8, 32, 44);
      ctx.beginPath(); ctx.moveTo(gateCX - 16, wallTop + 52); ctx.lineTo(gateCX, wallTop + 44); ctx.lineTo(gateCX + 16, wallTop + 52); ctx.closePath(); ctx.fill();
      ctx.fillStyle = '#e8bd6a'; ctx.font = '700 15px Cinzel, Georgia, serif'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillText('J', gateCX, wallTop + 28);
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
      const t = ease(Math.min(1, ar.t));
      const ax = ar.sx + (ar.tx - ar.sx) * t, ay = ar.sy + (ar.ty - ar.sy) * t;
      const angle = Math.atan2(ar.ty - ar.sy, ar.tx - ar.sx);
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
      ctx.fillStyle = 'rgba(232,224,196,.9)'; ctx.beginPath(); ctx.arc(W * 0.16, H * 0.24, 24, 0, 6.28); ctx.fill();
      ctx.fillStyle = 'rgba(15,20,40,.6)'; ctx.beginPath(); ctx.arc(W * 0.16 + 9, H * 0.24 - 5, 22, 0, 6.28); ctx.fill();
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
          ctx.fillText('✖ ' + p.label, p.x - 2, p.y);
        } else ctx.fillRect(p.x, p.y, 2.4, 2.4);
      }
      ctx.globalAlpha = 1;
    }

    function showDone() {
      const noFP = m.FP === 0;
      $('done-line').innerHTML = 'Jev judged <span class="num">' + esc(m.total_requests) + '</span> requests: <span class="num">' +
        esc(m.allowed) + '</span> villagers admitted, <span class="num r">' + esc(m.blocked) + '</span> attacks repelled. ' +
        'Precision ' + fmtPct(m.precision) + ', recall ' + fmtPct(m.recall) + '.' +
        (noFP ? ' No legitimate request was turned away.' : '');
      $('done').hidden = false;
    }

    function play() {
      if (spawned >= total && !arrows.length) restart();
      if (!total) return;
      playing = true; $('play').textContent = 'Pause'; last = performance.now();
    }
    function pause() { playing = false; $('play').textContent = (judged >= total && total) ? 'Replay' : 'Play'; }
    function restart() {
      spawned = judged = blockedSoFar = admitted = repelled = 0; acc = 0;
      arrows = []; sparks = []; folk = []; gateGlow = 0;
      stream.selectAll('.tile').remove(); redlog.selectAll('.flag').remove();
      if (redlog.select('#redempty').empty()) redlog.append('div').attr('class', 'empty').attr('id', 'redempty').text('No blocked requests yet.');
      $('done').hidden = true;
      drawRace(0, false); updateCounter();
    }

    $('play').onclick = () => (playing ? pause() : play());
    $('restart').onclick = () => { restart(); play(); };
    new ResizeObserver(resize).observe(cv);

    function loop(now) { const dt = Math.min(now - last, 60); last = now; step(dt); draw(); requestAnimationFrame(loop); }
    resize(); restart(); play(); requestAnimationFrame(loop);
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
