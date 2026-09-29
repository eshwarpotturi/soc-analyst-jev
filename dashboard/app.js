(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  const MAXROWS = 60;

  fetch('run.json').then((r) => {
    if (!r.ok) throw new Error('run.json HTTP ' + r.status);
    return r.json();
  }).then(init).catch((e) => {
    document.querySelector('main').innerHTML = '<p class="empty">Could not load run.json: ' + esc(e.message) + '</p>';
  });

  function init(run) {
    const events = run.events || [];
    const timeline = run.category_timeline || [];
    const metrics = run.metrics || {};
    const byCat = run.by_category || {};
    const total = events.length;

    // categories derived from data
    const cats = Array.from(new Set(
      timeline.flatMap((t) => Object.keys(t.counts || {})).concat(Object.keys(byCat))));
    const color = d3.scaleOrdinal().domain(cats).range(d3.schemeTableau10);

    let pos = 0, timer = null, playing = false;

    const stream = d3.select('#stream'), redlog = d3.select('#redlog');
    redlog.append('div').attr('class', 'empty').attr('id', 'redempty').text('No blocked requests yet.');

    // ---- bar chart race ----
    const W = 520, rowH = 30, M = {l: 130, r: 50, t: 4, b: 4};
    const H = Math.max(1, cats.length) * rowH + M.t + M.b;
    const svg = d3.select('#race').append('svg').attr('viewBox', `0 0 ${W} ${H}`);
    const x = d3.scaleLinear().range([0, W - M.l - M.r]);
    const y = d3.scaleBand().domain(d3.range(cats.length)).range([M.t, H - M.b]).padding(0.15);

    function drawRace(animate) {
      const counts = pos > 0 && timeline[pos - 1] ? timeline[pos - 1].counts || {} : {};
      const data = cats.map((c) => ({c, v: counts[c] || 0}))
        .sort((a, b) => b.v - a.v || d3.ascending(a.c, b.c));
      x.domain([0, Math.max(1, d3.max(data, (d) => d.v) || 0)]);
      const dur = animate ? 250 : 0;
      svg.selectAll('g.bar').data(data, (d) => d.c).join(
        (enter) => {
          const g = enter.append('g').attr('class', 'bar').attr('transform', (d, i) => `translate(${M.l},${y(i)})`);
          g.append('rect').attr('height', y.bandwidth()).attr('width', 0).attr('rx', 3).attr('fill', (d) => color(d.c));
          g.append('text').attr('class', 'lab').attr('x', -8).attr('y', y.bandwidth() / 2).attr('dy', '.35em')
            .attr('text-anchor', 'end').attr('fill', '#d5dde8').attr('font-size', 12).text((d) => d.c.replace(/_/g, ' '));
          g.append('text').attr('class', 'val').attr('y', y.bandwidth() / 2).attr('dy', '.35em')
            .attr('fill', '#d5dde8').attr('font-size', 12);
          return g;
        })
        .call((g) => {
          g.transition().duration(dur).ease(d3.easeLinear).attr('transform', (d, i) => `translate(${M.l},${y(i)})`);
          g.select('rect').transition().duration(dur).ease(d3.easeLinear).attr('width', (d) => x(d.v));
          g.select('.val').transition().duration(dur).ease(d3.easeLinear).attr('x', (d) => x(d.v) + 6).text((d) => d.v);
        });
    }

    // ---- accuracy panel ----
    const fmtPct = (v) => (typeof v === 'number' && isFinite(v) ? (v * 100).toFixed(1) + '%' : 'n/a');
    const fmtNum = (v, d) => (typeof v === 'number' && isFinite(v) ? v.toFixed(d) : 'n/a');
    const kpi = (l, v, c) => `<div class="kpi"><div class="v ${c || ''}">${v}</div><div class="l">${l}</div></div>`;
    const m = metrics;
    $('accuracy').innerHTML =
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
      kpi('Avg latency (ms)', fmtNum(m.avg_latency_ms, 0)) + kpi('Total cost (USD)', '$' + fmtNum(m.total_cost, 4)) + '</div>';

    // ---- playback ----
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
    function updateCounter() {
      let blocked = 0;
      for (let i = 0; i < pos; i++) if (events[i].action === 'block') blocked++;
      $('counter').textContent = `${pos} / ${total} processed · ${blocked} blocked`;
      $('bar').style.width = (total ? (pos / total) * 100 : 0) + '%';
    }
    function step() {
      if (pos >= total) { pause(); return; }
      addEvent(events[pos]); pos++;
      updateCounter(); drawRace(true);
      if (pos >= total) pause();
    }
    const speed = () => +$('speed').value || 1;
    function schedule() { clearInterval(timer); timer = setInterval(step, 120 / speed()); }
    function play() {
      if (pos >= total) restart(true);
      if (!total) return;
      playing = true; $('play').textContent = 'Pause'; schedule();
    }
    function pause() { playing = false; clearInterval(timer); $('play').textContent = pos >= total && total ? 'Replay' : 'Play'; }
    function restart(keep) {
      clearInterval(timer); pos = 0;
      stream.selectAll('.tile').remove(); redlog.selectAll('.flag').remove();
      if (redlog.select('#redempty').empty()) redlog.append('div').attr('class', 'empty').attr('id', 'redempty').text('No blocked requests yet.');
      updateCounter(); drawRace(false);
      if (keep === true) return;
      playing = false; $('play').textContent = 'Play';
    }
    $('play').onclick = () => (playing ? pause() : play());
    $('restart').onclick = () => { restart(); play(); };
    $('speed').onchange = () => { if (playing) schedule(); };

    updateCounter(); drawRace(false);
    play();
  }
})();
