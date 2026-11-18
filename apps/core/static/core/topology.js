/* Network VMap topology view. Plain SVG, no libraries.
   Data:  GET  /topology/data/<kind>/?site=&endpoints=1  -> {nodes, links}
   Saves: POST /topology/layout/save/  {id, name, kind, site, positions, hidden, labels, options}
   Interaction: drag nodes, drag background to pan, wheel to zoom, hover a port dot / link / node for details,
   click a node for its panel, right-click for hide / pin / rename / icon / draw a link, right-click the background to add a note
   or a custom node (ISP, firewall, cloud, unmanaged switch). Grouping, colouring and custom objects live in the layout options. */
(function () {
  var root = document.getElementById('topo');
  if (!root) return;
  var KIND = root.dataset.kind, CAN_EDIT = root.dataset.edit === '1', CSRF = root.dataset.csrf;
  var svg = root.querySelector('svg'), vp = svg.querySelector('#vp'), gL = vp.querySelector('.g-links'), gP = vp.querySelector('.g-ports'),
      gN = vp.querySelector('.g-nodes'), gG = vp.querySelector('.g-groups'), gT = vp.querySelector('.g-notes'), tip = root.querySelector('.topo-tip'), side = root.querySelector('.topo-side'),
      menu = root.querySelector('.topo-menu'), statusEl = document.getElementById('topo-status');
  var NS = 'http://www.w3.org/2000/svg';
  var layout = JSON.parse(document.getElementById('layout-json').textContent) || {};
  var state = {
    id: layout.id || null, name: layout.name || 'Default', site: layout.site || '',
    pos: layout.positions || {}, hidden: layout.hidden || [], labels: layout.labels || {},
    opt: Object.assign({endpoints: false, portLabels: false, linkLabels: true, groupBy: '', colorBy: '', icons: {},
                        custom: {nodes: [], links: [], notes: []}}, layout.options || {}),
    view: {x: 0, y: 0, k: 1}, data: {nodes: [], links: []}, byId: {}, sel: null, vlan: '', dirty: false
  };
  var siteSel = document.getElementById('topo-site');
  if (siteSel && state.site) siteSel.value = state.site;
  bindToggle('opt-endpoints', 'endpoints', true);
  bindToggle('opt-ports', 'portLabels');
  bindToggle('opt-linklabels', 'linkLabels');
  bindSelect('opt-group', 'groupBy');
  bindSelect('opt-color', 'colorBy');
  state.opt.custom = Object.assign({nodes: [], links: [], notes: []}, state.opt.custom || {});
  state.opt.icons = state.opt.icons || {};
  var linkFrom = null;          // node id while drawing a custom link

  function el(tag, attrs, parent) { var e = document.createElementNS(NS, tag); for (var k in attrs) e.setAttribute(k, attrs[k]); if (parent) parent.appendChild(e); return e; }
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]; }); }
  function bps(v) { v = +v || 0; var u = ['b/s', 'Kb/s', 'Mb/s', 'Gb/s', 'Tb/s'], i = 0; while (v >= 1000 && i < 4) { v /= 1000; i++; } return (i ? v.toFixed(1) : v.toFixed(0)) + ' ' + u[i]; }
  function spd(m) { if (!m) return ''; return m >= 1000 ? (m / 1000) + 'G' : m + 'M'; }
  function status(t) { if (statusEl) statusEl.textContent = t; }

  function bindToggle(id, key, reload) {
    var c = document.getElementById(id); if (!c) return;
    c.checked = !!state.opt[key];
    c.addEventListener('change', function () { state.opt[key] = c.checked; markDirty(); if (reload) load(); else render(); });
  }

  function bindSelect(id, key) {
    var c = document.getElementById(id); if (!c) return;
    c.value = state.opt[key] || '';
    c.addEventListener('change', function () { state.opt[key] = c.value; markDirty(); render(); });
  }

  // custom nodes and links drawn by people, merged into the discovered graph
  function mergeCustom(d) {
    state.opt.custom.nodes.forEach(function (c) {
      d.nodes.push({id: c.id, type: 'custom', label: c.label, kind: c.kind || 'cloud', ip: c.note || '', custom: true});
    });
    var ids = {}; d.nodes.forEach(function (n) { ids[n.id] = 1; });
    state.opt.custom.links.forEach(function (c, i) {
      if (ids[c.a] && ids[c.b]) d.links.push({id: 'cl' + i, source: c.a, target: c.b, mode: 'custom', up: true, custom: true, label: c.label || '', protocols: ['drawn']});
    });
    return d;
  }

  // ------------------------------------------------------------ data
  function load() {
    status('Loading…');
    var site = siteSel ? siteSel.value : '';
    fetch('/topology/data/' + KIND + '/?site=' + encodeURIComponent(site) + (state.opt.endpoints ? '&endpoints=1' : ''), {credentials: 'same-origin'})
      .then(function (r) { return r.json(); })
      .then(function (d) {
        d = mergeCustom(d);
        state.data = d; state.byId = {};
        d.nodes.forEach(function (n) { state.byId[n.id] = n; });
        var missing = d.nodes.filter(function (n) { return !state.pos[n.id]; });
        if (missing.length === d.nodes.length) tieredLayout(true); else if (missing.length) placeNew(missing);
        render(); if (!state.fitted) { fit(); state.fitted = true; }
        status(d.nodes.length + ' nodes, ' + d.links.length + ' links');
        renderHiddenList();
        if (!d.nodes.length) root.querySelector('.topo-empty').hidden = false;
      }).catch(function () { status('Could not load the topology.'); });
  }

  function visible(n) { return n && state.hidden.indexOf(n.id) < 0; }

  // ------------------------------------------------------------ layouts
  function tieredLayout(all) {
    var nodes = state.data.nodes.filter(visible), tiers = {};
    var adj = {};
    state.data.links.forEach(function (l) { (adj[l.source] = adj[l.source] || []).push(l.target); (adj[l.target] = adj[l.target] || []).push(l.source); });
    var endpoints = [];
    nodes.forEach(function (n) {
      if (n.type === 'external' && (n.kind === 'phone' || n.kind === 'ap' || n.kind === 'host' || n.kind === 'unknown') && (adj[n.id] || []).length === 1) { endpoints.push(n); return; }
      var t = n.tier == null ? 2 : n.tier; (tiers[t] = tiers[t] || []).push(n);
    });
    var keys = Object.keys(tiers).map(Number).sort(function (a, b) { return a - b; });
    var gapX = KIND === 'l3' ? 190 : 170, gapY = 170, order = {};
    keys.forEach(function (t, ti) {
      var row = tiers[t];
      if (ti > 0) {   // barycentre ordering against the tier above
        row.forEach(function (n) {
          var ps = (adj[n.id] || []).filter(function (p) { return order[p] != null; }).map(function (p) { return order[p]; });
          n._bc = ps.length ? ps.reduce(function (a, b) { return a + b; }, 0) / ps.length : 1e9;
        });
        row.sort(function (a, b) { return a._bc - b._bc || String(a.label).localeCompare(b.label); });
      } else row.sort(function (a, b) { return String(a.label).localeCompare(b.label); });
      row.forEach(function (n, i) {
        order[n.id] = i - (row.length - 1) / 2;
        state.pos[n.id] = [order[n.id] * gapX, ti * gapY];
      });
    });
    var byParent = {};
    endpoints.forEach(function (n) { var p = adj[n.id][0]; (byParent[p] = byParent[p] || []).push(n); });
    Object.keys(byParent).forEach(function (p) {
      var kids = byParent[p], pp = state.pos[p] || [0, keys.length * gapY], per = 6;
      kids.forEach(function (n, i) {
        var row = Math.floor(i / per), col = i % per, cnt = Math.min(per, kids.length - row * per);
        state.pos[n.id] = [pp[0] + (col - (cnt - 1) / 2) * 62, pp[1] + 120 + row * 64];
      });
    });
    if (!all) markDirty();
  }

  function placeNew(list) {
    list.forEach(function (n) {
      var nb = state.data.links.filter(function (l) { return l.source === n.id || l.target === n.id; })
        .map(function (l) { return state.pos[l.source === n.id ? l.target : l.source]; }).filter(Boolean);
      var base = nb.length ? nb[0] : [0, 0];
      state.pos[n.id] = [base[0] + (Math.random() - .5) * 160, base[1] + 120 + Math.random() * 40];
    });
  }

  function forceLayout() {
    var nodes = state.data.nodes.filter(visible), links = state.data.links.filter(function (l) { return visible(state.byId[l.source]) && visible(state.byId[l.target]); });
    var P = {}; nodes.forEach(function (n) { var p = state.pos[n.id] || [Math.random() * 400, Math.random() * 400]; P[n.id] = {x: p[0], y: p[1], vx: 0, vy: 0}; });
    for (var it = 0; it < 320; it++) {
      var alpha = 1 - it / 320;
      for (var i = 0; i < nodes.length; i++) for (var j = i + 1; j < nodes.length; j++) {
        var a = P[nodes[i].id], b = P[nodes[j].id], dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy + .01, f = 9000 / d2;
        var d = Math.sqrt(d2); dx /= d; dy /= d; a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
      }
      links.forEach(function (l) {
        var a = P[l.source], b = P[l.target]; if (!a || !b) return;
        var dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) + .01, want = (state.byId[l.target].type === 'external' ? 90 : 160), f = (d - want) * .04;
        dx /= d; dy /= d; a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
      });
      nodes.forEach(function (n) { var p = P[n.id]; if (n._pin) { p.vx = p.vy = 0; return; } p.x += Math.max(-30, Math.min(30, p.vx)) * alpha; p.y += Math.max(-30, Math.min(30, p.vy)) * alpha; p.vx *= .5; p.vy *= .5; });
    }
    nodes.forEach(function (n) { state.pos[n.id] = [Math.round(P[n.id].x), Math.round(P[n.id].y)]; });
    markDirty(); render(); fit();
  }

  // ------------------------------------------------------------ rendering
  var GLYPH = {
    switch: 'M-13 -4h26M-13 4h26M7 -8l6 4-6 4M-7 0l-6 4 6 4',
    router: 'M-9 0h18M0 -9v18M5 -5l4 5-4 5M-5 -5l-4 5 4 5',
    subnet: 'M-11 5a5 5 0 0 1 1-10 7 7 0 0 1 13-1 5 5 0 0 1 8 6z',
    phone: 'M-6 -9h12v18h-12zM-3 6h6',
    ap: 'M-9 -2a13 13 0 0 1 18 0M-5 2a7 7 0 0 1 10 0M0 6h.01',
    host: 'M-10 -7h20v12h-20zM-4 9h8',
    unknown: 'M-3 -4a3 3 0 1 1 3 3v2M0 6h.01',
    cloud: 'M-11 5a5 5 0 0 1 1-10 7 7 0 0 1 13-1 5 5 0 0 1 8 6z',
    internet: 'M0 -10a10 10 0 1 0 .01 0M-10 0h20M0 -10c-5 5-5 15 0 20M0 -10c5 5 5 15 0 20',
    firewall: 'M-11 -8h22v16h-22zM-11 -3h22M-11 3h22M-4 -8v5M4 -3v6M-4 3v5',
    server: 'M-8 -10h16v20h-16zM-8 -3h16M-8 4h16M-4 -6.5h.01M-4 .5h.01',
    wan: 'M-11 0h22M-6 -6l-5 6 5 6M6 -6l5 6-5 6'
  };
  var VENDOR_COLORS = {Cisco: '#1ba0d7', Aruba: '#ff8300', 'HPE Aruba': '#ff8300', Huawei: '#e40c2b', Juniper: '#84b135', Arista: '#2d5ca8', Fortinet: '#da291c'};
  function nodeColor(n) {
    var c = state.opt.colorBy;
    if (!c || n.custom) return '';
    if (c === 'vendor') return VENDOR_COLORS[n.vendor] || '#8a8f98';
    var v = c === 'security' ? n.security : c === 'health' ? n.health : null;
    if (c === 'status') return {up: '#22a06b', down: '#e5484d', unreachable: '#e5484d', auth_failed: '#f5a524'}[n.status] || '#8a8f98';
    if (v == null) return '#8a8f98';
    return v >= 85 ? '#22a06b' : v >= 65 ? '#f5a524' : '#e5484d';
  }
  function groupOf(n) {
    var g = state.opt.groupBy;
    if (!g || n.type === 'subnet' || n.type === 'endpoint' || n.custom) return '';
    return n[g] || '';
  }

  function render() {
    gL.textContent = ''; gP.textContent = ''; gN.textContent = ''; if (gG) gG.textContent = ''; if (gT) gT.textContent = '';
    state.groups = {};
    if (state.opt.groupBy && gG) {
      state.data.nodes.forEach(function (n) { var g = groupOf(n); if (g && visible(n)) (state.groups[g] = state.groups[g] || {nodes: []}).nodes.push(n); });
      Object.keys(state.groups).forEach(function (g) {
        var grp = state.groups[g];
        grp.rect = el('rect', {'class': 'tg-box', rx: 14}, gG);
        grp.text = el('text', {'class': 'tg-label'}, gG); grp.text.textContent = g;
      });
    }
    var pair = {};
    state.data.links.forEach(function (l) {
      if (!visible(state.byId[l.source]) || !visible(state.byId[l.target])) return;
      var k = [l.source, l.target].sort().join('|'); (pair[k] = pair[k] || []).push(l);
    });
    Object.keys(pair).forEach(function (k) { var g = pair[k]; g.forEach(function (l, i) { l._off = (i - (g.length - 1) / 2) * 16; }); });
    state.data.links.forEach(function (l) {
      if (!visible(state.byId[l.source]) || !visible(state.byId[l.target])) return;
      if (l.custom) {
        l._el = el('path', {'class': 'tl tl-custom'}, gL);
        l._hit = el('path', {'class': 'tl-hit'}, gL);
        l._hit.addEventListener('mousemove', function (e) { showTip(e, '<h4>Drawn link</h4><dl>' + row('Between', (state.labels[l.source] || state.byId[l.source].label) + ' and ' + (state.labels[l.target] || state.byId[l.target].label)) + row('Note', l.label) + '</dl>' + (CAN_EDIT ? '<p class="muted small">Right-click to edit or delete.</p>' : '')); });
        l._hit.addEventListener('mouseleave', hideTip);
        l._hit.addEventListener('contextmenu', function (e) { e.preventDefault(); if (CAN_EDIT) linkMenu(e, l); });
        if (l.label) { l._lbl = el('text', {'class': 'tlbl', 'text-anchor': 'middle'}, gL); l._lbl.textContent = l.label; }
        return;
      }
      var cls = 'tl tl-' + l.mode + (l.up ? '' : ' tl-down') + ((l.issues || []).length ? ' tl-issue' : '') + (l.port_channel ? ' tl-pc' : '') + (l.ospf ? ' ospf' : '');
      l._el = el('path', {'class': cls}, gL);
      l._hit = el('path', {'class': 'tl-hit'}, gL);
      l._hit.addEventListener('mousemove', function (e) { showTip(e, linkTip(l)); });
      l._hit.addEventListener('mouseleave', hideTip);
      if ((l.issues || []).length) l._mark = el('circle', {'class': 'tl-issue-mark', r: 5}, gL);
      if (state.opt.linkLabels && !(l.port_channel && l._off > 0)) {
        var t = KIND === 'l3' ? (l.mode === 'routed' ? l.subnet : '') : [l.port_channel, spd(l.speed)].filter(Boolean).join(' · ');
        if (t) { l._lbl = el('text', {'class': 'tlbl', 'text-anchor': 'middle'}, gL); l._lbl.textContent = t; }
      }
      ['a', 'b'].forEach(function (side) {
        var p = l[side], nodeId = side === 'a' ? l.source : l.target, port = side === 'a' ? l.source_port : l.target_port;
        if (!port) return;
        var iss = l[side + '_issues'] || [];
        var pm = p && p.mode && p.mode !== 'unknown' && p.mode !== 'virtual' ? p.mode : l.mode;
        var blk = p && p.stp_blocked && p.stp_blocked.length;
        var c = el('circle', {r: 4.5, 'class': 'tp tp-' + pm + (iss.length ? ' tp-bad' : '') + (blk ? ' tp-blk' : '')}, gP);
        if (blk) l['_blk' + side] = p.stp_blocked;
        c.addEventListener('mousemove', function (e) { showTip(e, portTip(l, side)); });
        c.addEventListener('mouseleave', hideTip);
        l['_p' + side] = c;
        if (state.opt.portLabels) { var tx = el('text', {'class': 'tpl', 'text-anchor': 'middle'}, gP); tx.textContent = port; l['_t' + side] = tx; }
      });
    });
    state.data.nodes.forEach(function (n) {
      if (!visible(n)) return;
      var g = el('g', {'class': 'tn t-' + n.type + ' k-' + n.kind + ' st-' + (n.status || 'unknown') + (state.sel === n.id ? ' sel' : '') + (n._pin ? ' pinned' : '')}, gN);
      var w = n.type === 'subnet' ? 54 : 46, h = 34;
      var box = el('rect', {'class': 'box', x: -w / 2, y: -h / 2, width: w, height: h, rx: n.kind === 'router' ? 17 : 8}, g);
      var col = nodeColor(n); if (col) { box.style.stroke = col; box.style.strokeWidth = '2.5'; }
      el('path', {'class': 'glyph', d: GLYPH[state.opt.icons[n.id] || n.kind] || GLYPH.unknown}, g);
      var name = el('text', {'class': 'name', y: h / 2 + 14, 'text-anchor': 'middle'}, g); name.textContent = state.labels[n.id] || n.label;
      var sub = el('text', {'class': 'sub', y: h / 2 + 27, 'text-anchor': 'middle'}, g);
      sub.textContent = n.type === 'subnet' ? (n.vlan ? 'VLAN ' + n.vlan : ((n.members || []).length === 1 ? 'edge / upstream' : (n.members || []).length + ' members')) : (n.ip || '');
      if (n.alerts) { el('circle', {'class': 'badge-a', cx: w / 2 - 2, cy: -h / 2 + 2, r: 8}, g); var bt = el('text', {'class': 'badge-t', x: w / 2 - 2, y: -h / 2 + 5.5, 'text-anchor': 'middle'}, g); bt.textContent = n.alerts > 99 ? '99+' : n.alerts; }
      el('circle', {'class': 'pin', cx: -w / 2 + 2, cy: -h / 2 + 2, r: 4}, g);
      n._el = g;
      g.addEventListener('mousedown', function (e) { startDrag(e, n); });
      g.addEventListener('mousemove', function (e) { if (!drag) showTip(e, nodeTip(n)); });
      g.addEventListener('mouseleave', hideTip);
      g.addEventListener('click', function (e) {
        if (moved) return; e.stopPropagation();
        if (linkFrom) {
          if (linkFrom !== n.id) { var lbl = prompt('Optional note on this link (e.g. "ISP-A 1 Gb/s circuit 44821"):', '') || ''; state.opt.custom.links.push({a: linkFrom, b: n.id, label: lbl}); markDirty(); }
          linkFrom = null; svg.classList.remove('linking'); load(); return;
        }
        select(n);
      });
      g.addEventListener('dblclick', function (e) { if (n.device_id) location.href = '/devices/' + n.device_id + '/'; e.stopPropagation(); });
      g.addEventListener('contextmenu', function (e) { e.preventDefault(); openMenu(e, n); });
    });
    (state.opt.custom.notes || []).forEach(function (nt) {
      if (!gT) return;
      var g = el('g', {'class': 'tnote'}, gT), lines = String(nt.text || '').split('\n');
      var w = Math.max.apply(null, lines.map(function (x) { return x.length; })) * 6.6 + 18, h = lines.length * 15 + 12;
      el('rect', {x: 0, y: 0, width: w, height: h, rx: 6}, g);
      lines.forEach(function (ln, i) { var t = el('text', {x: 9, y: 19 + i * 15}, g); t.textContent = ln; });
      g.setAttribute('transform', 'translate(' + nt.x + ',' + nt.y + ')');
      nt._el = g;
      g.addEventListener('mousedown', function (e) { if (e.button !== 0 || !CAN_EDIT) return; e.stopPropagation(); var p = pt(e); drag = {note: nt, dx: p[0] - nt.x, dy: p[1] - nt.y}; moved = false; });
      g.addEventListener('dblclick', function (e) { e.stopPropagation(); if (!CAN_EDIT) return; var v = prompt('Note text (use \\n for a new line):', nt.text.replace(/\n/g, '\\n')); if (v === null) return; nt.text = v.replace(/\\n/g, '\n'); markDirty(); render(); });
      g.addEventListener('contextmenu', function (e) { e.preventDefault(); e.stopPropagation(); if (!CAN_EDIT) return; if (confirm('Delete this note?')) { state.opt.custom.notes = state.opt.custom.notes.filter(function (x) { return x !== nt; }); markDirty(); render(); } });
    });
    update();
    applyVlan();
    applyPathHighlight();
  }

  var HL = (new URLSearchParams(location.search).get('hl') || '').split(',').filter(Boolean).map(function (x) { return 'd' + x; });
  function applyPathHighlight() {
    if (!HL.length) return;
    var on = {}; HL.forEach(function (id) { on[id] = 1; });
    state.data.nodes.forEach(function (n) { if (n._el) n._el.classList.toggle('dim', !on[n.id]); });
    state.data.links.forEach(function (l) {
      if (!l._el) return;
      var i = HL.indexOf(l.source), j = HL.indexOf(l.target), hit = i >= 0 && j >= 0 && Math.abs(i - j) === 1;
      [l._el, l._pa, l._pb, l._ta, l._tb, l._lbl].forEach(function (x) { if (x) x.classList.toggle('dim', !hit); });
      l._el.classList.toggle('hl', hit);
    });
  }

  function update() {
    state.data.links.forEach(function (l) {
      if (!l._el) return;
      var a = state.pos[l.source], b = state.pos[l.target]; if (!a || !b) return;
      var dx = b[0] - a[0], dy = b[1] - a[1], d = Math.sqrt(dx * dx + dy * dy) || 1, nx = -dy / d, ny = dx / d;
      var cx = (a[0] + b[0]) / 2 + nx * l._off * 2, cy = (a[1] + b[1]) / 2 + ny * l._off * 2;
      var path = 'M' + a[0] + ' ' + a[1] + ' Q' + cx + ' ' + cy + ' ' + b[0] + ' ' + b[1];
      l._el.setAttribute('d', path); l._hit.setAttribute('d', path);
      var mx = .25 * a[0] + .5 * cx + .25 * b[0], my = .25 * a[1] + .5 * cy + .25 * b[1];
      if (l._mark) { l._mark.setAttribute('cx', mx); l._mark.setAttribute('cy', my); }
      if (l._lbl) { l._lbl.setAttribute('x', mx); l._lbl.setAttribute('y', my - 6); }
      [['a', a], ['b', b]].forEach(function (s) {
        var c = l['_p' + s[0]]; if (!c) return;
        var px = s[1][0], py = s[1][1], ux = cx - px, uy = cy - py, ud = Math.sqrt(ux * ux + uy * uy) || 1;
        var r = Math.min(34, ud * .45);
        c.setAttribute('cx', px + ux / ud * r); c.setAttribute('cy', py + uy / ud * r);
        var t = l['_t' + s[0]]; if (t) { var r2 = Math.min(56, ud * .6); t.setAttribute('x', px + ux / ud * r2); t.setAttribute('y', py + uy / ud * r2 + 3); }
      });
    });
    state.data.nodes.forEach(function (n) { if (n._el && state.pos[n.id]) n._el.setAttribute('transform', 'translate(' + state.pos[n.id][0] + ',' + state.pos[n.id][1] + ')'); });
    Object.keys(state.groups || {}).forEach(function (g) {
      var grp = state.groups[g], xs = [], ys = [];
      grp.nodes.forEach(function (n) { var p = state.pos[n.id]; if (p) { xs.push(p[0]); ys.push(p[1]); } });
      if (!xs.length) return;
      var x0 = Math.min.apply(null, xs) - 50, x1 = Math.max.apply(null, xs) + 50, y0 = Math.min.apply(null, ys) - 42, y1 = Math.max.apply(null, ys) + 56;
      grp.rect.setAttribute('x', x0); grp.rect.setAttribute('y', y0); grp.rect.setAttribute('width', x1 - x0); grp.rect.setAttribute('height', y1 - y0);
      grp.text.setAttribute('x', x0 + 12); grp.text.setAttribute('y', y0 + 17);
    });
  }

  function applyView() { vp.setAttribute('transform', 'translate(' + state.view.x + ',' + state.view.y + ') scale(' + state.view.k + ')'); }

  function fit() {
    var xs = [], ys = [];
    state.data.nodes.forEach(function (n) { if (visible(n) && state.pos[n.id]) { xs.push(state.pos[n.id][0]); ys.push(state.pos[n.id][1]); } });
    if (!xs.length) { state.view = {x: svg.clientWidth / 2, y: 80, k: 1}; return applyView(); }
    var minx = Math.min.apply(null, xs) - 120, maxx = Math.max.apply(null, xs) + 80, miny = Math.min.apply(null, ys) - 60, maxy = Math.max.apply(null, ys) + 150;
    var W = svg.clientWidth, H = svg.clientHeight, k = Math.min(1.6, Math.min(W / (maxx - minx), H / (maxy - miny)));
    state.view = {k: k, x: (W - (maxx + minx) * k) / 2, y: (H - (maxy + miny) * k) / 2};
    applyView();
  }

  // ------------------------------------------------------------ tooltips
  function showTip(e, html) {
    tip.innerHTML = html; tip.hidden = false;
    var r = root.getBoundingClientRect(), x = e.clientX - r.left + 14, y = e.clientY - r.top + 14;
    if (x + tip.offsetWidth > r.width - 8) x = e.clientX - r.left - tip.offsetWidth - 14;
    if (y + tip.offsetHeight > r.height - 8) y = Math.max(4, e.clientY - r.top - tip.offsetHeight - 14);
    tip.style.left = x + 'px'; tip.style.top = y + 'px';
  }
  function hideTip() { tip.hidden = true; }
  function row(k, v) { return v === '' || v == null ? '' : '<dt>' + esc(k) + '</dt><dd>' + esc(v) + '</dd>'; }
  function modePill(m) { return '<span class="mode-pill mode-' + esc(m || 'unknown') + '">' + esc(m || 'unknown') + '</span>'; }

  function portTip(l, side) {
    var p = l[side], node = state.byId[side === 'a' ? l.source : l.target], other = state.byId[side === 'a' ? l.target : l.source];
    var port = side === 'a' ? l.source_port : l.target_port, oport = side === 'a' ? l.target_port : l.source_port;
    var iss = l[side + '_issues'] || [];
    var h = '<h4>' + esc(state.labels[node.id] || node.label) + ' <span class="mono">' + esc(port) + '</span> ' + modePill(p ? p.mode : l.mode) + '</h4><dl>';
    if (p) {
      h += row('Status', (p.up ? 'up' : 'down') + (p.status ? ' (' + p.status + ')' : ''));
      h += row('Description', p.description);
      h += row('Speed / duplex', [p.speed, p.duplex].filter(Boolean).join(' / '));
      if (p.mode === 'access') { h += row('VLAN', p.access_vlan); h += row('Voice VLAN', p.voice_vlan); }
      if (p.mode === 'trunk') { h += row('Native VLAN', p.native_vlan); h += row('Allowed VLANs', p.trunk_vlans || 'all'); }
      h += row('IP', p.ip);
      h += row('Port-channel', p.port_channel);
      h += row('Media', p.media);
      h += row('Traffic in / out', bps(p.in_bps) + ' / ' + bps(p.out_bps));
      if (p.util != null) h += row('Utilisation', p.util + '%');
      h += row('CRC / in err / out err', [p.crc, p.in_errors, p.out_errors].join(' / '));
      if (p.drops) h += row('Output drops', p.drops);
      if (p.late_collisions) h += row('Late collisions', p.late_collisions);
      h += row('MTU', p.mtu);
      if (p.optic || p.rx != null) h += row('Optic', (p.optic || '') + (p.rx != null ? '  rx ' + p.rx + ' / tx ' + p.tx + ' dBm' : ''));
      if (p.poe) h += row('PoE', p.poe);
      if (p.stp_blocked && p.stp_blocked.length) h += row('Spanning tree', 'blocking in VLAN ' + p.stp_blocked.join(', '));
    } else h += row('Port', port + ' (not managed: no counters)');
    h += row('Connected to', (state.labels[other.id] || other.label) + (oport ? ' ' + oport : ''));
    h += row('Learned by', (l.protocols || []).join(', ').toUpperCase());
    h += '</dl>';
    if (iss.length) h += '<div class="iss">' + iss.map(function (i) { return '⚠ ' + esc(i.title); }).join('<br>') + '</div>';
    return h;
  }
  function linkTip(l) {
    var a = state.byId[l.source], b = state.byId[l.target];
    var h = '<h4>' + modePill(l.mode) + ' link</h4><dl>';
    h += row(state.labels[a.id] || a.label, l.source_port);
    h += row(state.labels[b.id] || b.label, l.target_port || (l.subnet || ''));
    if (l.subnet) h += row('Subnet', l.subnet);
    if (l.speed) h += row('Speed', spd(l.speed));
    if (l.util) h += row('Utilisation', l.util + '%');
    h += row('Port-channel', l.port_channel);
    if (l.a && l.a.mode === 'trunk') h += row('VLANs', l.a.trunk_vlans || 'all');
    if (l.a && l.a.mode === 'access') h += row('VLAN', l.a.access_vlan);
    h += row('State', l.up ? 'up' : 'down');
    if (l.ospf) h += row('Routing', 'OSPF adjacency');
    h += '</dl>';
    if ((l.issues || []).length) h += '<div class="iss">' + l.issues.map(function (i) { return '⚠ ' + esc(i.title); }).join('<br>') + '</div>';
    return h + '<p class="muted small" style="margin:6px 0 0">Hover the dots at each end for port details.</p>';
  }
  function nodeTip(n) {
    var h = '<h4>' + esc(state.labels[n.id] || n.label) + '</h4><dl>';
    if (n.type === 'subnet') {
      h += row('Subnet', n.label); h += row('VLAN', n.vlan);
      (n.members || []).forEach(function (m) { h += row(m.device, m.ip + ' (' + m.port + ')'); });
      return h + '</dl>';
    }
    h += row('Address', n.ip); h += row('Model', n.model); h += row('Software', n.version); h += row('Role', n.role);
    h += row('Site', n.site); h += row('Status', n.status);
    if (n.type === 'device') {
      h += row('Security score', n.security == null ? '–' : n.security); h += row('Interface health', n.health == null ? '–' : n.health);
      if (n.routes != null) h += row('Routes', n.routes + ' (' + Object.keys(n.route_counts || {}).map(function (k) { return k + ' ' + n.route_counts[k]; }).join(', ') + ')');
      if (n.loopbacks && n.loopbacks.length) h += row('Loopbacks', n.loopbacks.join(', '));
      if (n.default_via) h += row('Default via', n.default_via);
      h += row('Open alerts', n.alerts || 0);
    } else h += row('Managed', n.managed_elsewhere ? 'yes (other site)' : 'no — seen through CDP/LLDP');
    return h + '</dl><p class="muted small" style="margin:6px 0 0">Click for details, double-click to open, right-click for options.</p>';
  }

  // ------------------------------------------------------------ side panel & menu
  function select(n) {
    state.sel = n ? n.id : null;
    gN.querySelectorAll('.tn').forEach(function (g) { g.classList.remove('sel'); });
    if (!n) { side.hidden = true; return; }
    n._el.classList.add('sel');
    var links = state.data.links.filter(function (l) { return l.source === n.id || l.target === n.id; });
    var h = '<button class="help-close" data-close-side>×</button><h3>' + esc(state.labels[n.id] || n.label) + '</h3><p class="muted small" style="margin:0 0 10px">' + esc(n.model || n.kind) + '</p><dl class="kv-list">';
    h += row('Address', n.ip) + row('Software', n.version) + row('Role', n.role) + row('Status', n.status) + row('Site', n.site);
    h += '</dl><h3 style="margin-top:14px">Connections (' + links.length + ')</h3><table class="tbl compact"><tbody>';
    links.forEach(function (l) {
      var mine = l.source === n.id, o = state.byId[mine ? l.target : l.source];
      h += '<tr><td class="mono">' + esc(mine ? l.source_port : l.target_port) + '</td><td>' + modePill(l.mode) + '</td><td>' + esc(state.labels[o.id] || o.label) + ' <span class="muted mono">' + esc(mine ? l.target_port : l.source_port) + '</span></td></tr>';
    });
    h += '</tbody></table><div class="actions" style="margin-top:12px">';
    if (n.device_id) h += '<a class="btn btn-sm btn-primary" href="/devices/' + n.device_id + '/">Open device</a>';
    if (CAN_EDIT) h += '<button class="btn btn-sm" data-act="rename">Rename</button><button class="btn btn-sm" data-act="hide">Hide</button>';
    h += '</div>';
    side.innerHTML = h; side.hidden = false;
    side.querySelector('[data-close-side]').onclick = function () { select(null); };
    side.querySelectorAll('[data-act]').forEach(function (b) { b.onclick = function () { act(b.dataset.act, n); }; });
  }
  function openMenu(e, n) {
    if (!CAN_EDIT && !n.device_id) return;
    var r = root.getBoundingClientRect(), h = '';
    if (n.device_id) h += '<button data-act="open">Open device page</button>';
    if (CAN_EDIT) h += '<button data-act="rename">Rename on this map</button><button data-act="pin">' + (n._pin ? 'Unpin' : 'Pin (force layout keeps it)') + '</button><button data-act="hide">Hide from this map</button><button data-act="neighbours">Show only this and its neighbours</button>' +
      '<button data-act="link">Draw a link from here…</button><button data-act="icon">Change icon…</button>' + (n.custom ? '<button data-act="delcustom">Delete this custom node</button>' : '');
    menu.innerHTML = h; menu.hidden = false; menu.style.left = (e.clientX - r.left) + 'px'; menu.style.top = (e.clientY - r.top) + 'px';
    menu.querySelectorAll('button').forEach(function (b) { b.onclick = function () { menu.hidden = true; act(b.dataset.act, n); }; });
  }
  function act(a, n) {
    if (a === 'link') { linkFrom = n.id; status('Click the node to connect ' + (state.labels[n.id] || n.label) + ' to (Esc to cancel)'); svg.classList.add('linking'); return; }
    if (a === 'icon') {
      var choices = ['switch', 'router', 'firewall', 'server', 'cloud', 'internet', 'wan', 'ap', 'phone', 'host'];
      var v = prompt('Icon (' + choices.join(', ') + '), empty = automatic:', state.opt.icons[n.id] || ''); if (v === null) return;
      v = v.trim().toLowerCase(); if (v && choices.indexOf(v) < 0) { alert('Unknown icon: ' + v); return; }
      if (v) state.opt.icons[n.id] = v; else delete state.opt.icons[n.id];
      if (n.custom) { state.opt.custom.nodes.forEach(function (c) { if (c.id === n.id && v) c.kind = v; }); }
      markDirty(); render(); return;
    }
    if (a === 'delcustom') {
      state.opt.custom.nodes = state.opt.custom.nodes.filter(function (c) { return c.id !== n.id; });
      state.opt.custom.links = state.opt.custom.links.filter(function (c) { return c.a !== n.id && c.b !== n.id; });
      select(null); markDirty(); load(); return;
    }
    if (a === 'open') location.href = '/devices/' + n.device_id + '/';
    if (a === 'rename') {
      var v = prompt('Label on this map (empty = device name):', state.labels[n.id] || n.label); if (v === null) return;
      if (n.custom) { state.opt.custom.nodes.forEach(function (c) { if (c.id === n.id && v.trim()) c.label = v.trim(); }); n.label = v.trim() || n.label; markDirty(); render(); return; }
      if (v.trim() && v !== n.label) state.labels[n.id] = v.trim(); else delete state.labels[n.id]; markDirty(); render();
    }
    if (a === 'pin') { n._pin = !n._pin; render(); }
    if (a === 'hide') { state.hidden.push(n.id); select(null); markDirty(); render(); renderHiddenList(); }
    if (a === 'neighbours') {
      var keep = {}; keep[n.id] = 1;
      state.data.links.forEach(function (l) { if (l.source === n.id) keep[l.target] = 1; if (l.target === n.id) keep[l.source] = 1; });
      state.hidden = state.data.nodes.filter(function (x) { return !keep[x.id]; }).map(function (x) { return x.id; });
      markDirty(); render(); fit(); renderHiddenList();
    }
  }
  function renderHiddenList() {
    var box = document.getElementById('topo-hidden'); if (!box) return;
    box.innerHTML = state.hidden.length ? state.hidden.length + ' hidden · <a href="#" id="unhide">show all</a>' : '';
    var u = document.getElementById('unhide'); if (u) u.onclick = function (e) { e.preventDefault(); state.hidden = []; markDirty(); render(); renderHiddenList(); };
  }

  // ------------------------------------------------------------ VLAN highlight & search
  function carries(p, v) {
    if (!p) return false;
    if (p.mode === 'access') return String(p.access_vlan) === v || String(p.voice_vlan) === v;
    if (p.mode === 'trunk') {
      var s = (p.trunk_vlans || '').toUpperCase().replace(/\s/g, '');
      if (!s || s === 'ALL') return true;
      return s.split(',').some(function (r) { var b = r.split('-'); var n = +v; return b.length === 2 ? n >= +b[0] && n <= +b[1] : +b[0] === n; });
    }
    return false;
  }
  function applyVlan() {
    var v = state.vlan;
    state.data.links.forEach(function (l) {
      if (!l._el) return;
      var on = !v || carries(l.a, v) || carries(l.b, v);
      [l._el, l._pa, l._pb, l._ta, l._tb].forEach(function (x) { if (x) x.classList.toggle('dim', !on); });
      l._el.classList.toggle('hl', !!v && on);
      var blocked = v && ((l._blka || []).concat(l._blkb || [])).map(String).indexOf(v) >= 0;
      l._el.classList.toggle('tl-stpblk', !!blocked);
    });
  }
  var vin = document.getElementById('topo-vlan');
  if (vin) vin.addEventListener('input', function () { state.vlan = vin.value.trim(); applyVlan(); });
  var fin = document.getElementById('topo-find');
  if (fin) fin.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter') return; e.preventDefault();
    var q = fin.value.trim().toLowerCase(); if (!q) return;
    var n = state.data.nodes.find(function (x) { return visible(x) && ((state.labels[x.id] || x.label).toLowerCase().indexOf(q) >= 0 || (x.ip || '').indexOf(q) === 0); });
    if (!n) { status('No node matches "' + q + '"'); return; }
    var p = state.pos[n.id], k = Math.max(state.view.k, 1.1);
    state.view = {k: k, x: svg.clientWidth / 2 - p[0] * k, y: svg.clientHeight / 2 - p[1] * k}; applyView(); select(n);
  });

  // ------------------------------------------------------------ drag / pan / zoom
  var drag = null, pan = null, moved = false;
  function pt(e) { var r = svg.getBoundingClientRect(); return [(e.clientX - r.left - state.view.x) / state.view.k, (e.clientY - r.top - state.view.y) / state.view.k]; }
  function startDrag(e, n) { if (e.button !== 0) return; e.stopPropagation(); hideTip(); moved = false; var p = pt(e); drag = {n: n, dx: p[0] - state.pos[n.id][0], dy: p[1] - state.pos[n.id][1]}; }
  svg.addEventListener('mousedown', function (e) { if (e.button !== 0) return; menu.hidden = true; moved = false; pan = {x: e.clientX - state.view.x, y: e.clientY - state.view.y}; svg.classList.add('panning'); });
  window.addEventListener('mousemove', function (e) {
    if (drag && drag.note) { var q = pt(e); drag.note.x = Math.round(q[0] - drag.dx); drag.note.y = Math.round(q[1] - drag.dy); drag.note._el.setAttribute('transform', 'translate(' + drag.note.x + ',' + drag.note.y + ')'); moved = true; }
    else if (drag) { var p = pt(e); state.pos[drag.n.id] = [Math.round(p[0] - drag.dx), Math.round(p[1] - drag.dy)]; moved = true; update(); }
    else if (pan) { state.view.x = e.clientX - pan.x; state.view.y = e.clientY - pan.y; moved = true; applyView(); }
  });
  window.addEventListener('mouseup', function () {
    if (drag && moved && CAN_EDIT) markDirty();
    if (drag && drag.note && moved) render();
    drag = null; if (pan) { svg.classList.remove('panning'); if (!moved) select(null); } pan = null;
    setTimeout(function () { moved = false; }, 0);
  });
  svg.addEventListener('wheel', function (e) {
    e.preventDefault();
    var r = svg.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top, k0 = state.view.k;
    var k = Math.max(.15, Math.min(4, k0 * (e.deltaY < 0 ? 1.12 : 1 / 1.12)));
    state.view.x = mx - (mx - state.view.x) * k / k0; state.view.y = my - (my - state.view.y) * k / k0; state.view.k = k; applyView();
  }, {passive: false});
  function zoom(f) { var W = svg.clientWidth / 2, H = svg.clientHeight / 2, k0 = state.view.k, k = Math.max(.15, Math.min(4, k0 * f)); state.view.x = W - (W - state.view.x) * k / k0; state.view.y = H - (H - state.view.y) * k / k0; state.view.k = k; applyView(); }
  document.addEventListener('click', function (e) { if (!menu.contains(e.target)) menu.hidden = true; });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && linkFrom) { linkFrom = null; svg.classList.remove('linking'); status(''); } });
  svg.addEventListener('contextmenu', function (e) {
    if (e.target.closest('.tn') || e.target.closest('.tnote') || e.target.classList.contains('tl-hit')) return;
    e.preventDefault(); if (!CAN_EDIT) return;
    var r = root.getBoundingClientRect(), at = pt(e);
    menu.innerHTML = '<button data-add="note">Add a note here</button><button data-add="internet">Add internet / ISP here</button><button data-add="firewall">Add a firewall here</button>' +
      '<button data-add="cloud">Add a cloud / WAN here</button><button data-add="server">Add a server here</button><button data-add="switch">Add an unmanaged switch here</button>';
    menu.hidden = false; menu.style.left = (e.clientX - r.left) + 'px'; menu.style.top = (e.clientY - r.top) + 'px';
    menu.querySelectorAll('button').forEach(function (b) {
      b.onclick = function () {
        menu.hidden = true;
        if (b.dataset.add === 'note') {
          var t = prompt('Note text (use \\n for a new line):', ''); if (!t) return;
          state.opt.custom.notes.push({id: 'n' + Date.now(), text: t.replace(/\\n/g, '\n'), x: Math.round(at[0]), y: Math.round(at[1])});
          markDirty(); render(); return;
        }
        var label = prompt('Name for this ' + b.dataset.add + ':', {internet: 'Internet', firewall: 'Firewall', cloud: 'WAN', server: 'Server', switch: 'Unmanaged switch'}[b.dataset.add]); if (!label) return;
        var id = 'c' + Date.now();
        state.opt.custom.nodes.push({id: id, label: label, kind: b.dataset.add});
        state.pos[id] = [Math.round(at[0]), Math.round(at[1])];
        markDirty(); load();
      };
    });
  });
  function linkMenu(e, l) {
    var r = root.getBoundingClientRect(), idx = +String(l.id).slice(2);
    menu.innerHTML = '<button data-a="edit">Edit the note on this link</button><button data-a="del">Delete this link</button>';
    menu.hidden = false; menu.style.left = (e.clientX - r.left) + 'px'; menu.style.top = (e.clientY - r.top) + 'px';
    menu.querySelectorAll('button').forEach(function (b) {
      b.onclick = function () {
        menu.hidden = true; var c = state.opt.custom.links[idx]; if (!c) return;
        if (b.dataset.a === 'del') state.opt.custom.links.splice(idx, 1);
        else { var v = prompt('Note on this link:', c.label || ''); if (v === null) return; c.label = v; }
        markDirty(); load();
      };
    });
  }

  // ------------------------------------------------------------ save
  var saveTimer;
  function markDirty() {
    if (!CAN_EDIT) return;
    state.dirty = true; status('Unsaved changes…');
    clearTimeout(saveTimer); saveTimer = setTimeout(save, 1200);
  }
  function save(asName) {
    if (!CAN_EDIT) return;
    var body = {id: asName ? null : state.id, name: asName || state.name, kind: KIND, site: siteSel ? siteSel.value : '',
                positions: state.pos, hidden: state.hidden, labels: state.labels, options: state.opt};
    return fetch('/topology/layout/save/', {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json', 'X-CSRFToken': CSRF}, body: JSON.stringify(body)})
      .then(function (r) { return r.json(); }).then(function (d) {
        if (d.id) { state.id = d.id; state.name = d.name; state.dirty = false; status('Layout "' + d.name + '" saved'); if (asName) location.href = '?layout=' + d.id; }
      });
  }

  // ------------------------------------------------------------ toolbar
  function on(id, fn) { var b = document.getElementById(id); if (b) b.addEventListener('click', fn); }
  on('btn-tiered', function () { tieredLayout(); render(); fit(); });
  on('btn-force', forceLayout);
  on('btn-fit', fit);
  on('btn-zin', function () { zoom(1.2); });
  on('btn-zout', function () { zoom(1 / 1.2); });
  on('btn-saveas', function () { var n = prompt('Save this layout as:', state.name === 'Default' ? '' : state.name + ' copy'); if (n && n.trim()) save(n.trim()); });
  on('btn-reload', load);
  on('btn-svg', exportSvg);
  if (siteSel) siteSel.addEventListener('change', function () { state.fitted = false; load(); markDirty(); });
  var laySel = document.getElementById('topo-layout');
  if (laySel) laySel.addEventListener('change', function () { location.href = laySel.value ? '?layout=' + laySel.value : '?'; });

  function exportSvg() {
    var clone = svg.cloneNode(true), css = '';
    var cs = getComputedStyle(document.documentElement);
    ['--trunk', '--access', '--routed', '--l3sub', '--panel', '--border', '--text', '--text-2', '--muted', '--bad', '--ok', '--faint', '--panel-2', '--info', '--warn', '--sans', '--mono'].forEach(function (v) { css += v + ':' + cs.getPropertyValue(v) + ';'; });
    var rules = [];
    for (var s = 0; s < document.styleSheets.length; s++) { try { [].forEach.call(document.styleSheets[s].cssRules, function (r) { if (/\.t[lnp]|\.tpl|\.tlbl|\.tn /.test(r.cssText)) rules.push(r.cssText); }); } catch (e) {} }
    var st = document.createElementNS(NS, 'style'); st.textContent = 'svg{' + css + '}' + rules.join('\n'); clone.insertBefore(st, clone.firstChild);
    clone.setAttribute('xmlns', NS); clone.setAttribute('width', svg.clientWidth); clone.setAttribute('height', svg.clientHeight);
    var blob = new Blob([new XMLSerializer().serializeToString(clone)], {type: 'image/svg+xml'});
    var a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'vmap-' + KIND + '-topology.svg'; a.click();
  }

  window.addEventListener('resize', applyView);
  load();
  setInterval(function () { if (!drag && !pan && !state.dirty && document.visibilityState === 'visible') refreshStatus(); }, 60000);
  function refreshStatus() {   // keep positions, refresh states and counters
    var site = siteSel ? siteSel.value : '';
    fetch('/topology/data/' + KIND + '/?site=' + encodeURIComponent(site) + (state.opt.endpoints ? '&endpoints=1' : ''), {credentials: 'same-origin'})
      .then(function (r) { return r.json(); }).then(function (d) {
        d = mergeCustom(d);
        var pins = {}; state.data.nodes.forEach(function (n) { if (n._pin) pins[n.id] = 1; });
        state.data = d; state.byId = {}; d.nodes.forEach(function (n) { state.byId[n.id] = n; if (pins[n.id]) n._pin = true; });
        var missing = d.nodes.filter(function (n) { return !state.pos[n.id]; }); if (missing.length) placeNew(missing);
        render(); if (state.sel && state.byId[state.sel]) select(state.byId[state.sel]);
      });
  }
})();
