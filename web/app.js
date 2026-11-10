const $ = (selector) => document.querySelector(selector);
const number = new Intl.NumberFormat("en-US");
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const state = {
  view: "network", page: 1, pageSize: 5, group: "All", protocol: "All", search: "",
  alpha: .05, logScale: true, data: null, angle: 0, tilt: -.22, zoom: 1,
  dragging: false, lastX: 0, lastY: 0, pointer: null, sceneStarted: 0,
  flowLoading: false, refreshing: false, flowLoadId: 0,
};
const sceneInfo = {
  network: ["TRAFFIC TOPOLOGY / 3D NETWORK MAP", "A living network"],
  packets: ["DISTRIBUTION / EXTRUDED PACKET BINS", "Packet volume"],
  protocols: ["PROTOCOL MIX / TRAFFIC COMPOSITION", "Protocol signatures"],
  flows: ["CONNECTION DETAIL / LIVE RECORDS", "Flow log"],
};
const cameraPresets = {
  network: { angle: 0, tilt: -.22, zoom: 1 },
  packets: { angle: 0, tilt: .4, zoom: 1 },
  protocols: { angle: 0, tilt: .4, zoom: 1 },
  flows: { angle: 0, tilt: -.22, zoom: 1 },
};
const canvas = $("#scene-canvas");
const ctx = canvas.getContext("2d");
let width = 0, height = 0, pixelRatio = 1, frame = 0, previousTime = 0;
let ambientFrame = 0;
let flowSearchTimer = 0;
let resumeAmbient = () => {};

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}
function fmt(value, digits = 1) {
  return Number.isFinite(Number(value)) ? Number(value).toLocaleString("en-US", { maximumFractionDigits: digits }) : "—";
}
function compact(value) {
  return new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(value);
}
function resetCamera(view = state.view) {
  Object.assign(state, cameraPresets[view] || cameraPresets.network);
}
async function refresh() {
  const requestId = ++state.flowLoadId;
  state.flowLoading = false;
  state.refreshing = true;
  $("#flow-view").setAttribute("aria-busy", "true");
  $("#flow-view").classList.add("is-filtering");
  const params = new URLSearchParams({
    alpha: state.alpha, top_n: 8, page: state.page, page_size: state.pageSize,
    group: state.group, protocol: state.protocol, search: state.search,
    aggregation: "median", log_scale: state.logScale,
  });
  try {
    const response = await fetch(`/api/dashboard?${params}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Dashboard data could not be loaded.");
    if (requestId !== state.flowLoadId) return;
    state.data = data;
    render(data);
  } catch (error) {
    if (requestId === state.flowLoadId) $("#notices").innerHTML = `<div class="notice">${esc(error.message)}</div>`;
  } finally {
    if (requestId === state.flowLoadId) {
      state.refreshing = false;
      $("#flow-view").setAttribute("aria-busy", "false");
      $("#flow-view").classList.remove("is-filtering");
    }
  }
}

function render(data) {
  const packets = data?.packets || { normal: { mean: 0 }, malicious: { mean: 0 } };
  const test = data?.test || { difference: 0, p: 1, t: 0, ci: [0, 0], cohens_d: 0, effect: "negligible", significant: false };
  const counts = data?.counts || { all: 0, normal: 0, malicious: 0 };
  const normalMean = Number(packets.normal?.mean ?? 0);
  const maliciousMean = Number(packets.malicious?.mean ?? 0);
  const packetMax = Math.max(normalMean, maliciousMean, 1);

  $("#source").textContent = (data?.source || "Synthetic demo data").toUpperCase();
  $("#source-detail").textContent = data?.source || "Synthetic demo data";
  animateNumber($("#total-count"), counts.all);
  animateNumber($("#normal-count"), counts.normal);
  animateNumber($("#malicious-count"), counts.malicious);
  $("#packet-gap").textContent = `${Number(test.difference || 0) > 0 ? "+" : ""}${compact(Number(test.difference || 0))}`;
  $("#mean-normal").style.width = `${(normalMean / packetMax) * 100}%`;
  $("#mean-malicious").style.width = `${(maliciousMean / packetMax) * 100}%`;
  $("#mean-normal-value").textContent = compact(normalMean);
  $("#mean-malicious-value").textContent = compact(maliciousMean);
  $("#p-value").textContent = Number(test.p || 1) < .001 ? "< .001" : fmt(Number(test.p || 1), 4);
  $("#t-stat").textContent = fmt(Number(test.t || 0), 3);
  $("#ci").textContent = `[${fmt(Number(test.ci?.[0] ?? 0))}, ${fmt(Number(test.ci?.[1] ?? 0))}]`;
  $("#effect").textContent = `${fmt(Number(test.cohens_d || 0), 3)} · ${test.effect || "negligible"}`;
  $("#test-decision").textContent = test.significant ? "SIGNIFICANT · REJECT H₀" : "NOT SIGNIFICANT · RETAIN H₀";
  $("#test-decision").classList.toggle("nonsig", !test.significant);
  renderTable(data?.table || { page: 1, page_size: 5, pages: 1, total: 0, records: [] });
  renderNotices(data || { source: "Synthetic demo data", duplicates: 0, issues: [] });
  state.sceneStarted = performance.now();
  animateSceneEntry();
  updateSceneLabels();
  drawScene();
}

function animateSceneEntry() {
  const scene = $(".scene");
  scene.classList.remove("scene-arrive");
  void scene.offsetWidth;
  scene.classList.add("scene-arrive");
}

function animateNumber(element, target) {
  if (reducedMotion.matches) {
    element.textContent = number.format(target);
    return;
  }
  const start = performance.now();
  const duration = 850;
  const from = Number(element.dataset.value || 0);
  element.dataset.value = String(target);
  const tick = (time) => {
    const progress = Math.min(1, (time - start) / duration);
    const eased = 1 - (1 - progress) ** 4;
    element.textContent = number.format(Math.round(from + (target - from) * eased));
    if (progress < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

function renderNotices(data) {
  const notices = [];
  if (data.source.startsWith("Synthetic")) {
    notices.push('<div class="notice demo">Synthetic demo data. Add UNSW-NB15 CSV files beside app.py or in data/ for real analysis.</div>');
  }
  if (data.duplicates) notices.push(`<div class="notice demo">Removed ${number.format(data.duplicates)} duplicate record(s).</div>`);
  for (const issue of data.issues) notices.push(`<div class="notice">${esc(issue)}</div>`);
  $("#notices").innerHTML = notices.join("");
}

function flowCards(records, table) {
  return records.map((record, index) => {
    const malicious = record.group === "Malicious";
    const packets = (Number(record.spkts) || 0) + (Number(record.dpkts) || 0);
    const signalDuration = Math.max(1.25, 4.2 - Math.log10(packets + 1)).toFixed(2);
    const flowLabel = `${malicious ? "Malicious" : "Normal"} ${record.proto || "unknown"} flow with ${number.format(packets)} packets, ${fmt(record.dur, 3)} seconds and ${compact((Number(record.sbytes) || 0) + (Number(record.dbytes) || 0))} bytes.`;
    const rowIndex = (table.page - 1) * table.page_size + index;
    return `<article class="flow-card ${malicious ? "is-malicious" : "is-normal"}" style="--card-index:${rowIndex % table.page_size};--flow-index:${rowIndex};--signal-duration:${signalDuration}s" tabindex="0" role="listitem" aria-label="${esc(flowLabel)}">` +
      `<div class="flow-card-top"><span class="flow-id">FLOW / ${String(rowIndex + 1).padStart(5, "0")}</span><span class="flow-class"><i></i>${malicious ? "MALICIOUS" : "NORMAL"}</span></div>` +
      `<div class="flow-card-main"><div class="flow-protocol"><small>PROTOCOL</small><b>${esc(record.proto || "unknown")}</b></div>` +
      `<div class="flow-measure"><small>PACKETS</small><b>${number.format(packets)}</b><span>${number.format(Number(record.spkts) || 0)} ↑ &nbsp; ${number.format(Number(record.dpkts) || 0)} ↓</span></div>` +
      `<div class="flow-measure"><small>DURATION</small><b>${fmt(record.dur, 3)}<em> sec</em></b></div>` +
      `<div class="flow-measure flow-volume"><small>PAYLOAD</small><b>${compact((Number(record.sbytes) || 0) + (Number(record.dbytes) || 0))}<em> bytes</em></b></div></div>` +
      `<div class="flow-signal" aria-hidden="true"><i></i><i></i></div></article>`;
  }).join("");
}

function updateFlowFooter(table) {
  const loaded = Math.min(table.page * table.page_size, table.total);
  $("#table-count").textContent = `${number.format(loaded)} / ${number.format(table.total)} FLOWS`;
  $("#next-page").hidden = loaded >= table.total;
  $("#next-page").disabled = state.flowLoading;
  $("#next-page").textContent = state.flowLoading ? "LOADING…" : "LOAD MORE";
}

function renderTable(table) {
  const deck = $("#flow-deck");
  const protocolFilter = $("#protocol-filter");
  const selectedProtocol = state.protocol;
  protocolFilter.innerHTML = '<option value="All">All</option>' +
    (table.protocols || []).map((protocol) => `<option value="${esc(protocol)}">${esc(protocol.toUpperCase())}</option>`).join("");
  protocolFilter.value = selectedProtocol;
  deck.innerHTML = table.records.length
    ? flowCards(table.records, table)
    : '<div class="flow-empty">No flows match this filter.</div>';
  deck.scrollTop = 0;
  updateFlowFooter(table);
}

async function loadMoreFlows() {
  const table = state.data?.table;
  if (!table || state.refreshing || state.flowLoading || state.page >= table.pages) return;

  const requestId = ++state.flowLoadId;
  const page = state.page + 1;
  state.flowLoading = true;
  updateFlowFooter(table);
  const params = new URLSearchParams({
    alpha: state.alpha, top_n: 8, page, page_size: state.pageSize,
    group: state.group, protocol: state.protocol, search: state.search,
    aggregation: "median", log_scale: state.logScale,
  });
  try {
    const response = await fetch(`/api/dashboard?${params}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "More flows could not be loaded.");
    if (requestId !== state.flowLoadId) return;
    state.page = page;
    state.data = data;
    const deck = $("#flow-deck");
    deck.querySelector(".flow-empty")?.remove();
    deck.insertAdjacentHTML("beforeend", flowCards(data.table.records, data.table));
    updateFlowFooter(data.table);
    updateSceneLabels();
  } catch (error) {
    if (requestId !== state.flowLoadId) return;
    $("#notices").innerHTML = `<div class="notice">${esc(error.message)}</div>`;
  } finally {
    if (requestId === state.flowLoadId) {
      state.flowLoading = false;
      if (state.data) updateFlowFooter(state.data.table);
    }
  }
}

function updateSceneLabels() {
  document.body.dataset.view = state.view;
  const details = {
    network: ["NORMAL NODES", "MALICIOUS NODES"],
    packets: ["NORMAL FLOWS", "MALICIOUS FLOWS"],
    protocols: ["NORMAL MIX", "MALICIOUS MIX"],
    flows: ["FILTER", "VISIBLE RECORDS"],
  }[state.view];
  $("#scene-label-a").textContent = details[0];
  $("#scene-label-b").textContent = details[1];
  $("#scene-number").textContent = String(["network", "packets", "protocols", "flows"].indexOf(state.view) + 1).padStart(2, "0");
  $("#scene-title").textContent = sceneInfo[state.view][1];
  $("#scene-kicker").textContent = sceneInfo[state.view][0];
  $("#scene").setAttribute("aria-label", `${sceneInfo[state.view][1]} view`);
  $("#scale-control").hidden = state.view !== "packets";
  $("#scene-note").textContent = state.view === "flows" ? "SCROLL WITHIN PANEL TO REVIEW RECORDS" : "DRAG TO ROTATE · SCROLL TO ZOOM";
  $("#scene-canvas").hidden = state.view === "flows";
  $("#scene-vignette").hidden = state.view === "flows";
  $("#flow-view").hidden = state.view !== "flows";
  $("#scene-value-a").textContent = state.view === "flows" ? state.group.toUpperCase() : $("#normal-count").textContent;
  const visibleFlows = state.data ? Math.min(state.page * state.pageSize, state.data.table.total) : 0;
  $("#scene-value-b").textContent = state.view === "flows" ? `${visibleFlows} SHOWN` : $("#malicious-count").textContent;
  const active = $(`.tab[data-view="${state.view}"]`);
  document.querySelectorAll(".tab").forEach((tab) => {
    const selected = tab === active;
    tab.classList.toggle("active", selected);
    tab.setAttribute("aria-selected", String(selected));
  });
  const indicator = $(".tab-indicator");
  indicator.style.left = `${active.offsetLeft}px`;
  indicator.style.width = `${active.offsetWidth}px`;
}

function resizeCanvas() {
  const rect = canvas.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  width = rect.width;
  height = rect.height;
  pixelRatio = Math.min(window.devicePixelRatio || 1, 1.6);
  canvas.width = Math.round(width * pixelRatio);
  canvas.height = Math.round(height * pixelRatio);
  ctx.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
  drawScene();
}

function project(point, scale = 1) {
  const cosY = Math.cos(state.angle), sinY = Math.sin(state.angle);
  const cosX = Math.cos(state.tilt), sinX = Math.sin(state.tilt);
  const x = point.x * cosY - point.z * sinY;
  const z = point.x * sinY + point.z * cosY;
  const y = point.y * cosX - z * sinX;
  const depth = point.y * sinX + z * cosX;
  const camera = 18;
  const perspective = camera / (camera - depth);
  const unit = Math.min(width, height) * .105 * state.zoom * scale;
  return { x: width * .51 + x * unit * perspective, y: height * .53 - y * unit * perspective, depth, perspective };
}

function polygon(points, color, alpha = 1) {
  ctx.beginPath();
  points.forEach((point, index) => index ? ctx.lineTo(point.x, point.y) : ctx.moveTo(point.x, point.y));
  ctx.closePath();
  ctx.globalAlpha = alpha;
  ctx.fillStyle = color;
  ctx.fill();
  ctx.globalAlpha = 1;
}

function line3d(a, b, color, alpha = 1, lineWidth = 1) {
  const p = project(a), q = project(b);
  ctx.beginPath();
  ctx.moveTo(p.x, p.y);
  ctx.lineTo(q.x, q.y);
  ctx.strokeStyle = color;
  ctx.globalAlpha = alpha;
  ctx.lineWidth = lineWidth;
  ctx.stroke();
  ctx.globalAlpha = 1;
}

function drawFloor() {
  for (let x = -6; x <= 6; x += 1) line3d({ x, y: -2.35, z: -4 }, { x, y: -2.35, z: 4 }, "#8a9b8b", .11);
  for (let z = -4; z <= 4; z += 1) line3d({ x: -6, y: -2.35, z }, { x: 6, y: -2.35, z }, "#8a9b8b", .11);
  line3d({ x: -6, y: -2.35, z: 0 }, { x: 6, y: -2.35, z: 0 }, "#c9f36a", .28, 1.2);
}

function drawCube(x, z, h, color, time, phase) {
  const w = .22, d = .25, bottom = -2.35, top = bottom + h;
  const points = [
    { x: x-w, y: bottom, z: z-d }, { x: x+w, y: bottom, z: z-d },
    { x: x+w, y: top, z: z-d }, { x: x-w, y: top, z: z-d },
    { x: x-w, y: bottom, z: z+d }, { x: x+w, y: bottom, z: z+d },
    { x: x+w, y: top, z: z+d }, { x: x-w, y: top, z: z+d },
  ].map((point) => project(point));
  const faces = [
    { points: [0,1,2,3], color, shade: .55 },
    { points: [1,5,6,2], color, shade: .78 },
    { points: [3,2,6,7], color, shade: 1 },
  ];
  faces.forEach((face) => polygon(face.points.map((index) => points[index]), face.color, face.shade));
  const topFace = [3,2,6,7].map((index) => points[index]);
  ctx.save();
  ctx.shadowColor = color;
  ctx.shadowBlur = 12;
  polygon(topFace, color, .86);
  ctx.restore();
  const point = project({ x, y: top + .1 + Math.sin(time * .003 + phase) * .12, z });
  const beamBase = project({ x, y: top, z });
  ctx.beginPath();
  ctx.moveTo(beamBase.x, beamBase.y);
  ctx.lineTo(point.x, point.y - 5);
  ctx.strokeStyle = color;
  ctx.globalAlpha = .18 + .12 * Math.sin(time * .002 + phase);
  ctx.lineWidth = 1;
  ctx.stroke();
  ctx.globalAlpha = 1;
  const halo = ctx.createRadialGradient(point.x, point.y, 0, point.x, point.y, 10);
  halo.addColorStop(0, `${color}cc`);
  halo.addColorStop(1, `${color}00`);
  ctx.fillStyle = halo;
  ctx.fillRect(point.x - 10, point.y - 10, 20, 20);
  ctx.beginPath();
  ctx.arc(point.x, point.y, 2, 0, Math.PI * 2);
  ctx.fillStyle = "#f4ffd8";
  ctx.shadowColor = color;
  ctx.shadowBlur = 12;
  ctx.fill();
  ctx.shadowBlur = 0;
}

function drawBars(time) {
  const data = state.data;
  if (!data) return;
  drawFloor();
  let groups;
  if (state.view === "packets") {
    groups = data.distribution.normal.map((normal, index) => ({
      x: (index - 7) * .68,
      normal: normal,
      malicious: data.distribution.malicious[index],
    }));
    $("#scene-value-a").textContent = `${fmt(data.packets.normal.median, 0)} MEDIAN PKTS`;
    $("#scene-value-b").textContent = `${fmt(data.packets.malicious.median, 0)} MEDIAN PKTS`;
  } else {
    const names = data.protocols.names;
    groups = names.map((name, index) => ({
      x: (index - (names.length - 1) / 2) * 1.18,
      normal: data.protocols.normal[index],
      malicious: data.protocols.malicious[index],
      name,
    }));
    $("#scene-value-a").textContent = `${data.protocols.names.length} PROTOCOLS`;
    $("#scene-value-b").textContent = "SHARE BY CLASS";
  }
  const values = groups.flatMap((group) => [group.normal, group.malicious]);
  const maximum = Math.max(...values, 1);
  const floor = -2.35;
  const elapsed = reducedMotion.matches ? 1000 : Math.max(0, time - state.sceneStarted);
  const progress = 1 - (1 - Math.min(1, elapsed / 780)) ** 3;
  const columns = [];
  groups.forEach((group, index) => {
    const factor = state.logScale && state.view === "packets"
      ? Math.log1p(Math.max(0, group.normal)) / Math.log1p(maximum)
      : group.normal / maximum;
    const maliciousFactor = state.logScale && state.view === "packets"
      ? Math.log1p(Math.max(0, group.malicious)) / Math.log1p(maximum)
      : group.malicious / maximum;
    const normalHeight = (.16 + factor * 3) * progress;
    const maliciousHeight = (.16 + maliciousFactor * 3) * progress;
    columns.push(
      { x: group.x, z: -.68, height: normalHeight, color: "#c9f36a", phase: index, depth: project({ x: group.x, y: floor + normalHeight / 2, z: -.68 }).depth },
      { x: group.x, z: .68, height: maliciousHeight, color: "#ff765e", phase: index + 2.5, depth: project({ x: group.x, y: floor + maliciousHeight / 2, z: .68 }).depth },
    );
  });
  columns.sort((a, b) => a.depth - b.depth).forEach((column) => {
    drawCube(column.x, column.z, column.height, column.color, time, column.phase);
  });
  groups.forEach((group, index) => {
    const label = state.view === "packets" ? String(index + 1).padStart(2, "0") : group.name;
    const p = project({ x: group.x, y: floor - .22, z: 0 });
    ctx.save();
    ctx.fillStyle = "#849088";
    ctx.font = "9px monospace";
    ctx.textAlign = "center";
    ctx.fillText(label, p.x, p.y);
    ctx.restore();
  });
}

function drawNetwork(time) {
  const count = 84;
  const points = [];
  const golden = Math.PI * (3 - Math.sqrt(5));
  const radius = 3.25;
  const normalShare = state.data
    ? state.data.counts.normal / state.data.counts.all
    : .5;
  for (let i = 0; i < count; i++) {
    const y = 1 - (i / (count - 1)) * 2;
    const r = Math.sqrt(1 - y * y);
    const theta = golden * i;
    points.push({ x: Math.cos(theta) * r * radius, y: y * radius, z: Math.sin(theta) * r * radius });
  }

  const centerX = width * .51;
  const centerY = height * .53;
  const globeRadius = Math.min(width, height) * .34 * state.zoom;
  const surface = ctx.createRadialGradient(
    centerX - globeRadius * .25, centerY - globeRadius * .32, globeRadius * .08,
    centerX, centerY, globeRadius,
  );
  surface.addColorStop(0, "#26302a55");
  surface.addColorStop(.72, "#1a22201c");
  surface.addColorStop(1, "#10151600");
  ctx.save();
  ctx.beginPath();
  ctx.arc(centerX, centerY, globeRadius, 0, Math.PI * 2);
  ctx.fillStyle = surface;
  ctx.fill();
  ctx.strokeStyle = "#b8c5b52b";
  ctx.lineWidth = 1;
  ctx.stroke();
  ctx.restore();

  const rearGrid = [];
  const frontGrid = [];
  const addGridRing = (samples) => {
    const projected = samples.map((point) => ({ ...project(point), world: point }));
    for (let i = 0; i < projected.length - 1; i++) {
      const a = projected[i];
      const b = projected[i + 1];
      const segment = { a, b };
      ((a.depth + b.depth) / 2 >= 0 ? frontGrid : rearGrid).push(segment);
    }
  };
  for (let latitude = -2; latitude <= 2; latitude++) {
    const phi = latitude * Math.PI / 7;
    const ringRadius = Math.cos(phi) * radius;
    const y = Math.sin(phi) * radius;
    const samples = [];
    for (let i = 0; i <= 96; i++) {
      const theta = i / 96 * Math.PI * 2;
      samples.push({ x: Math.cos(theta) * ringRadius, y, z: Math.sin(theta) * ringRadius });
    }
    addGridRing(samples);
  }
  for (let meridian = 0; meridian < 10; meridian++) {
    const theta = meridian / 10 * Math.PI;
    const samples = [];
    for (let i = 0; i <= 64; i++) {
      const phi = -Math.PI / 2 + i / 64 * Math.PI;
      const ringRadius = Math.cos(phi) * radius;
      samples.push({
        x: Math.cos(theta) * ringRadius,
        y: Math.sin(phi) * radius,
        z: Math.sin(theta) * ringRadius,
      });
    }
    addGridRing(samples);
  }
  const drawGridSegments = (segments, color, alpha, dash) => {
    ctx.save();
    ctx.beginPath();
    for (const { a, b } of segments) {
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
    }
    ctx.strokeStyle = color;
    ctx.globalAlpha = alpha;
    ctx.lineWidth = .7;
    ctx.setLineDash(dash);
    ctx.stroke();
    ctx.restore();
  };
  drawGridSegments(rearGrid, "#9dad9d", .16, [2, 5]);

  const projected = points.map((point, index) => ({
    ...point,
    world: point,
    index,
    ...project(point),
    color: (index * 37 % count) < count * normalShare ? "#c9f36a" : "#ff765e",
  }));
  const links = [];
  projected.forEach((point, index) => {
    const nearest = projected
      .filter((target) => target.index !== index)
      .map((target) => ({
        target,
        distance: (point.world.x - target.world.x) ** 2
          + (point.world.y - target.world.y) ** 2
          + (point.world.z - target.world.z) ** 2,
      }))
      .sort((a, b) => a.distance - b.distance)
      .slice(0, 2);
    nearest.forEach(({ target }) => {
      if (point.index < target.index) links.push({
        point,
        target,
        depth: (point.depth + target.depth) / 2,
      });
    });
  });
  links.sort((a, b) => a.depth - b.depth).forEach(({ point, target, depth }) => {
    if (depth >= 0) return;
    ctx.beginPath();
    ctx.moveTo(point.x, point.y);
    ctx.lineTo(target.x, target.y);
    ctx.strokeStyle = depth >= 0 ? "#a4b99e" : "#87958a";
    ctx.globalAlpha = depth >= 0 ? .24 : .1;
    ctx.lineWidth = depth >= 0 ? .8 : .55;
    ctx.setLineDash(depth >= 0 ? [] : [2, 3]);
    ctx.stroke();
  });
  drawGridSegments(frontGrid, "#9dad9d", .3, []);
  ctx.setLineDash([]);
  links.forEach(({ point, target, depth }) => {
    if (depth < 0) return;
    ctx.beginPath();
    ctx.moveTo(point.x, point.y);
    ctx.lineTo(target.x, target.y);
    ctx.strokeStyle = "#a4b99e";
    ctx.globalAlpha = .24;
    ctx.lineWidth = .8;
    ctx.stroke();
  });
  ctx.setLineDash([]);

  projected.sort((a, b) => a.depth - b.depth).forEach((point) => {
    const front = point.depth >= 0;
    ctx.beginPath();
    ctx.arc(point.x, point.y, front ? 2 : 1.35, 0, Math.PI * 2);
    ctx.fillStyle = point.color;
    ctx.globalAlpha = front ? .92 : .3;
    ctx.fill();
    ctx.globalAlpha = 1;
  });

  for (let pulse = 0; pulse < 5; pulse++) {
    const link = links[(pulse * 17) % links.length];
    if (!link || link.depth < 0) continue;
    const progress = (time / 2200 + pulse * .23) % 1;
    const x = link.point.x + (link.target.x - link.point.x) * progress;
    const y = link.point.y + (link.target.y - link.point.y) * progress;
    ctx.beginPath();
    ctx.arc(x, y, 1.5, 0, Math.PI * 2);
    ctx.fillStyle = "#f4ffd8";
    ctx.fill();
  }
}

function drawScene(time = 0) {
  if (!width || !height || state.view === "flows") return;
  ctx.clearRect(0, 0, width, height);
  if (state.view === "network") drawNetwork(time);
  else drawBars(time);
}

function animate(time) {
  const elapsed = previousTime ? time - previousTime : 16;
  previousTime = time;
  if (state.view === "network") state.angle += elapsed * .000018;
  drawScene(time);
  if (state.view !== "flows" && !document.hidden && !reducedMotion.matches) frame = requestAnimationFrame(animate);
}

document.addEventListener("visibilitychange", () => {
  cancelAnimationFrame(frame);
  if (!document.hidden && !reducedMotion.matches && state.view !== "flows") {
    frame = requestAnimationFrame(animate);
  }
});

function switchView(view) {
  if (view !== state.view) resetCamera(view);
  state.view = view;
  updateSceneLabels();
  syncInspectorState();
  animateSceneEntry();
  state.sceneStarted = performance.now();
  if (view === "flows") cancelAnimationFrame(frame);
  else if (!reducedMotion.matches) {
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(animate);
  } else drawScene();
}

function installAmbient() {
  const bg = $("#signal-field"), bgctx = bg.getContext("2d");
  let points = [];
  let bgWidth = 0, bgHeight = 0, ratio = 1;
  const resize = () => {
    bgWidth = innerWidth; bgHeight = innerHeight; ratio = Math.min(devicePixelRatio || 1, 1.25);
    bg.width = bgWidth * ratio; bg.height = bgHeight * ratio;
    bgctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    points = Array.from({ length: Math.max(22, Math.min(46, Math.floor(bgWidth * bgHeight / 34000))) }, () => ({
      x: Math.random() * bgWidth, y: Math.random() * bgHeight,
      vx: (Math.random() - .5) * .12, vy: (Math.random() - .5) * .12,
    }));
    renderBackground();
  };
  const renderBackground = () => {
    bgctx.clearRect(0, 0, bgWidth, bgHeight);
    points.forEach((point, index) => {
      if (!reducedMotion.matches) {
        point.x += point.vx; point.y += point.vy;
        if (point.x < 0 || point.x > bgWidth) point.vx *= -1;
        if (point.y < 0 || point.y > bgHeight) point.vy *= -1;
      }
      for (let i = index + 1; i < points.length; i++) {
        const other = points[i], distance = Math.hypot(point.x - other.x, point.y - other.y);
        if (distance < 150) {
          bgctx.beginPath(); bgctx.moveTo(point.x, point.y); bgctx.lineTo(other.x, other.y);
          bgctx.strokeStyle = `rgba(150,179,147,${(1 - distance / 150) * .12})`; bgctx.stroke();
        }
      }
      bgctx.beginPath(); bgctx.arc(point.x, point.y, 1.2, 0, Math.PI * 2);
      bgctx.fillStyle = "#c9f36a44"; bgctx.fill();
    });
    if (!reducedMotion.matches && !document.hidden) ambientFrame = requestAnimationFrame(renderBackground);
  };
  resumeAmbient = () => {
    cancelAnimationFrame(ambientFrame);
    if (!reducedMotion.matches && !document.hidden) ambientFrame = requestAnimationFrame(renderBackground);
  };
  resize();
  window.addEventListener("resize", resize, { passive: true });
  document.addEventListener("visibilitychange", resumeAmbient);
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => switchView(tab.dataset.view));
  tab.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const tabs = [...document.querySelectorAll(".tab")];
    const current = tabs.indexOf(tab);
    const next = event.key === "Home" ? 0
      : event.key === "End" ? tabs.length - 1
      : (current + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    tabs[next].focus();
    switchView(tabs[next].dataset.view);
  });
});
$(const closeButton = document.querySelector(".inspector-close");
  if (!toggle) return;
  const isMobile = window.matchMedia("(max-width: 520px)").matches;
  const canShow = isMobile && state.view !== "flows";
  if (!canShow) document.body.classList.remove("inspector-open");
  const open = canShow && document.body.classList.contains("inspector-open");
  toggle.hidden = !canShow;
  toggle.setAttribute("aria-expanded", String(open));
  toggle.querySelector(".inspector-toggle-text").textContent = open ? "Hide metrics" : "Metrics";
  if (closeButton) {
    closeButton.hidden = !canShow || !open;
    closeButton.setAttribute("aria-expanded", String(open));
  }
}

function init() {
  installAmbient();
  resizeCanvas();
  updateSceneLabels();
  refresh();
  const inspectorToggle = document.getElementById("inspector-toggle");
  const inspector = document.getElementById("data-inspector");
  const closeButton = document.querySelector(".inspector-close");
  const setInspectorOpen = (open) => {
    document.body.classList.toggle("inspector-open", open);
    syncInspectorState();
  };
  if (inspectorToggle) {
    inspectorToggle.addEventListener("click", () => {
      setInspectorOpen(!document.body.classList.contains("inspector-open"));
    });
  }
  if (closeButton) {
    closeButton.addEventListener("click", () => setInspectorOpen(false)s.addEventListener("pointermove", (event) => {
  if (!state.dragging) return;
  state.angle -= (event.clientX - state.lastX) * .009;
  state.tilt = Math.max(-.8, Math.min(.25, state.tilt + (event.clientY - state.lastY) * .005));
  state.lastX = event.clientX; state.lastY = event.clientY;
  if (state.view === "network" && reducedMotion.matches) drawScene();
});
canvas.addEventListener("pointerup", () => { state.dragging = false; });
canvas.addEventListener("pointercancel", () => { state.dragging = false; });
canvas.addEventListener("keydown", (event) => {
  const step = event.shiftKey ? .22 : .12;
  const isZoomKey = event.key === "+" || event.key === "=" || event.key === "-" || event.key === "_";
  if (["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "PageUp", "PageDown"].includes(event.key) || isZoomKey) {
    event.preventDefault();
  }
  if (event.key === "ArrowLeft") state.angle += step;
  if (event.key === "ArrowRight") state.angle -= step;
  if (event.key === "ArrowUp") state.tilt = Math.max(-.8, state.tilt - .08);
  if (event.key === "ArrowDown") state.tilt = Math.min(.25, state.tilt + .08);
  if (event.key === "+" || event.key === "=" || event.key === "PageUp") state.zoom = Math.max(.72, Math.min(1.45, state.zoom + .06));
  if (event.key === "-" || event.key === "_" || event.key === "PageDown") state.zoom = Math.max(.72, Math.min(1.45, state.zoom - .06));
  if (event.key === "Home") {
    state.angle = 0;
    state.tilt = cameraPresets[state.view].tilt;
    state.zoom = 1;
  }
  if (reducedMotion.matches) drawScene();
});
canvas.addEventListener("wheel", (event) => {
  event.preventDefault();
  state.zoom = Math.max(.72, Math.min(1.45, state.zoom - Math.sign(event.deltaY) * .05));
  if (reducedMotion.matches) drawScene();
}, { passive: false });
window.addEventListener("resize", () => {
  resizeCanvas();
  const active = $(`.tab[data-view="${state.view}"]`);
  $(".tab-indicator").style.left = `${active.offsetLeft}px`;
  $(".tab-indicator").style.width = `${active.offsetWidth}px`;
});
reducedMotion.addEventListener("change", () => {
  cancelAnimationFrame(frame); cancelAnimationFrame(ambientFrame);
  if (reducedMotion.matches) { drawScene(); }
  else {
    if (state.view !== "flows") frame = requestAnimationFrame(animate);
    resumeAmbient();
  }
});

function syncInspectorState() {
  const toggle = document.getElementById("inspector-toggle");
  if (!toggle) return;
  const isMobile = window.matchMedia("(max-width: 520px)").matches;
  const canShow = isMobile && state.view !== "flows";
  if (!canShow) document.body.classList.remove("inspector-open");
  const open = canShow && document.body.classList.contains("inspector-open");
  toggle.hidden = !canShow;
  toggle.setAttribute("aria-expanded", String(open));
  toggle.querySelector(".inspector-toggle-text").textContent = open ? "Hide metrics" : "Metrics";
}

function init() {
  installAmbient();
  resizeCanvas();
  updateSceneLabels();
  refresh();
  const inspectorToggle = document.getElementById("inspector-toggle");
  const inspector = document.getElementById("data-inspector");
  const setInspectorOpen = (open) => {
    document.body.classList.toggle("inspector-open", open);
    syncInspectorState();
  };
  if (inspectorToggle) {
    inspectorToggle.addEventListener("click", () => {
      setInspectorOpen(!document.body.classList.contains("inspector-open"));
    });
  }
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && document.body.classList.contains("inspector-open")) {
      setInspectorOpen(false);
    }
  });
  document.addEventListener("pointerdown", (event) => {
    const isMobile = window.matchMedia("(max-width: 520px)").matches;
    if (!isMobile || !document.body.classList.contains("inspector-open")) return;
    if (inspector?.contains(event.target) || inspectorToggle?.contains(event.target)) return;
    setInspectorOpen(false);
  });
  window.addEventListener("resize", syncInspectorState);
  syncInspectorState();
  if (!reducedMotion.matches) frame = requestAnimationFrame(animate);
}
init();
