const $ = (selector) => document.querySelector(selector);
const number = new Intl.NumberFormat("en-US");
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const state = {
  view: "network", page: 1, pageSize: 5, group: "All",
  alpha: .05, logScale: true, data: null, angle: 0, tilt: -.22, zoom: 1,
  dragging: false, lastX: 0, lastY: 0, pointer: null,
};
const sceneInfo = {
  network: ["TRAFFIC TOPOLOGY / 3D NETWORK MAP", "A living network"],
  packets: ["DISTRIBUTION / EXTRUDED PACKET BINS", "Packet volume"],
  protocols: ["PROTOCOL MIX / TRAFFIC COMPOSITION", "Protocol signatures"],
  flows: ["CONNECTION DETAIL / LIVE RECORDS", "Flow log"],
};
const canvas = $("#scene-canvas");
const ctx = canvas.getContext("2d");
let width = 0, height = 0, pixelRatio = 1, frame = 0, previousTime = 0;
let ambientFrame = 0;
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
function superscript(value) {
  return String(value).replace(/-/g, "⁻").replace(/\d/g, (digit) => "⁰¹²³⁴⁵⁶⁷⁸⁹"[digit]);
}

async function refresh() {
  const params = new URLSearchParams({
    alpha: state.alpha, top_n: 8, page: state.page, page_size: state.pageSize,
    group: state.group, aggregation: "median", log_scale: state.logScale,
  });
  try {
    const response = await fetch(`/api/dashboard?${params}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Dashboard data could not be loaded.");
    state.data = data;
    render(data);
  } catch (error) {
    $("#notices").innerHTML = `<div class="notice">${esc(error.message)}</div>`;
  }
}

function render(data) {
  $("#source").textContent = data.source.toUpperCase();
  $("#source-detail").textContent = data.source;
  $("#total-count").textContent = number.format(data.counts.all);
  $("#normal-count").textContent = number.format(data.counts.normal);
  $("#malicious-count").textContent = number.format(data.counts.malicious);
  $("#scene-value-a").textContent = number.format(data.counts.normal);
  $("#scene-value-b").textContent = number.format(data.counts.malicious);
  $("#packet-gap").textContent = `${data.test.difference > 0 ? "+" : ""}${compact(data.test.difference)}`;
  const packetMax = Math.max(data.packets.normal.mean, data.packets.malicious.mean, 1);
  $("#mean-normal").style.width = `${data.packets.normal.mean / packetMax * 100}%`;
  $("#mean-malicious").style.width = `${data.packets.malicious.mean / packetMax * 100}%`;
  $("#mean-normal-value").textContent = compact(data.packets.normal.mean);
  $("#mean-malicious-value").textContent = compact(data.packets.malicious.mean);
  $("#p-value").textContent = data.test.p < .001 ? "< .001" : fmt(data.test.p, 4);
  $("#t-stat").textContent = fmt(data.test.t, 3);
  $("#ci").textContent = `[${fmt(data.test.ci[0])}, ${fmt(data.test.ci[1])}]`;
  $("#effect").textContent = `${fmt(data.test.cohens_d, 3)} · ${data.test.effect}`;
  $("#test-decision").textContent = data.test.significant ? "SIGNIFICANT · REJECT H₀" : "NOT SIGNIFICANT · RETAIN H₀";
  $("#test-decision").classList.toggle("nonsig", !data.test.significant);
  renderTable(data.table);
  renderNotices(data);
  updateSceneLabels();
  drawScene();
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

function renderTable(table) {
  const columns = ["proto", "spkts", "dpkts", "total_packets", "dur", "group"];
  const labels = { proto: "PROTOCOL", spkts: "SRC PKTS", dpkts: "DST PKTS", total_packets: "TOTAL", dur: "DURATION", group: "CLASS" };
  $("#table-head").innerHTML = `<tr>${columns.map((column) => `<th>${labels[column]}</th>`).join("")}</tr>`;
  $("#table-body").innerHTML = table.records.length ? table.records.map((record) =>
    `<tr>${columns.map((column) => {
      const value = record[column];
      if (column === "group") return `<td><span class="class-chip ${value === "Malicious" ? "malicious" : ""}">${esc(value)}</span></td>`;
      if (["spkts", "dpkts", "total_packets"].includes(column)) return `<td>${number.format(Number(value) || 0)}</td>`;
      if (column === "dur") return `<td>${fmt(value, 4)}</td>`;
      return `<td>${esc(value)}</td>`;
    }).join("")}</tr>`
  ).join("") : '<tr><td class="empty" colspan="6">No flow records.</td></tr>';
  const first = table.total ? (table.page - 1) * table.page_size + 1 : 0;
  const last = Math.min(table.page * table.page_size, table.total);
  $("#table-count").textContent = `${number.format(first)}–${number.format(last)} / ${number.format(table.total)}`;
  $("#page-indicator").textContent = `${table.page} / ${table.pages}`;
  $("#prev-page").disabled = table.page <= 1;
  $("#next-page").disabled = table.page >= table.pages;
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
  $("#scene-value-b").textContent = state.view === "flows" ? `${state.data?.table.records.length ?? 0} SHOWN` : $("#malicious-count").textContent;
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
  const camera = 15;
  const perspective = camera / (camera + depth);
  const unit = Math.min(width, height) * .105 * state.zoom * scale;
  return { x: width * .51 + x * unit * perspective, y: height * .53 - y * unit * perspective, depth };
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

function drawCube(x, z, h, color) {
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
}

function drawBars() {
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
  groups.forEach((group, index) => {
    const factor = state.logScale && state.view === "packets"
      ? Math.log1p(Math.max(0, group.normal)) / Math.log1p(maximum)
      : group.normal / maximum;
    const maliciousFactor = state.logScale && state.view === "packets"
      ? Math.log1p(Math.max(0, group.malicious)) / Math.log1p(maximum)
      : group.malicious / maximum;
    const normalHeight = .16 + factor * 3;
    const maliciousHeight = .16 + maliciousFactor * 3;
    drawCube(group.x, -.58, normalHeight, "#c9f36a");
    drawCube(group.x, .58, maliciousHeight, "#ff765e");
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
  const rotation = state.angle;
  const radius = 3.25;
  const normalShare = state.data
    ? state.data.counts.normal / state.data.counts.all
    : .5;
  for (let i = 0; i < count; i++) {
    const y = 1 - (i / (count - 1)) * 2;
    const r = Math.sqrt(1 - y * y);
    const theta = golden * i + rotation;
    points.push({ x: Math.cos(theta) * r * radius, y: y * radius, z: Math.sin(theta) * r * radius });
  }
  ctx.save();
  ctx.beginPath();
  ctx.arc(width * .51, height * .53, Math.min(width, height) * .345 * state.zoom, 0, Math.PI * 2);
  ctx.strokeStyle = "#c9f36a22";
  ctx.lineWidth = 1;
  ctx.stroke();
  ctx.restore();
  const links = [];
  points.forEach((point, index) => {
    [1, 5, 11].forEach((offset) => {
      const target = points[(index + offset) % points.length];
      const depth = (project(point).depth + project(target).depth) / 2;
      links.push({ point, target, depth });
    });
  });
  links.sort((a, b) => a.depth - b.depth).forEach(({ point, target, depth }) => {
    const front = depth < 0;
    line3d(point, target, front ? "#a4c782" : "#6e8b78", front ? .19 : .06, front ? .8 : .55);
  });
  points.forEach((point, index) => {
    const p = project(point);
    const visibility = Math.max(.18, Math.min(1, .6 - p.depth / 9));
    const color = index < count * normalShare ? "#c9f36a" : "#ff765e";
    ctx.beginPath();
    ctx.arc(p.x, p.y, 1.5, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.globalAlpha = visibility;
    ctx.shadowColor = color;
    ctx.shadowBlur = 7;
    ctx.fill();
    ctx.globalAlpha = 1;
    ctx.shadowBlur = 0;
  });
  const pulseIndex = Math.floor(time / 34) % points.length;
  const a = project(points[pulseIndex]), b = project(points[(pulseIndex + 5) % points.length]);
  const progress = (time % 3400) / 3400;
  const x = a.x + (b.x - a.x) * progress, y = a.y + (b.y - a.y) * progress;
  const glow = ctx.createRadialGradient(x, y, 0, x, y, 15);
  glow.addColorStop(0, "#fff8d8dd"); glow.addColorStop(.15, "#c9f36a99"); glow.addColorStop(1, "#c9f36a00");
  ctx.fillStyle = glow; ctx.fillRect(x - 15, y - 15, 30, 30);
}

function drawScene(time = 0) {
  if (!width || !height || state.view === "flows") return;
  ctx.clearRect(0, 0, width, height);
  if (state.view === "network") drawNetwork(time);
  else drawBars();
}

function animate(time) {
  const elapsed = previousTime ? time - previousTime : 16;
  previousTime = time;
  if (state.view !== "flows") state.angle += elapsed * .000018;
  drawScene(time);
  if (state.view !== "flows" && !document.hidden && !reducedMotion.matches) frame = requestAnimationFrame(animate);
}

function switchView(view) {
  state.view = view;
  updateSceneLabels();
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
$("#alpha").addEventListener("change", (event) => { state.alpha = Number(event.target.value); refresh(); });
$("#log-scale").addEventListener("change", (event) => { state.logScale = event.target.checked; if (state.data) drawScene(); });
$("#group-filter").addEventListener("change", (event) => { state.group = event.target.value; state.page = 1; refresh(); });
$("#prev-page").addEventListener("click", () => { if (state.page > 1) { state.page--; refresh(); } });
$("#next-page").addEventListener("click", () => { if (state.data && state.page < state.data.table.pages) { state.page++; refresh(); } });
canvas.addEventListener("pointerdown", (event) => {
  state.dragging = true; state.lastX = event.clientX; state.lastY = event.clientY; canvas.setPointerCapture(event.pointerId);
});
canvas.addEventListener("pointermove", (event) => {
  if (!state.dragging) return;
  state.angle += (event.clientX - state.lastX) * .009;
  state.tilt = Math.max(-.8, Math.min(.25, state.tilt + (event.clientY - state.lastY) * .005));
  state.lastX = event.clientX; state.lastY = event.clientY;
  if (state.view === "network" && reducedMotion.matches) drawScene();
});
canvas.addEventListener("pointerup", () => { state.dragging = false; });
canvas.addEventListener("pointercancel", () => { state.dragging = false; });
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
    if (state.view === "network") frame = requestAnimationFrame(animate);
    resumeAmbient();
  }
});

function init() {
  installAmbient();
  resizeCanvas();
  updateSceneLabels();
  refresh();
  if (!reducedMotion.matches) frame = requestAnimationFrame(animate);
}
init();
