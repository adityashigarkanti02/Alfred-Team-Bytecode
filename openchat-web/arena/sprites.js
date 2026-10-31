/* Possessed Butler — pixel-art arena renderer (canvas, no assets). */
window.Arena = (function () {
  "use strict";

  const W = 960, H = 420, FLOOR = 332;
  let cvs, ctx, raf = 0, t0 = 0, last = 0, shakeUntil = 0;
  const view = { mood: "idle", phase: "idle" };
  const parts = [], bolts = [], rings = [];

  /* ---------- sprites (16x16 grids) ---------- */
  const WITCH = {
    scale: 6,
    pal: { H: "#2a0a3f", P: "#7b2cbf", D: "#4c1d95", F: "#e8d8ff", E: "#ff2d55", B: "#0d0518" },
    rows: [
      "................",
      ".......HH.......",
      "......HHHH......",
      ".....HHHHHH.....",
      "....HHHHHHHH....",
      "..HHHHHHHHHHHH..",
      ".......FF.......",
      "......FEFE......",
      "......FFFF......",
      ".....PPPPPP.....",
      "....PPPPPPPP....",
      "...PPPPPPPPPP...",
      "..PPP.PPPPPP.PPP",
      ".....PPPPPP.....",
      "....BB....BB....",
      "...BBB....BBB..."
    ]
  };
  const PALADIN = {
    scale: 6,
    pal: { S: "#c9d6e8", s: "#8fa3c0", F: "#dfe9f7", E: "#22d3ee", C: "#5eead4", B: "#0d0518" },
    rows: [
      "................",
      "......SSSS......",
      ".....SSSSSS.....",
      ".....SFFFFS.....",
      ".....SFEEFS.....",
      "......SSSS......",
      ".....SSSSSS.....",
      "....SSSSSSSS....",
      "...SSSSSSSSSS...",
      "..SSSSSSSSSSSS..",
      "..SS.SSSSSS.SS..",
      ".....SSSSSS.....",
      "....SSSSSSSS....",
      "....SS....SS....",
      "...SSS....SSS...",
      "...BBB....BBB..."
    ]
  };
  const BUTLER = {
    scale: 7,
    pal: { B: "#171021", W: "#f4f1e8", F: "#e8d8c0", E: "#ffcc66", G: "#ffd166", T: "#0e7490" },
    rows: [
      "................",
      "......BBBB......",
      ".....BBBBBB.....",
      ".....BFFFFB.....",
      ".....BFEEFB.....",
      ".....BFFFFB.....",
      "......BBBB......",
      "....WWWWWWWW....",
      "...BBWWWWWWBB...",
      "...BBBWGGWBBB...",
      "...BBBBWWBBBB...",
      "....BBBBBBBB....",
      "....BBBBBBBB....",
      "....BBB..BBB....",
      "....BBB..BBB....",
      "...BBBB..BBBB..."
    ]
  };

  const baked = {};
  function bake(name, sp) {
    const c = document.createElement("canvas");
    c.width = 16 * sp.scale; c.height = 16 * sp.scale;
    const g = c.getContext("2d");
    sp.rows.forEach((row, y) => {
      for (let x = 0; x < 16; x++) {
        const ch = row[x];
        if (!ch || ch === ".") continue;
        g.fillStyle = sp.pal[ch] || "#f0f";
        g.fillRect(x * sp.scale, y * sp.scale, sp.scale, sp.scale);
      }
    });
    baked[name] = c;
  }

  /* ---------- helpers ---------- */
  const rnd = (a, b) => a + Math.random() * (b - a);

  function glowSprite(g, img, cx, baseY, bob, glow, flip) {
    const w = img.width, h = img.height;
    const x = cx - w / 2, y = baseY - h + bob;
    g.save();
    if (glow) { g.shadowColor = glow; g.shadowBlur = 22; }
    if (flip) { g.translate(cx, 0); g.scale(-1, 1); g.drawImage(img, -w / 2, y); }
    else g.drawImage(img, x, y);
    g.restore();
  }

  function shadow(g, cx, cy, rw) {
    g.save();
    g.fillStyle = "rgba(0,0,0,.45)";
    g.beginPath(); g.ellipse(cx, cy, rw, rw * 0.22, 0, 0, 7); g.fill();
    g.restore();
  }

  function burst(x, y, n, colors, speed) {
    for (let i = 0; i < n; i++) {
      const a = Math.random() * Math.PI * 2, s = rnd(0.2, 1) * speed;
      parts.push({
        x, y, vx: Math.cos(a) * s, vy: Math.sin(a) * s - 30,
        life: rnd(0.4, 1.1), max: 1.1, size: rnd(2, 5),
        color: colors[(Math.random() * colors.length) | 0], grav: 120
      });
    }
    if (parts.length > 500) parts.splice(0, parts.length - 500);
  }

  function makeBolt(x1, y1, x2, y2, color) {
    const pts = [];
    const seg = 7;
    for (let i = 0; i <= seg; i++) {
      const k = i / seg;
      pts.push({
        x: x1 + (x2 - x1) * k + (i && i < seg ? rnd(-16, 16) : 0),
        y: y1 + (y2 - y1) * k + (i && i < seg ? rnd(-20, 20) : 0)
      });
    }
    bolts.push({ pts, color, life: 0.55, max: 0.55 });
  }

  /* ---------- background ---------- */
  function drawBackground(g, t) {
    let grad = g.createLinearGradient(0, 0, 0, H);
    grad.addColorStop(0, "#07040d");
    grad.addColorStop(0.55, "#180b28");
    grad.addColorStop(1, "#0a0412");
    g.fillStyle = grad;
    g.fillRect(-20, -20, W + 40, H + 40);

    // wallpaper stripes
    g.strokeStyle = "rgba(140,80,190,.055)";
    g.lineWidth = 1;
    for (let x = 0; x < W; x += 46) {
      g.beginPath(); g.moveTo(x, 0); g.lineTo(x, 318); g.stroke();
    }
    g.strokeStyle = "rgba(140,80,190,.035)";
    for (let y = 20; y < 320; y += 40) {
      g.beginPath(); g.moveTo(0, y); g.lineTo(W, y); g.stroke();
    }

    // arched moon window
    g.save();
    const arch = () => {
      g.beginPath();
      g.moveTo(380, 286); g.lineTo(380, 132);
      g.arc(480, 132, 100, Math.PI, 0);
      g.lineTo(580, 286); g.closePath();
    };
    arch(); g.clip();
    const sky = g.createLinearGradient(0, 20, 0, 290);
    sky.addColorStop(0, "#3a2a68"); sky.addColorStop(0.6, "#1c1236"); sky.addColorStop(1, "#0d0719");
    g.fillStyle = sky; g.fillRect(360, 20, 240, 280);
    // stars
    for (let i = 0; i < 26; i++) {
      const sx = 386 + (i * 53) % 190, sy = 50 + (i * 37) % 120;
      g.fillStyle = `rgba(240,235,255,${0.25 + 0.55 * Math.abs(Math.sin(t * 0.7 + i))})`;
      g.fillRect(sx, sy, 2, 2);
    }
    // moon
    g.fillStyle = "#f2ebc8";
    g.beginPath(); g.arc(486, 120, 40, 0, 7); g.fill();
    g.fillStyle = "rgba(190,180,150,.45)";
    [[474, 108, 8], [500, 130, 6], [492, 100, 4], [468, 134, 5]].forEach(c => {
      g.beginPath(); g.arc(c[0], c[1], c[2], 0, 7); g.fill();
    });
    // clouds
    g.fillStyle = "rgba(30,20,55,.7)";
    for (let i = 0; i < 3; i++) {
      const cx = ((t * 6 + i * 120) % 300) + 360;
      g.beginPath(); g.ellipse(cx, 180 + i * 22, 70, 12, 0, 0, 7); g.fill();
    }
    // mullions
    g.strokeStyle = "#08040f"; g.lineWidth = 7;
    [440, 480, 520].forEach(x => { g.beginPath(); g.moveTo(x, 40); g.lineTo(x, 288); g.stroke(); });
    [172, 226].forEach(y => { g.beginPath(); g.moveTo(370, y); g.lineTo(590, y); g.stroke(); });
    g.restore();
    // window frame
    g.save();
    g.strokeStyle = "#0b0614"; g.lineWidth = 12; arch(); g.stroke();
    g.strokeStyle = "rgba(120,70,180,.25)"; g.lineWidth = 2; arch(); g.stroke();
    g.restore();

    // banners
    drawBanner(g, 104, "#4a0b16", "#7f1024", "#f43f5e");
    drawBanner(g, 812, "#082f49", "#0e4f6e", "#38bdf8");

    // pillars
    drawPillar(g, 30); drawPillar(g, 884);

    // chandelier
    drawChandelier(g, t);

    // floor
    const fl = g.createLinearGradient(0, 318, 0, H);
    fl.addColorStop(0, "#180d26"); fl.addColorStop(1, "#06030b");
    g.fillStyle = fl; g.fillRect(0, 318, W, H - 318);
    g.strokeStyle = "rgba(150,90,200,.12)"; g.lineWidth = 1;
    for (let i = -10; i <= 10; i++) {
      g.beginPath(); g.moveTo(480, 318); g.lineTo(480 + i * 110, H); g.stroke();
    }
    for (let i = 0; i < 5; i++) {
      const y = 326 + i * i * 3.4 + i * 4;
      g.beginPath(); g.moveTo(0, y); g.lineTo(W, y); g.stroke();
    }
    // rug
    g.fillStyle = "rgba(70,10,30,.55)";
    g.beginPath(); g.ellipse(480, 392, 300, 34, 0, 0, 7); g.fill();
    g.strokeStyle = "rgba(190,120,60,.25)"; g.lineWidth = 2;
    g.beginPath(); g.ellipse(480, 392, 280, 28, 0, 0, 7); g.stroke();

    // wall sconces
    drawSconce(g, 250, 196, t, 1);
    drawSconce(g, 710, 196, t, 2);

    // fog
    for (let i = 0; i < 4; i++) {
      const fx = ((t * (8 + i * 3) + i * 240) % (W + 400)) - 200;
      g.fillStyle = `rgba(150,120,220,${0.028 + i * 0.008})`;
      g.beginPath(); g.ellipse(fx, 330 + i * 16, 190, 22, 0, 0, 7); g.fill();
    }

    // vignette
    const vg = g.createRadialGradient(480, 220, 120, 480, 220, 620);
    vg.addColorStop(0, "rgba(0,0,0,0)"); vg.addColorStop(1, "rgba(0,0,0,.62)");
    g.fillStyle = vg; g.fillRect(0, 0, W, H);
  }

  function drawPillar(g, x) {
    g.fillStyle = "#0f0819"; g.fillRect(x, 0, 46, 336);
    g.fillStyle = "#1d1233"; g.fillRect(x + 6, 0, 9, 336);
    g.fillStyle = "#080410"; g.fillRect(x + 36, 0, 10, 336);
    g.fillStyle = "#241740";
    g.fillRect(x - 8, 0, 62, 20);
    g.fillRect(x - 10, 300, 66, 18);
    g.fillStyle = "rgba(160,110,220,.12)"; g.fillRect(x - 8, 20, 62, 3);
  }

  function drawBanner(g, x, c1, c2, em) {
    g.save();
    g.fillStyle = c1;
    g.beginPath();
    g.moveTo(x, 0); g.lineTo(x + 46, 0); g.lineTo(x + 46, 206);
    g.lineTo(x + 23, 184); g.lineTo(x, 206); g.closePath(); g.fill();
    g.fillStyle = c2;
    g.beginPath();
    g.moveTo(x + 8, 0); g.lineTo(x + 18, 0); g.lineTo(x + 18, 196);
    g.lineTo(x + 8, 192); g.closePath(); g.fill();
    g.strokeStyle = "rgba(0,0,0,.5)"; g.lineWidth = 2;
    g.beginPath(); g.moveTo(x, 0); g.lineTo(x, 206); g.stroke();
    g.fillStyle = em; g.globalAlpha = 0.75;
    g.beginPath(); g.arc(x + 23, 78, 11, 0, 7); g.fill();
    g.globalAlpha = 1;
    g.fillStyle = c1; g.beginPath(); g.arc(x + 23, 78, 6, 0, 7); g.fill();
    g.restore();
  }

  function drawChandelier(g, t) {
    g.save();
    g.strokeStyle = "#2b1c3f"; g.lineWidth = 3;
    g.beginPath(); g.moveTo(480, 0); g.lineTo(480, 34); g.stroke();
    g.strokeStyle = "#3a2752"; g.lineWidth = 4;
    g.beginPath(); g.ellipse(480, 44, 54, 9, 0, 0, 7); g.stroke();
    g.lineWidth = 2;
    [-42, -18, 18, 42].forEach(dx => {
      g.beginPath(); g.moveTo(480 + dx, 44); g.lineTo(480 + dx, 62); g.stroke();
    });
    [-42, -18, 0, 18, 42].forEach((dx, i) => {
      const fy = 58 + Math.sin(t * 6 + i) * 1.5;
      g.fillStyle = "#f5e6b8"; g.fillRect(480 + dx - 1, fy - 8, 3, 8);
      g.fillStyle = i % 2 ? "#fbbf24" : "#fb923c";
      g.beginPath(); g.ellipse(480 + dx, fy - 10, 2.5, 4.5, 0, 0, 7); g.fill();
      g.save(); g.shadowColor = "#f59e0b"; g.shadowBlur = 14;
      g.fillStyle = "rgba(251,191,36,.5)";
      g.beginPath(); g.arc(480 + dx, fy - 10, 4, 0, 7); g.fill(); g.restore();
    });
    g.restore();
  }

  function drawSconce(g, x, y, t, seed) {
    g.save();
    g.fillStyle = "#241740"; g.fillRect(x - 12, y, 24, 5);
    g.fillStyle = "#f5e6b8"; g.fillRect(x - 2, y - 16, 4, 16);
    const f = 1 + Math.sin(t * 7 + seed) * 0.18;
    g.save(); g.shadowColor = "#f59e0b"; g.shadowBlur = 18;
    g.fillStyle = "#fbbf24";
    g.beginPath(); g.ellipse(x, y - 20, 3.4 * f, 6 * f, 0, 0, 7); g.fill();
    g.restore();
    g.restore();
  }

  /* ---------- props ---------- */
  function drawKeyboard(g, t, bob) {
    const x = 118, y = 282 + bob;
    g.save();
    g.fillStyle = "#1b0b2b"; g.fillRect(x, y, 58, 18);
    g.fillStyle = "#341a4f"; g.fillRect(x + 2, y + 2, 54, 12);
    for (let r = 0; r < 3; r++) {
      for (let c = 0; c < 10; c++) {
        g.fillStyle = (r + c) % 7 === 0 ? "#ff2d55" : "#6d28d9";
        g.fillRect(x + 4 + c * 5, y + 3 + r * 4, 4, 3);
      }
    }
    g.fillStyle = "rgba(255,45,85,.5)";
    g.fillRect(x, y + 18, 58, 2);
    g.restore();
  }

  function drawBell(g, t) {
    const x = 690, y = 286;
    g.save();
    g.strokeStyle = "#ffd166"; g.lineWidth = 2;
    g.beginPath(); g.moveTo(x, y + 4); g.lineTo(x + 8, y + 4); g.stroke();
    g.fillStyle = "#c99a2e";
    g.beginPath();
    g.moveTo(x + 4, y + 6); g.lineTo(x + 32, y + 6);
    g.quadraticCurveTo(x + 30, y + 32, x + 38, y + 34);
    g.lineTo(x - 2, y + 34);
    g.quadraticCurveTo(x + 6, y + 32, x + 4, y + 6);
    g.closePath(); g.fill();
    g.fillStyle = "#ffd166";
    g.beginPath();
    g.moveTo(x + 7, y + 8); g.lineTo(x + 29, y + 8);
    g.quadraticCurveTo(x + 27, y + 29, x + 34, y + 31);
    g.lineTo(x + 2, y + 31);
    g.quadraticCurveTo(x + 9, y + 29, x + 7, y + 8);
    g.closePath(); g.fill();
    g.fillStyle = "#8a6a1f"; g.beginPath(); g.arc(x + 18, y + 34, 4, 0, 7); g.fill();
    g.fillStyle = "rgba(255,255,255,.45)"; g.fillRect(x + 10, y + 12, 3, 14);
    // ringing arcs
    const k = (t * 1.6) % 1;
    g.strokeStyle = `rgba(255,209,102,${0.5 * (1 - k)})`;
    g.lineWidth = 2;
    g.beginPath(); g.arc(x + 18, y + 20, 26 + k * 26, -0.7, 0.7); g.stroke();
    g.beginPath(); g.arc(x + 18, y + 20, 34 + k * 30, -0.5, 0.5); g.stroke();
    g.restore();
  }

  function drawTray(g, t, bob) {
    const x = 512, y = 288 + bob;
    g.save();
    g.fillStyle = "#3a2a18"; g.fillRect(x, y, 62, 4);
    g.fillStyle = "#c99a2e"; g.fillRect(x, y, 62, 1.5);
    // cup
    g.fillStyle = "#f4f1e8"; g.fillRect(x + 16, y - 12, 14, 12);
    g.fillStyle = "#f4f1e8";
    g.beginPath(); g.arc(x + 31, y - 7, 5, -1.2, 1.2); g.lineWidth = 2; g.strokeStyle = "#f4f1e8"; g.stroke();
    g.fillStyle = "#6b4a1f"; g.fillRect(x + 16, y - 13, 14, 2);
    // steam
    const s = (t * 0.9) % 1;
    g.strokeStyle = `rgba(240,235,220,${0.35 * (1 - s)})`;
    g.lineWidth = 1.5;
    g.beginPath();
    g.moveTo(x + 23, y - 15 - s * 10);
    g.bezierCurveTo(x + 19, y - 20 - s * 10, x + 27, y - 24 - s * 10, x + 23, y - 30 - s * 10);
    g.stroke();
    g.restore();
  }

  /* ---------- actors ---------- */
  function drawActors(g, t) {
    const bob = Math.sin(t * 2) * 2;
    const bob2 = Math.sin(t * 1.7 + 1) * 2;
    const bob3 = Math.sin(t * 2.3 + 2) * 1.5;

    // witch
    shadow(g, 198, FLOOR + 2, 46);
    let wGlow = view.phase === "red" ? "#a855f7" : null;
    glowSprite(g, baked.witch, 198, FLOOR, bob, wGlow, false);
    drawKeyboard(g, t, bob);

    // paladin
    shadow(g, 762, FLOOR + 2, 46);
    let pGlow = view.phase === "blue" ? "#38bdf8" : null;
    glowSprite(g, baked.paladin, 762, FLOOR, bob2, pGlow, true);
    drawBell(g, t);

    // butler
    shadow(g, 480, FLOOR + 2, 40);
    let bGlow = "#c99a2e";
    if (view.mood === "possessed") bGlow = "#ff2d55";
    else if (view.mood === "warded") bGlow = "#38bdf8";
    else if (view.mood === "thinking") bGlow = "#a855f7";
    let bx = 480, by = FLOOR;
    if (view.mood === "possessed") { bx += Math.sin(t * 42) * 2.2; by += Math.sin(t * 31) * 1.4; }
    glowSprite(g, baked.butler, bx, by, bob3, bGlow, false);
    drawTray(g, t, bob3);

    if (view.mood === "possessed") {
      g.save();
      g.globalCompositeOperation = "lighter";
      const a = 0.16 + 0.1 * Math.sin(t * 8);
      const rg = g.createRadialGradient(480, 270, 10, 480, 270, 130);
      rg.addColorStop(0, `rgba(255,45,85,${a})`); rg.addColorStop(1, "rgba(255,45,85,0)");
      g.fillStyle = rg; g.fillRect(340, 130, 280, 280);
      g.restore();
    }
    if (view.mood === "warded") {
      g.save();
      g.strokeStyle = "rgba(56,189,248,.35)"; g.lineWidth = 2;
      const r = 62 + Math.sin(t * 3) * 4;
      g.beginPath(); g.arc(480, 270, r, 0, 7); g.stroke();
      g.setLineDash([4, 8]);
      g.beginPath(); g.arc(480, 270, r + 12, t, t + 4.2); g.stroke();
      g.restore();
    }
  }

  /* ---------- fx ---------- */
  function update(dt) {
    for (let i = parts.length - 1; i >= 0; i--) {
      const p = parts[i];
      p.x += p.vx * dt; p.y += p.vy * dt;
      p.vy += p.grav * dt;
      p.life -= dt;
      if (p.life <= 0) parts.splice(i, 1);
    }
    for (let i = bolts.length - 1; i >= 0; i--) {
      bolts[i].life -= dt;
      if (bolts[i].life <= 0) bolts.splice(i, 1);
    }
    for (let i = rings.length - 1; i >= 0; i--) {
      const r = rings[i];
      r.life -= dt;
      r.r += (r.max - r.r) * dt * 4;
      if (r.life <= 0) rings.splice(i, 1);
    }
  }

  function drawFX(g) {
    bolts.forEach(b => {
      const a = Math.max(0, b.life / b.max);
      g.save();
      g.globalAlpha = a;
      g.strokeStyle = b.color; g.lineWidth = 3;
      g.shadowColor = b.color; g.shadowBlur = 18;
      g.beginPath();
      b.pts.forEach((p, i) => i ? g.lineTo(p.x, p.y) : g.moveTo(p.x, p.y));
      g.stroke();
      g.lineWidth = 1; g.strokeStyle = "#fff"; g.globalAlpha = a * 0.8;
      g.stroke();
      g.restore();
    });
    rings.forEach(r => {
      const a = Math.max(0, r.life / 0.9);
      g.save();
      g.globalAlpha = a;
      g.strokeStyle = r.color; g.lineWidth = 3;
      g.shadowColor = r.color; g.shadowBlur = 16;
      g.beginPath(); g.arc(r.x, r.y, r.r, 0, 7); g.stroke();
      g.restore();
    });
    parts.forEach(p => {
      const a = Math.max(0, Math.min(1, p.life / 0.5));
      g.globalAlpha = a;
      g.fillStyle = p.color;
      g.fillRect(p.x - p.size / 2, p.y - p.size / 2, p.size, p.size);
    });
    g.globalAlpha = 1;
  }

  /* ---------- loop ---------- */
  function frame(now) {
    if (!last) last = now;
    const dt = Math.min(0.05, (now - last) / 1000) || 0.016;
    last = now;
    const t = (now - t0) / 1000;
    update(dt);

    ctx.save();
    if (now < shakeUntil) {
      const k = (shakeUntil - now) / 600;
      ctx.translate(rnd(-7, 7) * k, rnd(-5, 5) * k);
    }
    drawBackground(ctx, t);
    drawActors(ctx, t);
    drawFX(ctx);
    ctx.restore();

    raf = requestAnimationFrame(frame);
  }

  /* ---------- public ---------- */
  function init(canvas) {
    cvs = canvas;
    ctx = cvs.getContext("2d");
    cvs.width = W; cvs.height = H;
    bake("witch", WITCH); bake("paladin", PALADIN); bake("butler", BUTLER);
    t0 = performance.now();
    cancelAnimationFrame(raf);
    raf = requestAnimationFrame(frame);
  }

  function set(patch) { Object.assign(view, patch); }
  function shake(ms) { shakeUntil = performance.now() + (ms || 450); }
  function castRed() {
    makeBolt(238, 268, 442, 258, "#a855f7");
    makeBolt(238, 268, 442, 258, "#4ade80");
    burst(238, 268, 16, ["#a855f7", "#4ade80", "#ff2d55"], 130);
    burst(452, 286, 14, ["#4ade80", "#86efac", "#a855f7"], 70);
  }
  function castBlue() {
    rings.push({ x: 480, y: 268, r: 18, max: 168, life: 0.9, color: "#ffd166" });
    rings.push({ x: 760, y: 280, r: 10, max: 120, life: 0.9, color: "#7dd3fc" });
    burst(480, 268, 20, ["#ffd166", "#7dd3fc", "#e0f2fe"], 100);
  }
  function possess() {
    view.mood = "possessed";
    shake(420);
    burst(480, 260, 28, ["#ff2d55", "#7f1d1d", "#a855f7"], 120);
  }
  function warded() {
    view.mood = "warded";
    rings.push({ x: 480, y: 268, r: 30, max: 150, life: 1.1, color: "#7dd3fc" });
    burst(480, 268, 22, ["#7dd3fc", "#e0f2fe", "#ffd166"], 90);
  }
  function tea() {
    view.mood = "idle";
    burst(524, 278, 12, ["#fef3c7", "#d6d3d1", "#fbbf24"], 28);
  }
  function hit(side) {
    shake(side === "red" ? 620 : 480);
    burst(480, 250, 26, side === "red"
      ? ["#ff2d55", "#a855f7", "#4ade80"]
      : ["#7dd3fc", "#e0f2fe", "#ffd166"], 160);
  }
  function reset() {
    parts.length = 0; bolts.length = 0; rings.length = 0;
    view.mood = "idle"; view.phase = "idle"; shakeUntil = 0;
  }

  return { init, set, shake, castRed, castBlue, possess, warded, tea, hit, reset };
})();
