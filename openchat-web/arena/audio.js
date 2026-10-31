/* Possessed Butler — chiptune organ, arcade SFX, and a very serious announcer. */
window.Sfx = (function () {
  "use strict";

  let ac = null, master = null, music = null, seq = null, step = 0, nextAt = 0;
  let on = true;
  try { on = localStorage.getItem("pb-sound") !== "off"; } catch (_) {}

  const midi = n => 440 * Math.pow(2, (n - 69) / 12);

  function ensure() {
    if (!ac) {
      const AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) return false;
      ac = new AC();
      master = ac.createGain();
      master.gain.value = on ? 0.55 : 0;
      master.connect(ac.destination);
      music = ac.createGain();
      music.gain.value = 0.13;
      music.connect(master);
    }
    if (ac.state === "suspended") ac.resume();
    return true;
  }

  function beep(freq, dur, type, vol, slideTo, dest) {
    if (!ensure()) return;
    const o = ac.createOscillator(), g = ac.createGain();
    o.type = type || "square";
    o.frequency.setValueAtTime(freq, ac.currentTime);
    if (slideTo) o.frequency.exponentialRampToValueAtTime(Math.max(20, slideTo), ac.currentTime + dur);
    g.gain.setValueAtTime(0.0001, ac.currentTime);
    g.gain.exponentialRampToValueAtTime(vol || 0.2, ac.currentTime + 0.01);
    g.gain.exponentialRampToValueAtTime(0.0001, ac.currentTime + dur);
    o.connect(g); g.connect(dest || master);
    o.start(); o.stop(ac.currentTime + dur + 0.02);
  }

  function noise(dur, vol, type, freq) {
    if (!ensure()) return;
    const n = Math.floor(ac.sampleRate * dur);
    const buf = ac.createBuffer(1, n, ac.sampleRate);
    const d = buf.getChannelData(0);
    for (let i = 0; i < n; i++) d[i] = (Math.random() * 2 - 1) * (1 - i / n);
    const src = ac.createBufferSource(); src.buffer = buf;
    const f = ac.createBiquadFilter(); f.type = type || "highpass"; f.frequency.value = freq || 900;
    const g = ac.createGain(); g.gain.value = vol || 0.15;
    src.connect(f); f.connect(g); g.connect(master);
    src.start();
  }

  const sfx = {
    click() { beep(520, 0.05, "square", 0.12); },
    type() { noise(0.03, 0.06, "highpass", 2200); },
    whoosh() { noise(0.35, 0.14, "bandpass", 500); beep(180, 0.25, "sawtooth", 0.06, 60); },
    bell() {
      [880, 1320, 1760].forEach((f, i) => beep(f, 0.9 - i * 0.2, "sine", 0.16 / (i + 1)));
      beep(440, 0.6, "triangle", 0.08);
    },
    shatter() { noise(0.3, 0.2, "highpass", 1800); beep(1200, 0.12, "square", 0.08, 200); },
    hit() { noise(0.18, 0.22, "lowpass", 300); beep(90, 0.22, "sawtooth", 0.18, 40); },
    point() { beep(660, 0.09, "square", 0.14); setTimeout(() => beep(990, 0.14, "square", 0.14), 90); },
    round() {
      beep(110, 1.1, "sawtooth", 0.12, 82);
      [220, 277, 330].forEach((f, i) => beep(f, 0.9, "triangle", 0.09, null, music));
    },
    fatality() {
      beep(330, 0.5, "sawtooth", 0.2, 70);
      noise(0.8, 0.18, "lowpass", 400);
      setTimeout(() => beep(55, 1.4, "sawtooth", 0.2, 30), 250);
    },
    win() {
      [523, 659, 784, 1046].forEach((f, i) => setTimeout(() => beep(f, 0.28, "square", 0.15), i * 130));
    }
  };

  /* D-minor organ loop: 32 steps of 16th-ish notes. */
  const BASS = [38, 38, 41, 41, 43, 43, 45, 45, 38, 38, 41, 41, 46, 46, 45, 45];
  const LEAD = [
    62, 0, 65, 69, 0, 68, 65, 0,
    62, 0, 65, 69, 0, 72, 69, 0,
    70, 0, 69, 65, 0, 62, 65, 0,
    69, 0, 68, 65, 0, 62, 60, 0
  ];

  function schedule() {
    if (!ac) return;
    while (nextAt < ac.currentTime + 0.5) {
      const s = step % 32;
      if (BASS[s]) beep(midi(BASS[s] - 12), 0.42, "triangle", 0.5, null, music);
      if (LEAD[s]) beep(midi(LEAD[s]), 0.2, "square", 0.18, null, music);
      if (s % 4 === 0) noise(0.05, 0.05, "highpass", 5000);
      nextAt += 0.26;
      step++;
    }
  }

  function startMusic() {
    if (!on || !ensure() || seq) return;
    nextAt = ac.currentTime + 0.1;
    seq = setInterval(schedule, 120);
  }

  function stopMusic() {
    clearInterval(seq); seq = null;
  }

  function announce(text) {
    if (!on || !window.speechSynthesis) return;
    try {
      const u = new SpeechSynthesisUtterance(text);
      u.pitch = 0.25; u.rate = 0.82; u.volume = 0.9;
      window.speechSynthesis.cancel();
      window.speechSynthesis.speak(u);
    } catch (_) { /* no voice, no problem */ }
  }

  function toggle() {
    on = !on;
    try { localStorage.setItem("pb-sound", on ? "on" : "off"); } catch (_) {}
    if (ensure()) master.gain.value = on ? 0.55 : 0;
    if (on) startMusic(); else { stopMusic(); if (window.speechSynthesis) window.speechSynthesis.cancel(); }
    return on;
  }

  function unlock() { ensure(); startMusic(); }

  return { sfx, announce, startMusic, stopMusic, toggle, unlock, get on() { return on; } };
})();
