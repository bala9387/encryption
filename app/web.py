"""
app/web.py
============

Local operator console over app/service.py:
  /            status: ledger health, node agreement, identities
  /sender      upload a document, pick recipients, download the package
  /recipient   decrypt as an identity, download the watermarked copy
  /trace       upload a leaked file, get the attribution report

Everything is inline: markup, CSS, SVG icons and the small amount of
JavaScript. There is no CDN, no web font and no framework, because the system
must run inside an air gap. Nothing is fetched at run time.

This is an operator tool, not a public service. It binds to 127.0.0.1 and has
NO user authentication: anyone who can reach the port can act as any identity
whose passphrase they know. Put it behind the host's own access control
(see docs/DEPLOYMENT.md).
"""

from __future__ import annotations
import html
import io
import json
import os
import sys
import traceback
from pathlib import Path

_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from flask import Flask, get_flashed_messages, redirect, request, send_file, url_for, flash

from app.service import Workspace, ServiceError
from watermark.document_formats import UnsupportedFormat

MAX_UPLOAD_MB = 64

# --------------------------------------------------------------------- styling
CSS = """
*,*::before,*::after{box-sizing:border-box}
:root{
  --bg:#F3F6FA; --panel:#FFFFFF; --panel-2:#F7F9FC; --line:#D8E0EA; --line-soft:#E7ECF3;
  --fg:#0F1C2E; --muted:#52647B; --faint:#64768C;
  --accent:#0B5FCC; --accent-ink:#FFFFFF; --accent-soft:#EAF2FE; --accent-line:#CFE2FB;
  --ok:#0F6B45; --ok-soft:#EAF7F0; --ok-line:#B7E2CC;
  --warn:#8A5A00; --warn-soft:#FDF4E5; --warn-line:#F0D5A6;
  --bad:#A8232B; --bad-soft:#FCEEEE; --bad-line:#F0C3C3;
  --violet:#4E3BC4; --violet-soft:#EFECFD; --violet-line:#D8D2F8;
  --r-lg:14px; --r-md:10px; --r-sm:8px;
  --shadow:0 1px 2px rgba(16,24,40,.05), 0 10px 26px -18px rgba(16,24,40,.28);
  --mono:ui-monospace,"Cascadia Mono",Consolas,"SF Mono",monospace;
}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--fg);
  font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  -webkit-font-smoothing:antialiased;min-height:100vh}
a{color:var(--accent)}
.mono{font-family:var(--mono);font-size:13px;letter-spacing:.1px;word-break:break-all}

/* ---------- header ---------- */
header{position:sticky;top:0;z-index:40;background:rgba(255,255,255,.93);
  backdrop-filter:blur(10px);border-bottom:1px solid var(--line-soft)}
.bar{max-width:1280px;margin:0 auto;padding:13px 24px;display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:11px;font-weight:700;letter-spacing:.2px}
.brand .mark{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;
  background:linear-gradient(145deg,#12386F,#0B5FCC);color:#fff;border:1px solid #0A4FA8}
.brand small{display:block;font-weight:600;font-size:10.5px;color:var(--faint);letter-spacing:.8px;text-transform:uppercase}
nav{display:flex;gap:3px;margin-left:6px;flex-wrap:wrap}
nav a{color:var(--muted);text-decoration:none;padding:7px 13px;border-radius:8px;font-size:14px;
  display:inline-flex;align-items:center;gap:8px;border:1px solid transparent;transition:.15s}
nav a:hover{color:var(--fg);background:var(--panel-2)}
nav a.on{color:var(--accent);background:var(--accent-soft);border-color:var(--accent-line);font-weight:600}
.chips{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap}
.chip{font-size:11.5px;color:var(--muted);border:1px solid var(--line);background:var(--panel);
  padding:5px 10px;border-radius:7px;display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.chip b{color:var(--fg);font-weight:700}
.dot{width:7px;height:7px;border-radius:50%;background:#18A05F;box-shadow:0 0 0 3px rgba(24,160,95,.15)}
.dot.bad{background:#D0353D;box-shadow:0 0 0 3px rgba(208,53,61,.15)}

/* ---------- layout ---------- */
main{max-width:1280px;margin:0 auto;padding:34px 24px 72px}
.hero{margin-bottom:26px}
.eyebrow{font-size:11.5px;letter-spacing:1.5px;text-transform:uppercase;color:var(--accent);font-weight:700}
h1{font-size:30px;line-height:1.2;margin:9px 0 0;letter-spacing:-.5px;font-weight:700}
.lede{color:var(--muted);margin:11px 0 0;max-width:74ch}
.grid{display:grid;gap:18px}
.g2{grid-template-columns:repeat(2,minmax(0,1fr))}
.g3{grid-template-columns:repeat(3,minmax(0,1fr))}
.g4{grid-template-columns:repeat(4,minmax(0,1fr))}
.split{display:grid;gap:18px;grid-template-columns:minmax(0,1.35fr) minmax(0,1fr);align-items:start}
@media (max-width:900px){ .g2,.g3,.g4,.split{grid-template-columns:1fr} }
@media (max-width:640px){
  html,body{overflow-x:hidden}
  .bar{padding:11px 16px;gap:12px}
  main{padding:24px 16px 56px}
  .chips{margin-left:0;width:100%}
  .chip{font-size:11px}
  h1{font-size:24px}
  .card{padding:18px 16px}
  .drop{padding:20px 14px}
  .drop .big{font-size:14px}
  .kv td:first-child{width:42%}
}

/* ---------- cards ---------- */
.card{background:var(--panel);border:1px solid var(--line-soft);border-radius:var(--r-lg);
  padding:22px 24px;box-shadow:var(--shadow)}
.card h2{font-size:15px;margin:0;display:flex;align-items:center;gap:10px;letter-spacing:.1px;font-weight:700}
.card .sub{color:var(--muted);font-size:13.5px;margin:9px 0 0}
.icon{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;flex:none;
  background:var(--accent-soft);color:var(--accent);border:1px solid var(--accent-line)}
.icon.ok{background:var(--ok-soft);color:var(--ok);border-color:var(--ok-line)}
.icon.warn{background:var(--warn-soft);color:var(--warn);border-color:var(--warn-line)}
.icon.bad{background:var(--bad-soft);color:var(--bad);border-color:var(--bad-line)}
.icon.violet{background:var(--violet-soft);color:var(--violet);border-color:var(--violet-line)}
hr.sep{border:0;border-top:1px solid var(--line-soft);margin:18px 0}

/* ---------- stats & nodes ---------- */
.stat{background:var(--panel);border:1px solid var(--line-soft);border-radius:var(--r-md);
  padding:17px 18px;box-shadow:var(--shadow)}
.stat .k{font-size:11px;letter-spacing:1.1px;text-transform:uppercase;color:var(--faint);font-weight:700}
.stat .v{font-size:27px;font-weight:700;margin-top:7px;letter-spacing:-.6px}
.stat .n{font-size:12.5px;color:var(--muted);margin-top:3px}
.node{display:flex;align-items:center;gap:12px;padding:11px 14px;border:1px solid var(--line-soft);
  border-radius:var(--r-md);background:var(--panel-2)}
.node svg{color:var(--faint)}
.node .nm{font-family:var(--mono);font-size:12.5px}
.node .rc{margin-left:auto;font-size:12px;color:var(--muted);white-space:nowrap}

/* ---------- forms ---------- */
label{display:block;font-size:11.5px;letter-spacing:.6px;text-transform:uppercase;color:var(--faint);
  font-weight:700;margin:20px 0 8px}
input[type=text],input[type=password],select{width:100%;background:#fff;color:var(--fg);
  border:1px solid var(--line);border-radius:var(--r-sm);padding:11px 13px;font:inherit;font-size:14.5px;transition:.15s}
input:focus,select:focus,.drop:focus-visible{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(11,95,204,.15)}
input::placeholder{color:#94A3B4}
.drop{border:1.5px dashed var(--line);border-radius:var(--r-md);background:var(--panel-2);
  padding:26px 20px;text-align:center;cursor:pointer;transition:.15s;display:block;color:var(--accent)}
.drop:hover,.drop.hot{border-color:var(--accent);background:var(--accent-soft)}
.drop .big{font-weight:600;margin-top:10px;color:var(--fg)}
.drop .hint{color:var(--faint);font-size:12.5px;margin-top:5px}
.drop.filled{border-style:solid;border-color:var(--ok-line);background:var(--ok-soft);color:var(--ok)}
.drop input[type=file]{display:none}
.picks{display:flex;flex-wrap:wrap;gap:9px}
.pick{position:relative;text-transform:none;letter-spacing:0;margin:0;font-weight:400}
.pick input{position:absolute;opacity:0;inset:0;cursor:pointer}
.pick span{display:inline-flex;align-items:center;gap:9px;padding:9px 15px;border-radius:8px;
  border:1px solid var(--line);background:#fff;font-size:14px;cursor:pointer;transition:.15s;color:var(--fg)}
.pick span::before{content:"";width:15px;height:15px;border-radius:4px;border:1.5px solid #B9C5D4;flex:none;background:#fff}
.pick input:checked+span{border-color:var(--accent);background:var(--accent-soft);font-weight:600}
.pick input:checked+span::before{background:var(--accent);border-color:var(--accent);box-shadow:inset 0 0 0 2px #fff}
.pick input:focus-visible+span{box-shadow:0 0 0 3px rgba(11,95,204,.18)}
.btn{margin-top:24px;display:inline-flex;align-items:center;gap:10px;border:0;cursor:pointer;
  background:var(--accent);color:var(--accent-ink);font:inherit;font-weight:600;font-size:15px;
  padding:12px 22px;border-radius:9px;transition:.15s;box-shadow:0 1px 2px rgba(16,24,40,.08)}
.btn:hover{background:#0A53B4}
.btn.ghost{background:#fff;border:1px solid var(--line);color:var(--fg)}
.empty{color:var(--muted);font-size:13.5px;background:var(--panel-2);border:1px dashed var(--line);
  border-radius:var(--r-md);padding:16px}

/* ---------- key/value ---------- */
.kv{width:100%;border-collapse:collapse;font-size:14px}
.kv td{padding:10px 0;border-bottom:1px solid var(--line-soft);vertical-align:top}
.kv tr:last-child td{border-bottom:0}
.kv td:first-child{color:var(--faint);width:34%;font-size:11.5px;letter-spacing:.6px;
  text-transform:uppercase;font-weight:700;padding-right:16px}
.copy{border:1px solid var(--line);background:#fff;color:var(--muted);cursor:pointer;
  padding:2px 7px;border-radius:5px;font-size:11px}
.copy:hover{color:var(--accent);border-color:var(--accent);background:var(--accent-soft)}

/* ---------- verdict + evidence chain ---------- */
.verdict{border-radius:var(--r-md);padding:18px 20px;display:flex;gap:14px;align-items:flex-start;margin-bottom:20px}
.verdict.y{background:var(--ok-soft);border:1px solid var(--ok-line);color:#0B4F34}
.verdict.n{background:var(--bad-soft);border:1px solid var(--bad-line);color:#7F1D23}
.verdict .t{font-size:11.5px;letter-spacing:1.3px;text-transform:uppercase;font-weight:800}
.verdict.y .t{color:var(--ok)}
.verdict.n .t{color:var(--bad)}
.verdict p{margin:6px 0 0;font-size:14.5px}
.chain{display:grid;gap:10px}
.step{display:flex;align-items:center;gap:13px;padding:13px 15px;border:1px solid var(--line-soft);
  border-radius:var(--r-md);background:var(--panel-2)}
.step svg{color:var(--faint)}
.step .lbl{font-weight:600;font-size:14px}
.step .val{color:var(--muted);font-size:13px;margin-top:2px}
.step .st{margin-left:auto;font-size:11px;letter-spacing:.8px;text-transform:uppercase;font-weight:800}
.step.pass{background:var(--ok-soft);border-color:var(--ok-line)}
.step.pass svg{color:var(--ok)}
.step.pass .st{color:var(--ok)}
.step.fail{background:var(--bad-soft);border-color:var(--bad-line)}
.step.fail svg{color:var(--bad)}
.step.fail .st{color:var(--bad)}
.step.idle .st{color:var(--faint)}
.flash{border:1px solid var(--bad-line);background:var(--bad-soft);color:#7F1D23;padding:13px 16px;
  border-radius:var(--r-md);margin-bottom:20px;display:flex;gap:11px;align-items:center}
.note{color:var(--faint);font-size:12.5px;margin-top:16px}
code{font-family:var(--mono);font-size:12.5px;background:var(--panel-2);border:1px solid var(--line-soft);
  padding:2px 7px;border-radius:5px;color:#1C3A5E}

/* ---------- busy overlay & progress bar ---------- */
#busy{position:fixed;inset:0;z-index:90;display:none;place-items:center;
  background:rgba(243,246,250,.90);backdrop-filter:blur(4px);transition:opacity .2s ease}
#busy.on{display:grid}
#busy .box{background:#fff;border:1px solid var(--line);border-radius:var(--r-lg);padding:28px 34px;
  text-align:center;box-shadow:0 24px 50px -18px rgba(16,24,40,.38);width:100%;max-width:410px}
.spin{width:36px;height:36px;margin:0 auto 14px;border-radius:50%;
  border:3.5px solid #E2EBF6;border-top-color:var(--accent);animation:sp .75s cubic-bezier(.6,.2,.4,.8) infinite}
@keyframes sp{ to{transform:rotate(360deg)} }
#busy .m{font-size:16px;font-weight:700;color:var(--fg);margin-bottom:4px}
#busy .s{color:var(--muted);font-size:13px;min-height:18px}

.pbar-wrap{margin:18px 0 6px}
.pbar-track{width:100%;height:10px;background:#EBF0F7;border-radius:999px;overflow:hidden;position:relative;border:1px solid var(--line-soft)}
.pbar-fill{height:100%;width:0%;background:linear-gradient(90deg,#0B5FCC,#3B82F6,#6366F1);border-radius:999px;
  transition:width .2s ease-out;position:relative;overflow:hidden}
.pbar-fill::after{content:'';position:absolute;inset:0;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.5),transparent);
  animation:pbar-shimmer 1.4s infinite;transform:translateX(-100%)}
@keyframes pbar-shimmer{ 100%{transform:translateX(100%)} }
.pbar-meta{display:flex;justify-content:space-between;align-items:center;font-size:12px;margin-top:7px;color:var(--muted);font-weight:600}
.pbar-pct{color:var(--accent);font-family:var(--mono);font-size:12.5px}
"""

JS = """
(function(){
  document.querySelectorAll('.drop').forEach(function(d){
    var inp = d.querySelector('input[type=file]');
    var out = d.querySelector('.big');
    var base = out.textContent;
    d.addEventListener('click', function(){ inp.click(); });
    d.addEventListener('keydown', function(e){ if(e.key==='Enter'||e.key===' '){ e.preventDefault(); inp.click(); } });
    ['dragenter','dragover'].forEach(function(ev){
      d.addEventListener(ev, function(e){ e.preventDefault(); d.classList.add('hot'); });
    });
    ['dragleave','drop'].forEach(function(ev){
      d.addEventListener(ev, function(e){ e.preventDefault(); d.classList.remove('hot'); });
    });
    d.addEventListener('drop', function(e){
      if(e.dataTransfer.files.length){ inp.files = e.dataTransfer.files; show(); }
    });
    inp.addEventListener('change', show);
    function show(){
      if(inp.files.length){
        var f = inp.files[0];
        out.textContent = f.name + '  (' + (f.size/1024).toFixed(0) + ' kB)';
        d.classList.add('filled');
      } else { out.textContent = base; d.classList.remove('filled'); }
    }
  });

  var busy = document.getElementById('busy');
  var pfill = document.getElementById('pbar-fill');
  var ppct = document.getElementById('pbar-pct');
  var pstage = document.getElementById('pbar-stage');
  var ptimer = null;

  function runProgress(totalDuration, stages) {
    if (ptimer) clearInterval(ptimer);
    var startTime = Date.now();
    pfill.style.width = '0%';
    pfill.style.background = 'linear-gradient(90deg,#0B5FCC,#3B82F6,#6366F1)';
    ppct.textContent = '0%';

    ptimer = setInterval(function(){
      var elapsed = Date.now() - startTime;
      var ratio = Math.min(elapsed / totalDuration, 0.96);
      var pct = Math.round(ratio * 100);
      pfill.style.width = pct + '%';
      ppct.textContent = pct + '%';

      for (var i = stages.length - 1; i >= 0; i--) {
        if (pct >= stages[i].at) {
          pstage.textContent = stages[i].text;
          break;
        }
      }
    }, 100);
  }

  document.querySelectorAll('form[data-busy]').forEach(function(f){
    f.addEventListener('submit', function(){
      var parts = f.getAttribute('data-busy').split('|');
      document.getElementById('busy-m').textContent = parts[0];
      document.getElementById('busy-s').textContent = parts[1] || '';

      var action = f.getAttribute('action') || window.location.pathname;
      var duration = 2400;
      var stages = [
        { at: 0, text: 'Reading input data…' },
        { at: 30, text: 'Generating cryptographic keys…' },
        { at: 65, text: 'Processing post-quantum payload…' },
        { at: 85, text: 'Finalizing…' }
      ];

      if (action.indexOf('sender') !== -1 || parts[0].indexOf('Encrypt') !== -1) {
        duration = 2000;
        stages = [
          { at: 0, text: 'Loading document…' },
          { at: 25, text: 'Generating AES-256 session key…' },
          { at: 55, text: 'Encapsulating ML-KEM-768 key-wraps…' },
          { at: 80, text: 'Building .ps26237 package…' },
          { at: 92, text: 'Preparing download…' }
        ];
      } else if (action.indexOf('recipient') !== -1 || parts[0].indexOf('Decrypt') !== -1) {
        duration = 2500;
        stages = [
          { at: 0, text: 'Verifying recipient credentials…' },
          { at: 25, text: 'Decapsulating ML-KEM-768 session key…' },
          { at: 50, text: 'Embedding unique invisible watermark…' },
          { at: 75, text: 'Signing record with ML-DSA-65…' },
          { at: 90, text: 'Committing to ledger quorum…' }
        ];
      } else if (action.indexOf('trace') !== -1 || parts[0].indexOf('watermark') !== -1) {
        duration = 13000;
        stages = [
          { at: 0, text: 'Rasterizing document…' },
          { at: 15, text: 'Extracting DCT frequency domain…' },
          { at: 35, text: 'Searching rotation angles & scale…' },
          { at: 60, text: 'Majority voting across redundant tiles…' },
          { at: 80, text: 'Querying multi-node ledger quorum…' },
          { at: 92, text: 'Cryptographic signature verification…' }
        ];
      }

      runProgress(duration, stages);
      busy.classList.add('on');
    });
  });

  window.addEventListener('pageshow', function(){
    if (ptimer) clearInterval(ptimer);
    busy.classList.remove('on');
  });

  busy.addEventListener('click', function(e){
    if (e.target === busy) {
      if (ptimer) clearInterval(ptimer);
      busy.classList.remove('on');
    }
  });

  document.querySelectorAll('.copy').forEach(function(b){
    b.addEventListener('click', function(){
      navigator.clipboard.writeText(b.dataset.v).then(function(){
        var t = b.textContent; b.textContent = 'copied'; setTimeout(function(){ b.textContent = t; }, 1100);
      });
    });
  });
})();
"""

ICONS = {
    "shield": '<path d="M12 3l7 3v5c0 4.4-3 8.3-7 10-4-1.7-7-5.6-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/>',
    "gauge": '<circle cx="12" cy="12" r="9"/><path d="M12 12l4-3"/>',
    "send": '<path d="M4 12h9m0 0l-4-4m4 4l-4 4"/><path d="M14 4h6v16h-6"/>',
    "inbox": '<path d="M4 13h4l2 3h4l2-3h4"/><path d="M5 5h14l1 8v6H4v-6z"/>',
    "search": '<circle cx="11" cy="11" r="6"/><path d="M20 20l-4.3-4.3"/>',
    "key": '<circle cx="8" cy="12" r="3"/><path d="M11 12h10m-3 0v3m-2-3v2"/>',
    "node": '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7.5h.01M7 17h.01"/>',
    "doc": '<path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5"/>',
    "check": '<path d="M4 12l5 5L20 6"/>',
    "alert": '<path d="M12 4l9 16H3z"/><path d="M12 10v4m0 3h.01"/>',
    "fingerprint": '<path d="M12 5a7 7 0 0 1 7 7v2"/><path d="M5 12a7 7 0 0 1 7-7"/><path d="M8.5 12a3.5 3.5 0 0 1 7 0v4"/><path d="M12 12v6"/><path d="M5 15v1"/>',
    "lock": '<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
}


def svg(name: str, size: int = 17, cls: str = "") -> str:
    return (f'<svg class="{cls}" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            f'stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" '
            f'aria-hidden="true">{ICONS[name]}</svg>')


def e(v) -> str:
    return html.escape(str(v), quote=True)


def create_app(ws: Workspace | None = None) -> Flask:
    if ws is None:
        from app.service import resolve_workspace_dir
        ws = Workspace(resolve_workspace_dir())
        ws.seed_demo_identities_if_empty()
    app = Flask(__name__)
    app.secret_key = "ps26237-local-console"
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

    def page(title: str, page_id: str, body: str) -> str:
        from crypto.pqc import MLKEM, MLDSA, BACKEND
        try:
            st = ws.ledger_status()
            healthy = st["integrity"]["network_consistent"]
            ledger_chip = (f'<span class="chip"><span class="dot{"" if healthy else " bad"}"></span>'
                           f'{e(ws.ledger_backend)} ledger <b>{st["records"]}</b> records</span>')
        except Exception:
            ledger_chip = '<span class="chip"><span class="dot bad"></span>ledger unavailable</span>'

        env_chip = ""
        if os.environ.get("VERCEL"):
            env_chip = '<span class="chip" style="background:var(--accent-soft);color:var(--accent);border-color:var(--accent-line)"><b>Vercel Serverless</b></span>'
        elif os.environ.get("NETLIFY") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or os.environ.get("LAMBDA_TASK_ROOT"):
            env_chip = '<span class="chip" style="background:var(--accent-soft);color:var(--accent);border-color:var(--accent-line)"><b>Cloud Serverless</b></span>'

        nav = "".join(
            f'<a href="{href}" class="{"on" if page_id == pid else ""}">{svg(ico, 16)}{label}</a>'
            for pid, href, label, ico in [
                ("home", "/", "Status", "gauge"),
                ("sender", "/sender", "Sender", "send"),
                ("recipient", "/recipient", "Recipient", "inbox"),
                ("trace", "/trace", "Forensic trace", "search"),
            ])
        flashes = "".join(f'<div class="flash">{svg("alert", 17)}<div>{e(m)}</div></div>'
                          for m in get_flashed_messages())
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)} · PS 26237</title><style>{CSS}</style></head><body>
<header><div class="bar">
  <div class="brand"><span class="mark">{svg("fingerprint", 17)}</span>
    <span>PRAMAAN<small>PS 26237 · attribution console</small></span></div>
  <nav>{nav}</nav>
  <div class="chips">{env_chip}{ledger_chip}
    <span class="chip">{svg("lock", 13)}{e(MLKEM.algorithm)} · {e(MLDSA.algorithm)}</span>
    <span class="chip">{e(BACKEND)}</span>
  </div>
</div></header>
<main>{flashes}{body}</main>
<div id="busy"><div class="box">
  <div class="spin" id="busy-spin"></div>
  <div class="m" id="busy-m">Working…</div>
  <div class="s" id="busy-s"></div>
  <div class="pbar-wrap">
    <div class="pbar-track"><div class="pbar-fill" id="pbar-fill"></div></div>
    <div class="pbar-meta"><span id="pbar-stage">Initializing…</span><span class="pbar-pct" id="pbar-pct">0%</span></div>
  </div>
</div></div>
<script>{JS}</script></body></html>"""

    def hero(eyebrow: str, title: str, lede: str) -> str:
        return (f'<div class="hero"><div class="eyebrow">{e(eyebrow)}</div>'
                f'<h1>{e(title)}</h1><p class="lede">{e(lede)}</p></div>')

    def drop(name: str, accept: str, label: str, hint: str) -> str:
        return (f'<div class="drop" tabindex="0" role="button">{svg("doc", 26, "")}'
                f'<div class="big">{e(label)}</div><div class="hint">{e(hint)}</div>'
                f'<input type="file" name="{name}" accept="{accept}" required></div>')

    def kv_row(k: str, v: str, mono: bool = False, copy: bool = False) -> str:
        val = f'<span class="mono">{v}</span>' if mono else v
        btn = f' <button type="button" class="copy" data-v="{e(v)}">copy</button>' if copy else ""
        return f"<tr><td>{e(k)}</td><td>{val}{btn}</td></tr>"

    # ------------------------------------------------------------------ errors
    @app.errorhandler(Exception)
    def on_error(err):
        if isinstance(err, (ServiceError, UnsupportedFormat)):
            flash(str(err))
        else:
            app.logger.error(traceback.format_exc())
            flash(f"{type(err).__name__}: {err}")
        return redirect(request.referrer or url_for("home")), 302

    # ------------------------------------------------------------------- status
    def node_records(v):
        """Fabric peers report a record count; simulated nodes report a chain length,
        which includes the genesis block."""
        if not isinstance(v, dict):
            return v
        if "records" in v:
            return v["records"]
        n = v.get("chain_length")
        return max(0, n - 1) if isinstance(n, int) else "-"

    @app.route("/")
    def home():
        st = ws.ledger_status()
        integ = st["integrity"]
        ok = integ["network_consistent"]
        tampered = set(integ.get("tampered_nodes", []))

        nodes = "".join(
            f'<div class="node"><span class="dot{"" if n not in tampered else " bad"}"></span>'
            f'<span class="nm">{e(n)}</span>'
            f'<span class="rc">{e(node_records(v))} records</span></div>'
            for n, v in integ["nodes"].items())

        ids = ws.list_identities()
        id_chips = "".join(f'<div class="node">{svg("key", 15)}<span class="nm">{e(i)}</span>'
                           f'<span class="rc">ML-KEM-768 · ML-DSA-65</span></div>' for i in ids) or \
            ('<div class="empty">No identities yet. Click below to seed demo identities or create one.</div>')

        identity_actions = f"""
        <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;align-items:center">
          <form method="post" action="/identities/seed_demo" style="margin:0">
            <button class="btn" type="submit" style="background:var(--violet);border-color:var(--violet);padding:7px 14px;font-size:13px">
              {svg("key", 15)} Seed Demo Identities (alice, bob, carol)
            </button>
          </form>
        </div>
        <details style="margin-top:14px;border-top:1px solid var(--line-soft);padding-top:10px">
          <summary style="cursor:pointer;color:var(--accent);font-weight:600;font-size:13px">+ Create custom identity</summary>
          <form method="post" action="/identities/new" style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
            <input type="text" name="identity_id" placeholder="ID (e.g. dave)" required style="flex:1;min-width:110px;padding:6px 10px;font-size:13px">
            <input type="password" name="passphrase" placeholder="Passphrase" required style="flex:1;min-width:110px;padding:6px 10px;font-size:13px">
            <button class="btn" type="submit" style="padding:6px 14px;font-size:13px">Add</button>
          </form>
        </details>
        """

        agreement = ('<b style="color:var(--ok)">all nodes agree</b>' if ok else
                     f'<b style="color:var(--bad)">disagreement: {e(", ".join(sorted(tampered)))}</b>')

        body = f"""
{hero("System status", "Attribution ledger is " + ("healthy" if ok else "reporting a conflict"),
      "Every decryption is watermarked, signed by the recipient and committed here before the document is released.")}
<div class="grid g4" style="margin-bottom:18px">
  <div class="stat"><div class="k">Ledger</div><div class="v">{e(ws.ledger_backend)}</div>
    <div class="n">{"4 org Fabric peers" if ws.ledger_backend == "fabric" else "in-process simulation"}</div></div>
  <div class="stat"><div class="k">Quorum</div><div class="v">{st['quorum']} of {len(st['nodes'])}</div>
    <div class="n">must hold the identical record</div></div>
  <div class="stat"><div class="k">Records</div><div class="v">{st['records']}</div>
    <div class="n">signed decryption events</div></div>
  <div class="stat"><div class="k">Identities</div><div class="v">{len(ids)}</div>
    <div class="n">post-quantum key pairs</div></div>
</div>
<div class="split">
  <div class="card"><h2><span class="icon{'' if ok else ' bad'}">{svg("node", 16)}</span>Ledger nodes</h2>
    <p class="sub">Each node is queried separately; a record counts only when {st['quorum']} of {len(st['nodes'])} return it
       identically — {agreement}.</p>
    <hr class="sep">
    <div class="grid" style="gap:10px">{nodes}</div>
  </div>
  <div class="card"><h2><span class="icon violet">{svg("key", 16)}</span>Identities</h2>
    <p class="sub">Secret keys are encrypted at rest with scrypt + AES-256-GCM under each holder's passphrase.</p>
    <hr class="sep">
    <div class="grid" style="gap:10px">{id_chips}</div>
    {identity_actions}
  </div>
</div>"""
        return page("Status", "home", body)

    # ------------------------------------------------------------------- sender
    @app.route("/sender", methods=["GET", "POST"])
    def sender():
        if request.method == "POST":
            f = request.files.get("doc")
            if not f or not f.filename:
                raise ServiceError("choose a document")
            pkg = ws.encrypt(f.read(), f.filename, request.form.getlist("recipients"),
                             request.form.get("doc_id") or None)
            info = ws.package_info(pkg)
            return send_file(io.BytesIO(pkg), as_attachment=True,
                             download_name=f"{info['document_id']}.ps26237", mimetype="application/json")

        ids = ws.list_identities()
        picks = "".join(f'<label class="pick"><input type="checkbox" name="recipients" value="{e(i)}">'
                        f'<span>{e(i)}</span></label>' for i in ids) or \
            ('<div class="empty">No identities yet — '
             '<form method="post" action="/identities/seed_demo" style="display:inline">'
             '<button class="btn" type="submit" style="background:var(--violet);border-color:var(--violet);padding:4px 10px;font-size:12px;display:inline-flex;margin-left:6px">'
             'Seed Alice, Bob, Carol</button></form></div>')

        body = f"""
{hero("Sender", "Encrypt once, distribute to many",
      "One AES-256-GCM ciphertext is shared by every recipient. Only the small per-recipient key wrap differs, so the package grows by about 1.5 kB per person.")}
<div class="split">
  <div class="card">
    <form method="post" enctype="multipart/form-data" data-busy="Encrypting…|Wrapping the document key for each recipient">
      <label>Document</label>
      {drop("doc", ".png,.jpg,.jpeg,.pdf", "Drop a file here, or click to choose", "PNG, JPEG or PDF · up to 64 MB")}
      <div style="margin:7px 0 14px;font-size:12px;color:var(--muted)">Need a test file? <a href="/samples/sample_contract.png" download style="font-weight:600">sample_contract.png</a> · <a href="/samples/sample_memo.pdf" download style="font-weight:600">sample_memo.pdf</a></div>
      <label>Document ID <span style="text-transform:none;color:var(--faint)">(optional)</span></label>
      <input type="text" name="doc_id" placeholder="OP-BLUEHORIZON-ANNEX-C">
      <label>Recipients</label>
      <div class="picks">{picks}</div>
      <button class="btn" type="submit">{svg("send", 17)}Encrypt and download package</button>
      <p class="note">The package is a single .ps26237 file. Distribute it however you like — it is useless without a recipient's post-quantum secret key.</p>
    </form>
  </div>
  <div class="card"><h2><span class="icon">{svg("lock", 16)}</span>What happens</h2>
    <hr class="sep">
    <div class="chain">
      <div class="step idle">{svg("doc", 17)}<div><div class="lbl">Document key generated</div>
        <div class="val">Random 256-bit key, used once for this document</div></div></div>
      <div class="step idle">{svg("lock", 17)}<div><div class="lbl">Encrypted once</div>
        <div class="val">AES-256-GCM over the whole file</div></div></div>
      <div class="step idle">{svg("key", 17)}<div><div class="lbl">Key wrapped per recipient</div>
        <div class="val">ML-KEM-768 encapsulation, one wrap each</div></div></div>
    </div>
    <p class="note">No watermark is applied here. Marking happens at decryption, which is what makes each copy distinct.</p>
  </div>
</div>"""
        return page("Sender", "sender", body)

    # ---------------------------------------------------------------- recipient
    _downloads: dict[str, object] = {}
    _download_dir = Path("/tmp/ps26237_downloads") if (os.environ.get("VERCEL") or os.environ.get("NETLIFY") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or os.environ.get("LAMBDA_TASK_ROOT")) else None
    if _download_dir:
        try:
            _download_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            _download_dir = None

    def stash(res) -> str:
        import uuid
        t = uuid.uuid4().hex
        _downloads[t] = res
        if _download_dir:
            try:
                (_download_dir / f"{t}.bin").write_bytes(res.data)
                (_download_dir / f"{t}.json").write_text(json.dumps({"filename": res.filename}))
            except Exception:
                pass
        for old in list(_downloads)[:-20]:
            _downloads.pop(old, None)
        return t

    @app.route("/recipient", methods=["GET", "POST"])
    def recipient():
        if request.method == "POST":
            f = request.files.get("package")
            if not f or not f.filename:
                raise ServiceError("choose a package file")
            res = ws.decrypt(f.read(), request.form["rid"], request.form.get("passphrase", ""))
            r = res.record
            rows = "".join([
                kv_row("document", e(r["document_id"]), mono=True),
                kv_row("watermark id", e(r["watermark_id"]), mono=True, copy=True),
                kv_row("session", e(r["session_id"]), mono=True, copy=True),
                kv_row("time (UTC)", e(r["human_timestamp"])),
                kv_row("signature", f'ML-DSA-65, made with {e(r["recipient_id"])}\'s own private key'),
                kv_row("ledger reference", e(res.ledger_ref), mono=True),
                kv_row("committed on", e(", ".join(res.committed_on))),
            ])
            body = f"""
{hero("Recipient", "Released and recorded",
      "The watermarked copy is handed over only after the signed record is committed, so a decryption with no ledger entry cannot exist.")}
<div class="verdict y">{svg("check", 22)}<div><div class="t">Committed on {len(res.committed_on)} nodes</div>
  <p>Your copy of <b>{e(r['document_id'])}</b> is visually identical to every other recipient's, and carries a watermark
     that belongs to this session alone.</p></div></div>
<div class="split">
  <div class="card"><h2><span class="icon ok">{svg("doc", 16)}</span>Decryption record</h2><hr class="sep">
    <table class="kv">{rows}</table>
    <form method="post" action="/download"><input type="hidden" name="token" value="{stash(res)}">
      <button class="btn" type="submit">{svg("inbox", 17)}Download {e(res.filename)}</button></form>
  </div>
  <div class="card"><h2><span class="icon violet">{svg("fingerprint", 16)}</span>Why this is binding</h2><hr class="sep">
    <div class="chain">
      <div class="step pass">{svg("key", 17)}<div><div class="lbl">Your key, your decryption</div>
        <div class="val">Only your ML-KEM-768 secret key unwraps this document</div></div><span class="st">done</span></div>
      <div class="step pass">{svg("fingerprint", 17)}<div><div class="lbl">Watermark embedded</div>
        <div class="val">Unique to you and this session</div></div><span class="st">done</span></div>
      <div class="step pass">{svg("lock", 17)}<div><div class="lbl">Signed by you</div>
        <div class="val">ML-DSA-65 over the record — non-repudiable</div></div><span class="st">done</span></div>
      <div class="step pass">{svg("node", 17)}<div><div class="lbl">Endorsed by the ledger</div>
        <div class="val">{e(len(res.committed_on))} nodes hold the identical record</div></div><span class="st">done</span></div>
    </div>
  </div>
</div>"""
            return page("Recipient", "recipient", body)

        ids = ws.list_identities()
        opts = "".join(f"<option>{e(i)}</option>" for i in ids)
        body = f"""
{hero("Recipient", "Decrypt your copy",
      "Your key unwraps the document key, a watermark unique to this session is embedded, and you sign the record before the file is released.")}
<div class="split">
  <div class="card">
    <form method="post" enctype="multipart/form-data" data-busy="Decrypting…|Watermarking, signing and committing to the ledger">
      <label>Encrypted package</label>
      {drop("package", ".ps26237,.json", "Drop the .ps26237 package here, or click to choose", "Produced by the sender page or the CLI")}
      <label>Decrypt as</label><select name="rid" required>{opts}</select>
      <label>Passphrase</label><input type="password" name="passphrase" placeholder="unlocks your post-quantum secret keys" required>
      <button class="btn" type="submit">{svg("inbox", 17)}Decrypt, watermark and commit</button>
      <p class="note">If the ledger commit fails, nothing is released — you get an error instead of a file.</p>
    </form>
  </div>
  <div class="card"><h2><span class="icon warn">{svg("alert", 16)}</span>Before you continue</h2><hr class="sep">
    <p class="sub">This decryption will be recorded permanently: your identity, the document, the session and the time,
       signed with your own private key. The record cannot be edited or deleted afterwards, by you or by an administrator.</p>
    <p class="sub">Your copy will look identical to everyone else's. If it leaks, it will trace back to this session.</p>
  </div>
</div>"""
        return page("Recipient", "recipient", body)

    @app.route("/download", methods=["POST"])
    def download():
        token = request.form.get("token", "")
        res = _downloads.pop(token, None)
        if res is not None:
            return send_file(io.BytesIO(res.data), as_attachment=True, download_name=res.filename)
        if _download_dir and token:
            bin_p = _download_dir / f"{token}.bin"
            meta_p = _download_dir / f"{token}.json"
            if bin_p.exists() and meta_p.exists():
                try:
                    meta = json.loads(meta_p.read_text())
                    data = bin_p.read_bytes()
                    return send_file(io.BytesIO(data), as_attachment=True, download_name=meta.get("filename", "download"))
                except Exception:
                    pass
        raise ServiceError("download expired — decrypt again")

    # -------------------------------------------------------------------- trace
    @app.route("/trace", methods=["GET", "POST"])
    def trace():
        if request.method == "POST":
            f = request.files.get("leaked")
            if not f or not f.filename:
                raise ServiceError("choose the leaked file")
            out = ws.trace(f.read())
            d = out.to_dict()
            rec, lk, ex = d["record"], d["ledger"], (d["extraction"] or {})
            confirmed = d["confirmed"]
            dist = d["match_distance_bits"]

            conf = float(ex.get("confidence", 0) or 0)
            conf_ok = conf >= 0.60   # below this the bits are mostly noise

            def step(ok, icon, label, value, state_text):
                cls = "pass" if ok else ("fail" if ok is False else "idle")
                return (f'<div class="step {cls}">{svg(icon, 17)}<div><div class="lbl">{label}</div>'
                        f'<div class="val">{value}</div></div><span class="st">{state_text}</span></div>')

            chain = "".join([
                step(None if not conf_ok else True, "fingerprint", "Watermark extracted",
                     f'{e(ex.get("method", "-"))} · sync confidence {conf:.2f} · '
                     f'rotation {ex.get("angle", 0):+.2f}° · scale ×{ex.get("scale", 1):.3f}',
                     "recovered" if conf_ok else "weak signal"),
                step(lk["found"], "search", "Matched against the ledger",
                     ("exact match" if dist == 0 else f"{dist} of 128 bits differ (≤16 accepted)") if lk["found"]
                     else "no record holds this watermark",
                     "match" if lk["found"] else "no match"),
                step(lk["verified"], "node", "Quorum agreement",
                     f'{lk["quorum_achieved"]} nodes returned the identical record · {lk["quorum_needed"]} required'
                     + (f' — {e(", ".join(lk["agreeing_nodes"]))}' if lk["agreeing_nodes"] else ""),
                     "verified" if lk["verified"] else "insufficient"),
                step(d["signature_valid"], "lock", "Recipient's signature",
                     "ML-DSA-65 signature re-verified against the published key" if d["signature_valid"]
                     else ("the stored signature did not verify" if d["signature_valid"] is False
                           else "nothing to verify — no record was matched"),
                     "valid" if d["signature_valid"] else ("invalid" if d["signature_valid"] is False else "not checked")),
            ])

            rows = "".join(kv_row(k.replace("_", " "), e(v), mono=True) for k, v in rec.items()) or \
                '<tr><td colspan="2" style="color:var(--muted);text-transform:none">No ledger record matched this watermark.</td></tr>'
            tried = ""
            if len(d["candidates_tried"]) > 1:
                tried = "<hr class='sep'><p class='sub'>" + " · ".join(
                    f'{e(c["source"])}: confidence {c["confidence"]}' for c in d["candidates_tried"]) + "</p>"

            who = e(rec.get("recipient_id", "unknown")) if rec else "unknown"
            body = f"""
{hero("Forensic trace", "Attribution report",
      "The watermark is recovered from the leaked copy, matched against a quorum of ledger nodes, and the recipient's own signature is re-verified.")}
<div class="verdict {'y' if confirmed else 'n'}">{svg('check' if confirmed else 'alert', 22)}
  <div><div class="t">{'Attributed to ' + who if confirmed else 'Not attributed'}</div>
  <p>{e(d['verdict']).replace(' -- ', ' — ')}</p></div></div>
<div class="split">
  <div class="card"><h2><span class="icon{' ok' if confirmed else ' bad'}">{svg("search", 16)}</span>Evidence chain</h2>
    <p class="sub">All four must hold before a name is reported.</p><hr class="sep">
    <div class="chain">{chain}</div>{tried}
    <p class="note">Extracted watermark <span class="mono">{e(d['extracted_watermark_id'])}</span> · source {e(d['source'])}</p>
  </div>
  <div class="card"><h2><span class="icon violet">{svg("doc", 16)}</span>Ledger record</h2>
    <p class="sub">As held by the agreeing nodes.</p><hr class="sep">
    <table class="kv">{rows}</table>
  </div>
</div>"""
            return page("Trace", "trace", body)

        body = f"""
{hero("Forensic trace", "Identify the source of a leak",
      "Upload a leaked copy. The extractor searches for rotation, rescaling and cropping, then attribution requires both a ledger quorum and a valid post-quantum signature.")}
<div class="split">
  <div class="card">
    <form method="post" enctype="multipart/form-data" data-busy="Analysing…|Searching rotation and scale, then querying the ledger quorum">
      <label>Leaked file</label>
      {drop("leaked", ".png,.jpg,.jpeg,.pdf", "Drop the leaked file here, or click to choose", "PNG, JPEG or PDF — cropped, rescaled or recompressed is fine")}
      <button class="btn" type="submit">{svg("search", 17)}Analyse</button>
      <p class="note">An untouched or lightly compressed copy resolves in under a second. A rotated or rescaled one triggers a geometry search that can take about 20 seconds.</p>
    </form>
  </div>
  <div class="card"><h2><span class="icon">{svg("shield", 16)}</span>What survives</h2><hr class="sep">
    <div class="chain">
      <div class="step pass">{svg("check", 17)}<div><div class="lbl">Cropping, rescaling, rotation</div>
        <div class="val">8 of 8 test documents recovered exactly</div></div><span class="st">yes</span></div>
      <div class="step pass">{svg("check", 17)}<div><div class="lbl">JPEG down to quality 75</div>
        <div class="val">and Gaussian noise</div></div><span class="st">yes</span></div>
      <div class="step fail">{svg("alert", 17)}<div><div class="lbl">Print-and-scan</div>
        <div class="val">3 of 8 — unreliable, measured</div></div><span class="st">partly</span></div>
      <div class="step fail">{svg("alert", 17)}<div><div class="lbl">Photograph of a screen</div>
        <div class="val">0 of 8 — does not survive</div></div><span class="st">no</span></div>
    </div>
    <p class="note">When the watermark is too damaged, the verdict is NO MATCH. The system never guesses a name.</p>
  </div>
</div>"""
        return page("Trace", "trace", body)

    @app.route("/api/status")
    def api_status():
        return json.dumps(ws.ledger_status(), indent=1), 200, {"Content-Type": "application/json"}

    @app.route("/identities/new", methods=["POST"])
    def new_identity():
        rid = request.form.get("identity_id", "").strip().lower()
        pw = request.form.get("passphrase", "")
        if not rid:
            flash("Identity ID cannot be empty")
            return redirect(url_for("home"))
        if len(pw) < 4:
            flash("Passphrase must be at least 4 characters")
            return redirect(url_for("home"))
        try:
            ws.create_identity(rid, pw)
            flash(f"Identity '{rid}' created successfully with ML-KEM-768 and ML-DSA-65 keypairs.")
        except Exception as ex:
            flash(f"Error creating identity '{rid}': {ex}")
        return redirect(request.referrer or url_for("home"))

    @app.route("/identities/seed_demo", methods=["POST"])
    def seed_demo():
        created = []
        for name in ["alice", "bob", "carol"]:
            if name not in ws.list_identities():
                try:
                    ws.create_identity(name, "password123")
                    created.append(name)
                except Exception:
                    pass
        if created:
            flash(f"Demo identities created: {', '.join(created)} (passphrase: password123)")
        else:
            flash("Demo identities (alice, bob, carol) already exist.")
        return redirect(request.referrer or url_for("home"))

    @app.route("/samples/<path:filename>")
    def sample_file(filename):
        sample_path = os.path.join(_parent, "public", "samples", os.path.basename(filename))
        if os.path.exists(sample_path):
            mimetype = "application/pdf" if filename.endswith(".pdf") else "image/png"
            return send_file(sample_path, mimetype=mimetype)
        flash(f"Sample file {filename} not found")
        return redirect(url_for("sender"))

    return app


if __name__ == "__main__":
    workspace_dir = os.environ.get("PS26237_HOME", "ps26237_workspace")
    ws = Workspace(workspace_dir)
    web_app = create_app(ws)
    print(f"PS26237 web UI on http://127.0.0.1:8237 (workspace {os.path.abspath(workspace_dir)}, ledger {ws.ledger_backend})")
    web_app.run(host="127.0.0.1", port=8237, debug=False, threaded=True)

