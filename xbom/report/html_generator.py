"""Interactive HTML report generator for xBOM scan results."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from xbom.models.bom_types import BomType, ScanResult


def generate_html_report(result: ScanResult) -> str:
    """Generate a single-file interactive HTML report.

    Uses Tailwind CSS + Alpine.js from CDN. Dark cybersecurity theme.
    Works offline -- all data embedded as JSON.
    """
    scan_data = _build_report_data(result)
    data_json = json.dumps(scan_data, indent=None, default=str)

    return _TEMPLATE.replace("/* __SCAN_DATA__ */{}", data_json)


def _build_report_data(result: ScanResult) -> dict:
    return {
        "package": result.package_path,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_ms": result.scan_duration_ms,
        "safe_level": result.safe_level.value,
        "safe_label": result.safe_level.label,
        "safe_color": result.safe_level.color,
        "risk_score": round(result.risk_score, 2),
        "dimensions": [
            {"name": d.name, "score": round(d.score, 1), "weight": d.weight}
            for d in result.dimension_scores
        ],
        "summary": {
            "sbom": len(result.sbom_entries),
            "saasbom": len(result.saasbom_entries),
            "mlbom": len(result.mlbom_entries),
            "cbom": len(result.cbom_entries),
            "secrets": len(result.secrets_entries),
            "skillbom": len(result.skill_entries),
        },
        "sbom": [_entry_to_dict(e) for e in result.sbom_entries],
        "saasbom": [_entry_to_dict(e) for e in result.saasbom_entries],
        "mlbom": [_entry_to_dict(e) for e in result.mlbom_entries],
        "cbom": [_entry_to_dict(e) for e in result.cbom_entries],
        "secrets": [_entry_to_dict(e) for e in result.secrets_entries],
        "skillbom": [_entry_to_dict(e) for e in result.skill_entries],
        "warnings": list(result.warnings),
        "errors": list(result.errors),
    }


def _entry_to_dict(entry) -> dict:
    return {
        "name": entry.name,
        "version": entry.version or "",
        "metadata": entry.metadata,
    }


_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>xBOM Report</title>
<script src="https://cdn.tailwindcss.com/3.4.17"></script>
<script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.14.8/dist/cdn.min.js" integrity="sha384-JMCk5VBaxHsPS/jVEFn3Fy/M6IxfMPtYEuGBiS20FV5l6RAFMzE+gWJHmvUfROVH" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js" integrity="sha384-Ggk6LGRl6bJesXEsVkNZPceNz4p9OoI60DjGPO1mYMBjFJq/EONqBW6+HfwxE2s0" crossorigin="anonymous"></script>
<style>
body{background:#0f172a;color:#e2e8f0;font-family:Inter,system-ui,sans-serif}
.glass{background:rgba(30,41,59,.65);backdrop-filter:blur(12px);border:1px solid rgba(56,189,248,.12)}
table{border-collapse:collapse;width:100%}
th{background:rgba(14,165,233,.18);text-align:left}
th,td{padding:.5rem .75rem;border:1px solid rgba(56,189,248,.1);font-size:.8rem}
tr:nth-child(even){background:rgba(30,41,59,.4)}
.tab-btn{padding:.5rem 1rem;border-radius:.5rem .5rem 0 0;cursor:pointer;font-size:.85rem;font-weight:600;transition:all .2s}
.tab-btn.active{background:rgba(14,165,233,.2);color:#38bdf8;border-bottom:2px solid #38bdf8}
.tab-btn:not(.active){color:#94a3b8}
.tab-btn:hover:not(.active){color:#e2e8f0;background:rgba(30,41,59,.5)}
input[type=text]{background:rgba(15,23,42,.8);border:1px solid rgba(56,189,248,.2);color:#e2e8f0;border-radius:.375rem;padding:.4rem .75rem;font-size:.8rem}
.badge{display:inline-block;padding:2px 10px;border-radius:9999px;font-size:.7rem;font-weight:600}
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
code,td.mono{font-family:'JetBrains Mono',monospace}
</style>
</head>
<body x-data="xbomApp()" x-init="init()">

<!-- Header: Risk Score + Summary -->
<header class="glass border-b border-slate-700/50">
<div class="max-w-7xl mx-auto px-6 py-4">
  <div class="flex flex-wrap items-center gap-6">
    <!-- Risk Badge -->
    <div class="flex items-center gap-3">
      <div class="w-16 h-16 rounded-xl flex items-center justify-center text-2xl font-bold"
           :style="`background:${data.safe_color}22;color:${data.safe_color};border:2px solid ${data.safe_color}`">
        <span x-text="'S'+data.safe_level"></span>
      </div>
      <div>
        <div class="text-lg font-bold" :style="`color:${data.safe_color}`" x-text="data.safe_label"></div>
        <div class="text-xs text-slate-400">Score: <span x-text="data.risk_score"></span>/5.00</div>
      </div>
    </div>
    <!-- Radar Chart -->
    <div class="w-28 h-28"><canvas id="radarChart"></canvas></div>
    <!-- Package Info -->
    <div class="ml-auto text-right text-sm">
      <div class="text-slate-300 font-mono text-xs" x-text="data.package.split('/').pop()"></div>
      <div class="text-slate-500 text-xs" x-text="new Date(data.timestamp).toLocaleString()"></div>
      <div class="text-slate-500 text-xs" x-text="data.duration_ms + 'ms'"></div>
    </div>
  </div>
  <!-- Summary Bar -->
  <div class="flex flex-wrap gap-4 mt-3 text-xs">
    <span class="badge" style="background:rgba(56,189,248,.15);color:#38bdf8" x-text="data.summary.sbom+' Components'"></span>
    <span class="badge" style="background:rgba(74,222,128,.15);color:#4ade80" x-text="data.summary.saasbom+' Services'"></span>
    <span class="badge" style="background:rgba(167,139,250,.15);color:#a78bfa" x-text="data.summary.mlbom+' Models'"></span>
    <span class="badge" style="background:rgba(251,191,36,.15);color:#fbbf24" x-text="data.summary.cbom+' Crypto'"></span>
    <span class="badge" style="background:rgba(251,113,133,.15);color:#fb7185" x-text="data.summary.secrets+' Secrets'"></span>
    <span class="badge" style="background:rgba(249,115,22,.15);color:#f97316" x-text="data.summary.skillbom+' Skills'"></span>
  </div>
</div>
</header>

<!-- Tab Navigation -->
<nav class="max-w-7xl mx-auto px-6 pt-4 flex flex-wrap gap-1 border-b border-slate-700/30">
  <template x-for="t in tabs" :key="t.id">
    <button class="tab-btn" :class="{'active':activeTab===t.id}" @click="activeTab=t.id" x-text="t.label+' ('+data.summary[t.id]+')'"></button>
  </template>
</nav>

<!-- Tab Content -->
<main class="max-w-7xl mx-auto px-6 py-4">
  <!-- Search -->
  <div class="flex items-center gap-3 mb-4">
    <input type="text" x-model="search" placeholder="Search..." class="w-64"/>
    <button @click="exportJSON()" class="text-xs px-3 py-1.5 rounded bg-slate-700 hover:bg-slate-600 text-slate-300">Export CycloneDX JSON</button>
  </div>

  <!-- SBOM Tab -->
  <div x-show="activeTab==='sbom'" class="glass rounded-lg overflow-hidden">
    <template x-if="filtered('sbom').length===0">
      <div class="p-8 text-center text-slate-400">No components detected. Package may be empty or unrecognized.</div>
    </template>
    <table x-show="filtered('sbom').length>0">
      <thead><tr><th>Name</th><th>Version</th><th>License</th><th>Type</th><th>PURL</th></tr></thead>
      <tbody>
        <template x-for="e in filtered('sbom')" :key="e.name+e.version">
          <tr>
            <td class="font-semibold text-slate-200" x-text="e.name"></td>
            <td class="mono text-slate-400" x-text="e.version||'—'"></td>
            <td x-text="(e.metadata.licenses||[]).join(', ')||'—'"></td>
            <td class="text-slate-400" x-text="e.metadata.type||'library'"></td>
            <td class="mono text-xs text-slate-500 max-w-xs truncate" x-text="e.metadata.purl||'—'"></td>
          </tr>
        </template>
      </tbody>
    </table>
  </div>

  <!-- SaaSBOM Tab -->
  <div x-show="activeTab==='saasbom'" class="glass rounded-lg overflow-hidden">
    <template x-if="filtered('saasbom').length===0">
      <div class="p-8 text-center text-slate-400">No API endpoints found in this package.</div>
    </template>
    <table x-show="filtered('saasbom').length>0">
      <thead><tr><th>Service</th><th>URL</th><th>Protocol</th><th>Traffic</th><th>Last Seen</th><th>Classification</th></tr></thead>
      <tbody>
        <template x-for="e in filtered('saasbom')" :key="e.name">
          <tr>
            <td class="font-semibold text-slate-200" x-text="e.name"></td>
            <td class="mono text-xs text-slate-400" x-text="e.metadata.url||'—'"></td>
            <td x-text="e.metadata.protocol||'—'"></td>
            <td x-text="e.metadata.actual_traffic_volume?formatBytes(e.metadata.actual_traffic_volume):'—'"></td>
            <td class="text-slate-400 text-xs" x-text="e.metadata.last_seen||'—'"></td>
            <td x-text="e.metadata.data_classification||'—'"></td>
          </tr>
        </template>
      </tbody>
    </table>
  </div>

  <!-- ML-BOM Tab -->
  <div x-show="activeTab==='mlbom'" class="glass rounded-lg overflow-hidden">
    <template x-if="filtered('mlbom').length===0">
      <div class="p-8 text-center text-slate-400">No ML models detected.</div>
    </template>
    <table x-show="filtered('mlbom').length>0">
      <thead><tr><th>Model</th><th>Framework</th><th>Architecture</th><th>File</th><th>Size</th></tr></thead>
      <tbody>
        <template x-for="e in filtered('mlbom')" :key="e.name">
          <tr>
            <td class="font-semibold text-slate-200" x-text="e.name"></td>
            <td x-text="e.metadata.framework||'—'"></td>
            <td x-text="e.metadata.architecture||'—'"></td>
            <td class="mono text-xs text-slate-400" x-text="e.metadata.file_path||'—'"></td>
            <td x-text="e.metadata.file_size_bytes?formatBytes(e.metadata.file_size_bytes):'—'"></td>
          </tr>
        </template>
      </tbody>
    </table>
  </div>

  <!-- CBOM Tab -->
  <div x-show="activeTab==='cbom'" class="glass rounded-lg overflow-hidden">
    <template x-if="filtered('cbom').length===0">
      <div class="p-8 text-center text-slate-400">No crypto assets found.</div>
    </template>
    <table x-show="filtered('cbom').length>0">
      <thead><tr><th>Asset</th><th>Algorithm</th><th>Strength</th><th>Quantum Level</th><th>Source</th></tr></thead>
      <tbody>
        <template x-for="e in filtered('cbom')" :key="e.name">
          <tr>
            <td class="font-semibold text-slate-200" x-text="e.name"></td>
            <td x-text="e.metadata.algorithm||e.metadata.type||'—'"></td>
            <td>
              <span class="badge" :class="e.metadata.strength==='weak'?'bg-red-500/20 text-red-400':'bg-green-500/20 text-green-400'"
                    x-text="e.metadata.strength||'—'"></span>
            </td>
            <td x-text="e.metadata.quantum_level!==undefined?'L'+e.metadata.quantum_level:'—'"></td>
            <td class="mono text-xs text-slate-400" x-text="e.metadata.source_file||'—'"></td>
          </tr>
        </template>
      </tbody>
    </table>
  </div>

  <!-- Secrets Tab -->
  <div x-show="activeTab==='secrets'" class="glass rounded-lg overflow-hidden">
    <template x-if="filtered('secrets').length===0">
      <div class="p-8 text-center text-green-400/80">No secrets detected. Good news!</div>
    </template>
    <table x-show="filtered('secrets').length>0">
      <thead><tr><th>Type</th><th>File</th><th>Line</th><th>Status</th></tr></thead>
      <tbody>
        <template x-for="e in filtered('secrets')" :key="e.name">
          <tr>
            <td class="font-semibold text-red-300" x-text="e.metadata.type||'unknown'"></td>
            <td class="mono text-xs text-slate-400" x-text="e.metadata.file_path||'—'"></td>
            <td x-text="e.metadata.line||'—'"></td>
            <td>
              <span class="badge" :class="e.metadata.is_active===true?'bg-red-500/20 text-red-400':e.metadata.is_active===false?'bg-green-500/20 text-green-400':'bg-slate-500/20 text-slate-400'"
                    x-text="e.metadata.is_active===true?'Active':e.metadata.is_active===false?'Inactive':'Unknown'"></span>
            </td>
          </tr>
        </template>
      </tbody>
    </table>
  </div>

  <!-- Skills Tab -->
  <div x-show="activeTab==='skillbom'" class="glass rounded-lg overflow-hidden">
    <template x-if="filtered('skillbom').length===0">
      <div class="p-8 text-center text-green-400/80">No agent supply chain assets found.</div>
    </template>
    <table x-show="filtered('skillbom').length>0">
      <thead><tr><th>Skill</th><th>Type</th><th>Findings</th><th>Max Severity</th><th>Exec Graph</th></tr></thead>
      <tbody>
        <template x-for="e in filtered('skillbom')" :key="e.name">
          <tr>
            <td class="font-semibold text-slate-200" x-text="e.name"></td>
            <td class="text-slate-400" x-text="e.metadata.file_type||'—'"></td>
            <td x-text="e.metadata.finding_count||0"></td>
            <td>
              <span class="badge" :class="e.metadata.max_severity==='CRITICAL'?'bg-red-500/20 text-red-400':e.metadata.max_severity==='HIGH'?'bg-orange-500/20 text-orange-400':e.metadata.max_severity==='MEDIUM'?'bg-yellow-500/20 text-yellow-400':'bg-green-500/20 text-green-400'"
                    x-text="e.metadata.max_severity||'Clean'"></span>
            </td>
            <td class="text-xs text-slate-400" x-text="e.metadata.execution_graph?e.metadata.execution_graph.nodes.length+' nodes':'—'"></td>
          </tr>
        </template>
      </tbody>
    </table>
  </div>

  <!-- Warnings -->
  <template x-if="data.warnings.length>0">
    <div class="mt-4 glass rounded-lg p-4">
      <div class="text-amber-400 text-sm font-semibold mb-2">Warnings</div>
      <template x-for="w in data.warnings"><div class="text-xs text-amber-300/70 mb-1" x-text="w"></div></template>
    </div>
  </template>
</main>

<footer class="border-t border-slate-700/30 py-4 text-center text-xs text-slate-500">
  Generated by xBOM Generator v0.1.0 | Netskope
</footer>

<script>
function xbomApp(){return{
  data:/* __SCAN_DATA__ */{},
  activeTab:'sbom',
  search:'',
  tabs:[
    {id:'sbom',label:'SBOM'},{id:'saasbom',label:'SaaSBOM'},
    {id:'mlbom',label:'ML-BOM'},{id:'cbom',label:'CBOM'},{id:'secrets',label:'Secrets'},
    {id:'skillbom',label:'Skills'}
  ],
  init(){this.$nextTick(()=>this.drawRadar())},
  filtered(tab){
    const items=this.data[tab]||[];
    if(!this.search)return items;
    const q=this.search.toLowerCase();
    return items.filter(e=>e.name.toLowerCase().includes(q)||JSON.stringify(e.metadata).toLowerCase().includes(q))
  },
  formatBytes(b){
    if(!b)return '—';
    const u=['B','KB','MB','GB'];let i=0;let v=b;
    while(v>=1024&&i<u.length-1){v/=1024;i++}
    return v.toFixed(1)+' '+u[i]
  },
  drawRadar(){
    const dims=this.data.dimensions||[];
    if(!dims.length)return;
    const ctx=document.getElementById('radarChart');
    if(!ctx)return;
    new Chart(ctx,{type:'radar',data:{
      labels:dims.map(d=>d.name),
      datasets:[{data:dims.map(d=>d.score),
        backgroundColor:'rgba(56,189,248,0.15)',borderColor:'#38bdf8',
        pointBackgroundColor:'#38bdf8',borderWidth:1.5,pointRadius:3}]
    },options:{scales:{r:{min:0,max:5,ticks:{stepSize:1,color:'#475569',font:{size:8}},
      grid:{color:'rgba(71,85,105,.3)'},pointLabels:{color:'#94a3b8',font:{size:9}}}},
      plugins:{legend:{display:false}},responsive:true,maintainAspectRatio:true}})
  },
  exportJSON(){
    const blob=new Blob([JSON.stringify(this.data,null,2)],{type:'application/json'});
    const a=document.createElement('a');
    a.href=URL.createObjectURL(blob);
    a.download='xbom-'+this.data.package.split('/').pop().replace(/\\.[^.]+$/,'')+'.json';
    a.click()
  }
}}
</script>
</body>
</html>'''
