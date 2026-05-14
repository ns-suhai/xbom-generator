"""Interactive HTML report generator for xBOM scan results."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from xbom.models.bom_types import BomEntry, BomType, ScanResult


def generate_html_report(result: ScanResult) -> str:
    """Generate a single-file interactive HTML report.

    Uses Tailwind CSS + Alpine.js from CDN. Dark cybersecurity theme.
    Works offline -- all data embedded as JSON.
    """
    scan_data = _build_report_data(result)
    data_json = json.dumps(scan_data, indent=None, default=str)

    return _TEMPLATE.replace("/* __SCAN_DATA__ */{}", data_json)


def _build_ecosystem_data(result: ScanResult) -> list[dict[str, object]]:
    """Build ecosystem metadata for each skill entry."""
    ecosystems = []
    for entry in result.skill_entries:
        provenance = entry.metadata.get("provenance", {})
        graph = entry.metadata.get("execution_graph", {})
        findings = entry.metadata.get("findings", [])
        refs = entry.metadata.get("referenced_scripts", [])

        # Compute local scores (0-100 scale like Manifold)
        finding_count = len(findings)
        max_sev = entry.metadata.get("max_severity")
        static_score = 100
        if max_sev == "CRITICAL":
            static_score = 20
        elif max_sev == "HIGH":
            static_score = 40
        elif max_sev == "MEDIUM":
            static_score = 65
        elif finding_count > 0:
            static_score = 80

        # Lineage score: penalize missing version, missing author
        lineage_score = 100
        if not provenance.get("version"):
            lineage_score -= 30
        if not provenance.get("author"):
            lineage_score -= 20
        if refs:
            lineage_score -= 10  # External script dependencies add risk

        # Composite score
        composite_score = int(static_score * 0.6 + lineage_score * 0.4)

        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        network_targets = [n["id"] for n in nodes if n.get("type") == "network_target"]

        ecosystems.append({
            "name": entry.name,
            "version": provenance.get("version", "unversioned"),
            "author": provenance.get("author", "unknown"),
            "description": provenance.get("description", ""),
            "source": entry.metadata.get("file_type", "unknown"),
            "static_score": static_score,
            "lineage_score": lineage_score,
            "composite_score": composite_score,
            "finding_count": finding_count,
            "max_severity": max_sev or "Clean",
            "graph_nodes": len(nodes),
            "graph_edges": len(edges),
            "network_targets": network_targets,
            "referenced_scripts": refs,
            "content_hash": provenance.get("content_hash", ""),
        })
    return ecosystems


def _build_report_data(result: ScanResult) -> dict[str, object]:
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
        "ecosystem": _build_ecosystem_data(result),
        "warnings": list(result.warnings),
        "errors": list(result.errors),
    }


def _entry_to_dict(entry: "BomEntry") -> dict[str, object]:
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
<script src="https://cdn.tailwindcss.com"></script>
<script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
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
    <button class="tab-btn" :class="{'active':activeTab===t.id}" @click="activeTab=t.id"
      x-text="t.id==='ecosystem'?t.label+' ('+(data.ecosystem||[]).length+')':t.label+' ('+(data.summary[t.id]||0)+')'"></button>
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
  <div x-show="activeTab==='skillbom'">
    <template x-if="filtered('skillbom').length===0">
      <div class="glass rounded-lg p-8 text-center text-green-400/80">No agent supply chain assets found.</div>
    </template>
    <div x-show="filtered('skillbom').length>0">
      <!-- Skills Table -->
      <div class="glass rounded-lg overflow-hidden mb-6">
        <table>
          <thead><tr><th>Skill</th><th>Type</th><th>Findings</th><th>Max Severity</th><th>Referenced Scripts</th><th>Graph Nodes</th></tr></thead>
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
                <td class="mono text-xs text-slate-400" x-text="(e.metadata.referenced_scripts||[]).join(', ')||'—'"></td>
                <td class="text-xs text-slate-400" x-text="e.metadata.execution_graph?e.metadata.execution_graph.nodes.length+' nodes':'—'"></td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>

      <!-- Findings Detail -->
      <template x-for="e in filtered('skillbom')" :key="'findings-'+e.name">
        <div x-show="e.metadata.finding_count>0" class="glass rounded-lg overflow-hidden mb-6">
          <div class="px-4 py-2 border-b border-slate-700/30">
            <span class="text-sm font-semibold text-slate-200" x-text="e.name+' — Findings'"></span>
          </div>
          <table>
            <thead><tr><th>Category</th><th>Severity</th><th>Source</th><th>Line</th></tr></thead>
            <tbody>
              <template x-for="f in e.metadata.findings||[]" :key="f.category+f.line">
                <tr>
                  <td class="text-slate-200" x-text="f.category.replace(/_/g,' ')"></td>
                  <td>
                    <span class="badge" :class="f.severity==='CRITICAL'?'bg-red-500/20 text-red-400':f.severity==='HIGH'?'bg-orange-500/20 text-orange-400':'bg-yellow-500/20 text-yellow-400'"
                          x-text="f.severity"></span>
                  </td>
                  <td class="mono text-xs text-slate-400" x-text="f.source_file||'SKILL.md'"></td>
                  <td class="text-slate-400" x-text="f.line"></td>
                </tr>
              </template>
            </tbody>
          </table>
        </div>
      </template>

      <!-- Execution Graph (Analysis Graph) -->
      <template x-for="e in filtered('skillbom')" :key="'graph-'+e.name">
        <div x-show="e.metadata.execution_graph && e.metadata.execution_graph.nodes.length>0" class="glass rounded-lg overflow-hidden mb-6">
          <div class="px-4 py-2 border-b border-slate-700/30 flex items-center gap-2">
            <svg class="w-4 h-4 text-sky-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
            <span class="text-sm font-semibold text-slate-200" x-text="e.name+' — Execution Graph'"></span>
            <span class="text-xs text-slate-500 ml-2" x-text="e.metadata.execution_graph.nodes.length+' nodes, '+e.metadata.execution_graph.edges.length+' edges'"></span>
          </div>
          <div class="p-4">
            <div :id="'mermaid-'+e.name.replace(/[^a-zA-Z0-9]/g,'')" class="mermaid-container bg-slate-900/50 rounded-lg p-4 overflow-x-auto"></div>
          </div>
        </div>
      </template>
    </div>
  </div>

  <!-- Ecosystem Tab -->
  <div x-show="activeTab==='ecosystem'">
    <template x-if="(data.ecosystem||[]).length===0">
      <div class="glass rounded-lg p-8 text-center text-slate-400">No ecosystem data available. Scan skill files to generate ecosystem intelligence.</div>
    </template>
    <template x-for="eco in data.ecosystem||[]" :key="eco.name">
      <div class="glass rounded-lg overflow-hidden mb-6">
        <!-- Ecosystem Header -->
        <div class="px-6 py-4 border-b border-slate-700/30">
          <div class="flex items-center justify-between">
            <div>
              <h3 class="text-lg font-bold text-slate-100" x-text="eco.name"></h3>
              <p class="text-sm text-slate-400 mt-1" x-text="eco.description||'No description'"></p>
            </div>
            <div class="text-right">
              <div class="text-2xl font-bold" :class="eco.composite_score>=70?'text-green-400':eco.composite_score>=40?'text-yellow-400':'text-red-400'"
                   x-text="eco.composite_score+'/100'"></div>
              <div class="text-xs text-slate-500">Composite Score</div>
            </div>
          </div>
        </div>

        <!-- Score Breakdown -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 p-6">
          <!-- Static Analysis Score -->
          <div class="bg-slate-800/50 rounded-lg p-4">
            <div class="flex items-center justify-between mb-2">
              <span class="text-xs font-semibold text-slate-400 uppercase">Static Score</span>
              <span class="text-lg font-bold" :class="eco.static_score>=70?'text-green-400':eco.static_score>=40?'text-yellow-400':'text-red-400'"
                    x-text="eco.static_score"></span>
            </div>
            <div class="w-full bg-slate-700 rounded-full h-2">
              <div class="h-2 rounded-full transition-all" :class="eco.static_score>=70?'bg-green-500':eco.static_score>=40?'bg-yellow-500':'bg-red-500'"
                   :style="'width:'+eco.static_score+'%'"></div>
            </div>
            <div class="text-xs text-slate-500 mt-2">Pattern analysis &amp; code inspection</div>
          </div>

          <!-- Lineage Score -->
          <div class="bg-slate-800/50 rounded-lg p-4">
            <div class="flex items-center justify-between mb-2">
              <span class="text-xs font-semibold text-slate-400 uppercase">Lineage Score</span>
              <span class="text-lg font-bold" :class="eco.lineage_score>=70?'text-green-400':eco.lineage_score>=40?'text-yellow-400':'text-red-400'"
                    x-text="eco.lineage_score"></span>
            </div>
            <div class="w-full bg-slate-700 rounded-full h-2">
              <div class="h-2 rounded-full transition-all" :class="eco.lineage_score>=70?'bg-green-500':eco.lineage_score>=40?'bg-yellow-500':'bg-red-500'"
                   :style="'width:'+eco.lineage_score+'%'"></div>
            </div>
            <div class="text-xs text-slate-500 mt-2">Provenance, versioning &amp; authorship</div>
          </div>

          <!-- Risk Summary -->
          <div class="bg-slate-800/50 rounded-lg p-4">
            <div class="flex items-center justify-between mb-2">
              <span class="text-xs font-semibold text-slate-400 uppercase">Risk Level</span>
              <span class="badge" :class="eco.max_severity==='CRITICAL'?'bg-red-500/20 text-red-400':eco.max_severity==='HIGH'?'bg-orange-500/20 text-orange-400':eco.max_severity==='MEDIUM'?'bg-yellow-500/20 text-yellow-400':'bg-green-500/20 text-green-400'"
                    x-text="eco.max_severity"></span>
            </div>
            <div class="text-sm text-slate-300 mt-2" x-text="eco.finding_count+' finding'+(eco.finding_count!==1?'s':'')"></div>
            <div class="text-xs text-slate-500 mt-1" x-text="eco.graph_nodes+' graph nodes, '+eco.graph_edges+' edges'"></div>
          </div>
        </div>

        <!-- Metadata Grid -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-px bg-slate-700/30 border-t border-slate-700/30">
          <div class="bg-slate-900/50 p-3">
            <div class="text-xs text-slate-500 uppercase">Author</div>
            <div class="text-sm text-slate-200 font-mono mt-1" x-text="eco.author"></div>
          </div>
          <div class="bg-slate-900/50 p-3">
            <div class="text-xs text-slate-500 uppercase">Version</div>
            <div class="text-sm font-mono mt-1" :class="eco.version==='unversioned'?'text-yellow-400':'text-slate-200'" x-text="eco.version"></div>
          </div>
          <div class="bg-slate-900/50 p-3">
            <div class="text-xs text-slate-500 uppercase">Source Type</div>
            <div class="text-sm text-slate-200 mt-1" x-text="eco.source"></div>
          </div>
          <div class="bg-slate-900/50 p-3">
            <div class="text-xs text-slate-500 uppercase">Content Hash</div>
            <div class="text-xs text-slate-400 font-mono mt-1 truncate" x-text="eco.content_hash?eco.content_hash.substring(0,16)+'...':'—'"></div>
          </div>
        </div>

        <!-- Network Targets -->
        <div x-show="eco.network_targets.length>0" class="border-t border-slate-700/30 p-4">
          <div class="text-xs font-semibold text-slate-400 uppercase mb-2">Network Targets</div>
          <div class="flex flex-wrap gap-2">
            <template x-for="t in eco.network_targets" :key="t">
              <span class="inline-flex items-center gap-1 px-2 py-1 rounded-md bg-red-500/10 border border-red-500/20 text-xs text-red-300 font-mono">
                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" stroke-width="1.5"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" stroke-width="1.5"/></svg>
                <span x-text="t"></span>
              </span>
            </template>
          </div>
        </div>

        <!-- Referenced Scripts -->
        <div x-show="eco.referenced_scripts.length>0" class="border-t border-slate-700/30 p-4">
          <div class="text-xs font-semibold text-slate-400 uppercase mb-2">Referenced Scripts</div>
          <div class="flex flex-wrap gap-2">
            <template x-for="s in eco.referenced_scripts" :key="s">
              <span class="inline-flex items-center gap-1 px-2 py-1 rounded-md bg-sky-500/10 border border-sky-500/20 text-xs text-sky-300 font-mono">
                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                <span x-text="s"></span>
              </span>
            </template>
          </div>
        </div>
      </div>
    </template>
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
mermaid.initialize({theme:'dark',themeVariables:{
  primaryColor:'#1e3a5f',primaryTextColor:'#e2e8f0',primaryBorderColor:'#38bdf8',
  lineColor:'#475569',secondaryColor:'#1e293b',tertiaryColor:'#0f172a',
  fontFamily:'JetBrains Mono,monospace',fontSize:'12px'
},flowchart:{curve:'basis',padding:12}});

function xbomApp(){return{
  data:/* __SCAN_DATA__ */{},
  activeTab:'sbom',
  search:'',
  tabs:[
    {id:'sbom',label:'SBOM'},{id:'saasbom',label:'SaaSBOM'},
    {id:'mlbom',label:'ML-BOM'},{id:'cbom',label:'CBOM'},{id:'secrets',label:'Secrets'},
    {id:'skillbom',label:'Skills'},{id:'ecosystem',label:'Ecosystem'}
  ],
  init(){this.$nextTick(()=>{this.drawRadar();this.renderGraphs()})},
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
  renderGraphs(){
    const skills=this.data.skillbom||[];
    skills.forEach(e=>{
      const graph=e.metadata.execution_graph;
      if(!graph||!graph.nodes.length)return;
      const containerId='mermaid-'+e.name.replace(/[^a-zA-Z0-9]/g,'');
      const container=document.getElementById(containerId);
      if(!container)return;

      let lines=['graph LR'];
      const nodeStyles={};

      graph.nodes.forEach((n,i)=>{
        const id='n'+i;
        const label=n.id.replace(/"/g,"'");
        switch(n.type){
          case'referenced_script':
            lines.push('  '+id+'(["'+label+'"])');
            nodeStyles[id]='fill:#1e3a5f,stroke:#38bdf8,color:#38bdf8';
            break;
          case'network_target':
            lines.push('  '+id+'(("'+label+'"))');
            nodeStyles[id]='fill:#3b1a1a,stroke:#f87171,color:#fca5a5';
            break;
          case'tool_call':
            lines.push('  '+id+'["'+label+'"]');
            nodeStyles[id]='fill:#1a2e1a,stroke:#4ade80,color:#4ade80';
            break;
          case'shell_command':
            lines.push('  '+id+'>>"'+label+'"]');
            nodeStyles[id]='fill:#2d1f0e,stroke:#fbbf24,color:#fbbf24';
            break;
          case'file_access':
            lines.push('  '+id+'[/"'+label+'"/]');
            nodeStyles[id]='fill:#1f1a2e,stroke:#a78bfa,color:#a78bfa';
            break;
          case'env_access':
            lines.push('  '+id+'{{"'+label+'"}}');
            nodeStyles[id]='fill:#1a2e2d,stroke:#2dd4bf,color:#2dd4bf';
            break;
          case'skill_call':case'mcp_call':
            lines.push('  '+id+'(["'+label+'"])');
            nodeStyles[id]='fill:#2e1a2e,stroke:#f472b6,color:#f472b6';
            break;
          default:
            lines.push('  '+id+'["'+label+'"]');
            nodeStyles[id]='fill:#1e293b,stroke:#64748b,color:#94a3b8';
        }
      });

      graph.edges.forEach(edge=>{
        const fromIdx=graph.nodes.findIndex(n=>n.id===edge.from);
        const toIdx=graph.nodes.findIndex(n=>n.id===edge.to);
        if(fromIdx<0){
          const rootId='root';
          if(!lines.find(l=>l.includes(rootId+'['))){
            lines.splice(1,0,'  '+rootId+'["'+edge.from.replace(/"/g,"'")+'"]');
            nodeStyles[rootId]='fill:#0c4a6e,stroke:#0ea5e9,color:#e0f2fe,stroke-width:2px';
          }
          if(toIdx>=0) lines.push('  '+rootId+' --> n'+toIdx);
        }else{
          if(toIdx>=0) lines.push('  n'+fromIdx+' --> n'+toIdx);
        }
      });

      Object.entries(nodeStyles).forEach(([id,style])=>{
        lines.push('  style '+id+' '+style);
      });

      const graphDef=lines.join('\\n');
      mermaid.render('mermaid-svg-'+containerId,graphDef).then(({svg})=>{
        container.replaceChildren();
        container.insertAdjacentHTML('afterbegin',svg);
      }).catch(err=>{
        container.textContent='Graph render error: '+err.message;
      });
    });
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
