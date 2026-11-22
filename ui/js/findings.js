export class FindingsController {
  constructor(options = {}) {
    this.listContainer = document.getElementById("issuesListContainer");
    this.countBadge = document.getElementById("issuesCountBadge");
    this.searchInput = document.getElementById("issuesSearch");
    this.inspectorContent = document.getElementById("inspectorContent");
    this.inspectorBadge = document.getElementById("inspectorSeverityBadge");

    this.onSelectFinding = options.onSelectFinding || (() => { });
    this.onProposePatch = options.onProposePatch || (() => { });

    this.findings = [];
    this.activeFilter = "ALL";
    this.searchQuery = "";
    this.selectedFinding = null;

    this.initFilterEvents();
  }

  initFilterEvents() {
    if (this.searchInput) {
      this.searchInput.addEventListener("input", (e) => {
        this.searchQuery = (e.target.value || "").toLowerCase().trim();
        this.renderList();
      });
    }

    const chips = document.querySelectorAll(".severity-filter-chips .chip");
    chips.forEach(chip => {
      chip.addEventListener("click", () => {
        chips.forEach(c => c.classList.remove("active"));
        chip.classList.add("active");
        this.activeFilter = chip.getAttribute("data-filter") || "ALL";
        this.renderList();
      });
    });
  }

  setFindings(findings = []) {
    this.findings = findings || [];
    if (this.countBadge) {
      this.countBadge.textContent = this.findings.length;
      if (this.findings.length > 0) {
        this.countBadge.classList.remove("count-zero");
      } else {
        this.countBadge.classList.add("count-zero");
      }
    }
    this.renderList();
    if (this.findings.length > 0) {
      this.selectFinding(this.findings[0]);
      this.onSelectFinding(this.findings[0]);
    } else {
      this.clearInspector();
    }
  }

  renderList() {
    if (!this.listContainer) return;

    let filtered = this.findings.filter(f => {
      const sev = (f.severity || "").toUpperCase();
      const cat = (f.category || "").toUpperCase();

      let matchesFilter = true;
      if (this.activeFilter !== "ALL") {
        if (this.activeFilter === "CODE_QUALITY") {
          matchesFilter = (cat === "CODE_QUALITY" || cat === "ARCHITECTURE");
        } else {
          matchesFilter = (sev === this.activeFilter);
        }
      }

      let matchesSearch = true;
      if (this.searchQuery) {
        const text = `${f.title} ${f.cwe_id || ''} ${f.file_path || ''} ${f.description || ''}`.toLowerCase();
        matchesSearch = text.includes(this.searchQuery);
      }

      return matchesFilter && matchesSearch;
    });

    if (filtered.length === 0) {
      this.listContainer.innerHTML = `<div class="empty-state">No matching findings found.</div>`;
      return;
    }

    this.listContainer.innerHTML = "";
    filtered.forEach(f => {
      const item = document.createElement("div");
      item.className = "issue-item";
      if (this.selectedFinding && this.selectedFinding.finding_id === f.finding_id) {
        item.style.borderColor = "var(--brand-primary)";
      }

      const sev = (f.severity || "MEDIUM").toUpperCase();
      const sevBadgeClass = `badge-severity ${sev.toLowerCase()}`;

      const relPath = (f.relative_file_path || f.file_path || "").replace(/\\/g, "/").split("/").pop();
      const line = f.start_line || f.line_number || 1;

      item.innerHTML = `
        <div class="issue-header">
          <span class="${sevBadgeClass}">${sev}</span>
          <span class="issue-meta">${relPath}:${line}</span>
        </div>
        <div class="issue-title" title="${f.title}">${f.title}</div>
      `;

      item.addEventListener("click", () => {
        this.selectFinding(f);
        this.onSelectFinding(f);
      });

      this.listContainer.appendChild(item);
    });
  }

  selectFinding(f) {
    this.selectedFinding = f;
    if (!this.inspectorContent) return;

    const sev = (f.severity || "INFO").toUpperCase();
    if (this.inspectorBadge) {
      this.inspectorBadge.textContent = sev;
      this.inspectorBadge.className = `badge-severity ${sev.toLowerCase()}`;
    }

    const cweText = f.cwe_id ? `${f.cwe_id} • ` : "";
    const catText = (f.category || "Security").toUpperCase();

    let exploitHtml = "";
    if (f.exploit_scenario) {
      exploitHtml = `
        <div class="finding-section">
          <span class="section-label">⚡ AI Exploit Scenario</span>
          <div class="exploit-card">
            <p>${this.escapeHtml(f.exploit_scenario)}</p>
          </div>
        </div>
      `;
    }

    let stepsHtml = "";
    if (Array.isArray(f.remediation_steps) && f.remediation_steps.length > 0) {
      stepsHtml = `
        <div class="finding-section">
          <span class="section-label">🛠️ Remediation Steps</span>
          <ul class="remediation-list">
            ${f.remediation_steps.map(s => `<li>${this.escapeHtml(s)}</li>`).join("")}
          </ul>
        </div>
      `;
    } else if (f.recommendation) {
      stepsHtml = `
        <div class="finding-section">
          <span class="section-label">🛠️ Recommendation</span>
          <p class="text-secondary" style="font-size:12px;">${this.escapeHtml(f.recommendation)}</p>
        </div>
      `;
    }

    this.inspectorContent.innerHTML = `
      <div class="finding-detail-card">
        <div class="finding-meta" style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono);">
          ${cweText}${catText}
        </div>
        <h3 class="finding-title">${this.escapeHtml(f.title)}</h3>
        <p class="finding-desc" style="font-size:12px; color:var(--text-secondary); line-height:1.4;">
          ${this.escapeHtml(f.description || f.risk_explanation || "")}
        </p>

        ${exploitHtml}
        ${stepsHtml}

        <button id="btnProposePatchInline" class="btn btn-primary" style="margin-top:8px;">
          <span>✨</span> Propose AI Patch
        </button>
      </div>
    `;

    const btnPropose = document.getElementById("btnProposePatchInline");
    if (btnPropose) {
      btnPropose.addEventListener("click", () => {
        this.onProposePatch(f);
      });
    }
  }

  clearInspector() {
    if (this.inspectorContent) {
      this.inspectorContent.innerHTML = `
        <div class="inspector-placeholder">
          <span>🔍</span>
          <p>No active vulnerability selected.</p>
        </div>`;
    }
    if (this.inspectorBadge) {
      this.inspectorBadge.textContent = "INFO";
      this.inspectorBadge.className = "badge-severity";
    }
  }

  escapeHtml(text) {
    return (text || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
}
