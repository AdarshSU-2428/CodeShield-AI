import { api } from "./api.js";

export class AuditController {
  constructor(options = {}) {
    this.btnRun = document.getElementById("btnRunAudit");
    this.toggleAi = document.getElementById("toggleAiScan");
    this.hudStatus = document.getElementById("hudStatusText");
    this.hudProgress = document.getElementById("hudProgressFill");

    this.countCrit = document.getElementById("hudCountCritical");
    this.countHigh = document.getElementById("hudCountHigh");
    this.countMed = document.getElementById("hudCountMedium");
    this.countQual = document.getElementById("hudCountQuality");

    this.btnExportMenu = document.getElementById("btnExportMenu");
    this.exportDropdown = document.getElementById("exportDropdown");
    this.btnExportMd = document.getElementById("btnExportMarkdown");
    this.btnExportSarif = document.getElementById("btnExportSarif");
    this.btnExportZip = document.getElementById("btnExportZip");

    this.onAuditComplete = options.onAuditComplete || (() => { });
    this.currentProjectId = null;
    this.currentJobId = null;
    this.pollInterval = null;

    this.initEvents();
  }

  initEvents() {
    if (this.btnRun) {
      this.btnRun.addEventListener("click", () => this.startAudit());
    }

    if (this.btnExportMenu && this.exportDropdown) {
      this.btnExportMenu.addEventListener("click", (e) => {
        e.stopPropagation();
        this.exportDropdown.classList.toggle("hidden");
      });

      document.addEventListener("click", () => {
        this.exportDropdown.classList.add("hidden");
      });
    }

    if (this.btnExportMd) {
      this.btnExportMd.addEventListener("click", () => {
        if (!this.currentJobId) {
          alert("No completed audit job available. Run an audit first.");
          return;
        }
        window.open(api.getAuditMarkdownReportUrl(this.currentJobId), "_blank");
      });
    }

    if (this.btnExportSarif) {
      this.btnExportSarif.addEventListener("click", () => {
        if (!this.currentJobId) {
          alert("No completed audit job available. Run an audit first.");
          return;
        }
        window.open(api.getAuditSarifUrl(this.currentJobId), "_blank");
      });
    }

    if (this.btnExportZip) {
      this.btnExportZip.addEventListener("click", () => {
        if (!this.currentProjectId) {
          alert("Please select a registered project first.");
          return;
        }
        window.open(api.getPatchedZipUrl(this.currentProjectId), "_blank");
      });
    }
  }

  setProjectId(projectId) {
    this.currentProjectId = projectId;
  }

  async startAudit() {
    if (!this.currentProjectId) {
      alert("Please select a registered project first.");
      return;
    }

    const enableAi = this.toggleAi ? this.toggleAi.checked : false;

    try {
      this.btnRun.disabled = true;
      this.btnRun.innerHTML = `<span class="btn-icon animate-spin">⏳</span> Scanning...`;
      this.hudStatus.textContent = "Starting...";
      this.hudStatus.style.color = "var(--brand-primary)";
      this.hudProgress.style.width = "5%";

      const jobData = await api.startAudit({
        project_id: this.currentProjectId,
        enable_ai: enableAi,
        enable_smells: true,
        include_tests: false,
        incremental: false,
      });

      if (!jobData || !jobData.job_id) {
        throw new Error(jobData.detail || "Failed to start audit job.");
      }

      this.currentJobId = jobData.job_id;
      this.pollProgress(jobData.job_id);

    } catch (err) {
      alert("Audit launch failed: " + err.message);
      this.resetRunButton();
      this.hudStatus.textContent = "Error";
      this.hudStatus.style.color = "var(--sev-critical)";
    }
  }

  pollProgress(jobId) {
    if (this.pollInterval) clearInterval(this.pollInterval);

    this.pollInterval = setInterval(async () => {
      try {
        const status = await api.getAuditStatus(jobId);
        if (!status) return;

        const pct = Math.min(100, Math.max(5, Math.round(status.progress_percentage || 0)));
        this.hudProgress.style.width = `${pct}%`;

        const stageText = (status.current_stage || status.status || "running").replace(/_/g, " ");
        this.hudStatus.textContent = `${stageText} (${pct}%)`;

        if (status.status === "completed") {
          clearInterval(this.pollInterval);
          this.hudProgress.style.width = "100%";
          this.hudStatus.textContent = "Completed (100%)";
          this.hudStatus.style.color = "var(--status-success)";
          this.resetRunButton();
          await this.loadResults(jobId);
        } else if (status.status === "failed") {
          clearInterval(this.pollInterval);
          this.hudStatus.textContent = "Failed";
          this.hudStatus.style.color = "var(--sev-critical)";
          this.resetRunButton();
          alert("Audit job failed: " + (status.error_message || "Unknown error"));
        }
      } catch (err) {
        console.warn("Status poll error:", err);
      }
    }, 1000);
  }

  async loadResults(jobId) {
    try {
      const results = await api.getAuditResults(jobId);
      if (results && results.findings) {
        this.updateMetrics(results.findings);
        this.onAuditComplete(results.findings);
      }
    } catch (err) {
      console.error("Error loading audit results:", err);
    }
  }

  updateMetrics(findings = []) {
    let crit = 0, high = 0, med = 0, qual = 0;
    findings.forEach(f => {
      const s = (f.severity || "").toUpperCase();
      const c = (f.category || "").toUpperCase();
      if (s === "CRITICAL") crit++;
      else if (s === "HIGH") high++;
      else if (s === "MEDIUM") med++;
      else qual++;
    });

    if (this.countCrit) this.countCrit.textContent = `🔴 ${crit} Crit`;
    if (this.countHigh) this.countHigh.textContent = `🟠 ${high} High`;
    if (this.countMed) this.countMed.textContent = `🟡 ${med} Med`;
    if (this.countQual) this.countQual.textContent = `🔵 ${qual} Qual`;
  }

  resetRunButton() {
    if (this.btnRun) {
      this.btnRun.disabled = false;
      this.btnRun.innerHTML = `<span class="btn-icon">▶</span> Run Audit`;
    }
  }
}
