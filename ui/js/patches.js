/**
 * CodeShield AI - Surgical Patch Console Controller
 * Handles Mode 1 (file-by-file surgical review) and Mode 2 (batch whole-project) patching.
 */

import { api } from "./api.js";

export class PatchesController {
  constructor() {
    this.drawer = document.getElementById("patchDrawer");
    this.btnToggle = document.getElementById("btnToggleDrawer");
    this.filePathBadge = document.getElementById("drawerFilePath");
    this.validationBadge = document.getElementById("drawerValidationBadge");
    this.diffContainer = document.getElementById("diffViewerContainer");

    this.btnValidate = document.getElementById("btnValidatePatch");
    this.btnApproveApply = document.getElementById("btnApproveApplyPatch");
    this.btnRollback = document.getElementById("btnRollbackPatch");
    this.btnBatchPatch = document.getElementById("btnBatchPatchProject");

    this.currentPatch = null;
    this.currentProjectId = null;

    this.initDrawer();
  }

  initDrawer() {
    if (this.btnToggle && this.drawer) {
      this.btnToggle.addEventListener("click", () => {
        this.drawer.classList.toggle("collapsed");
      });
    }

    if (this.btnValidate) {
      this.btnValidate.addEventListener("click", async () => {
        if (!this.currentPatch) return;
        try {
          this.btnValidate.textContent = "Validating...";
          const res = await api.validatePatch(this.currentPatch.patch_id);
          if (res.valid) {
            this.validationBadge.textContent = "✅ AST Validated";
            this.validationBadge.classList.remove("hidden");
            alert("Pre-flight check passed: AST syntax is 100% valid!");
          } else {
            alert(`Validation Warning: ${res.syntax_error || "Syntax issues detected."}`);
          }
        } catch (err) {
          alert("Validation error: " + err.message);
        } finally {
          this.btnValidate.textContent = "👁️ Validate AST";
        }
      });
    }

    if (this.btnApproveApply) {
      this.btnApproveApply.addEventListener("click", async () => {
        if (!this.currentPatch) return;
        if (!confirm(`Apply patch to '${this.currentPatch.file_path}'? A backup will be saved automatically.`)) return;

        try {
          this.btnApproveApply.disabled = true;
          this.btnApproveApply.textContent = "Applying...";
          await api.approvePatch(this.currentPatch.patch_id);
          const applyRes = await api.applyPatch(this.currentPatch.patch_id, true);

          if (applyRes && applyRes.status === "applied") {
            alert("Patch applied cleanly to disk! Backup created.");
            this.btnApproveApply.classList.add("hidden");
            this.btnRollback.classList.remove("hidden");
          } else {
            alert("Failed to apply patch: " + JSON.stringify(applyRes));
          }
        } catch (err) {
          alert("Error applying patch: " + err.message);
        } finally {
          this.btnApproveApply.disabled = false;
          this.btnApproveApply.textContent = "✅ Approve & Apply";
        }
      });
    }

    if (this.btnRollback) {
      this.btnRollback.addEventListener("click", async () => {
        if (!this.currentPatch) return;
        if (!confirm(`Rollback '${this.currentPatch.file_path}' to its pre-patch state?`)) return;

        try {
          this.btnRollback.disabled = true;
          this.btnRollback.textContent = "Rolling back...";
          const res = await api.rollbackPatch(this.currentPatch.patch_id);
          if (res && res.status === "rolled_back") {
            alert("Rollback successful! Original file restored byte-for-byte.");
            this.btnRollback.classList.add("hidden");
            this.btnApproveApply.classList.remove("hidden");
          } else {
            alert("Rollback issue: " + JSON.stringify(res));
          }
        } catch (err) {
          alert("Error rolling back: " + err.message);
        } finally {
          this.btnRollback.disabled = false;
          this.btnRollback.textContent = "↩️ Rollback (.bak)";
        }
      });
    }

    if (this.btnBatchPatch) {
      this.btnBatchPatch.addEventListener("click", async () => {
        if (!this.currentProjectId) {
          alert("Please select and audit a project first.");
          return;
        }

        if (!confirm("Propose and prepare batch patches for all actionable issues across this project?")) return;

        try {
          this.btnBatchPatch.disabled = true;
          this.btnBatchPatch.textContent = "Preparing Batch...";
          const res = await api.batchPropose({ project_id: this.currentProjectId, auto_approve: false });

          if (res && res.patches && res.patches.length > 0) {
            const count = res.patches.length;
            if (confirm(`Prepared ${count} candidate patches. Apply all ${count} patches with atomic backups now?`)) {
              const patchIds = res.patches.map(p => p.patch_id);
              const applyRes = await api.batchApply({ patch_ids: patchIds, atomic: true });
              alert(`Batch Apply Finished: ${applyRes.applied_count} applied successfully, ${applyRes.failed_count} skipped/failed.`);
            }
          } else {
            alert("No candidate patches were generated. Ensure an audit has completed with actionable findings.");
          }
        } catch (err) {
          alert("Batch patch error: " + err.message);
        } finally {
          this.btnBatchPatch.disabled = false;
          this.btnBatchPatch.textContent = "⚡ Batch Patch Project";
        }
      });
    }

    const btnDrawerExportZip = document.getElementById("btnDrawerExportZip");
    if (btnDrawerExportZip) {
      btnDrawerExportZip.addEventListener("click", () => {
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

  expandDrawer() {
    if (this.drawer) this.drawer.classList.remove("collapsed");
  }

  async proposeForFinding(finding, currentFileContent = "") {
    if (!finding) return;

    this.expandDrawer();
    this.filePathBadge.textContent = (finding.relative_file_path || finding.file_path || "file").replace(/\\/g, "/");

    // Check if architectural smell
    const cat = (finding.category || "").toLowerCase();
    if (cat === "architecture" || cat === "architectural") {
      this.currentPatch = null;
      this.btnValidate.classList.add("hidden");
      this.btnApproveApply.classList.add("hidden");
      this.btnRollback.classList.add("hidden");
      this.validationBadge.classList.add("hidden");

      this.diffContainer.innerHTML = `
        <div class="diff-empty" style="color: #f59e0b; text-align: left; padding: 1.5rem; line-height: 1.6;">
          <h4 style="margin: 0 0 0.5rem 0; font-size: 1rem; color: #fbbf24;">ℹ️ Architectural Structural Issue (${finding.title})</h4>
          <p style="margin: 0 0 0.5rem 0;">This issue represents a system-wide structural relationship (such as a Bottleneck Hub with high Fan-In/Fan-Out or a file > 250 lines), not an isolated single-line syntax bug.</p>
          <p style="margin: 0 0 0.5rem 0;">Automated code replacement cannot safely split classes or decouple multi-file architectures without human design decisions.</p>
          <div style="background: rgba(245, 158, 11, 0.1); border-left: 3px solid #f59e0b; padding: 0.75rem; border-radius: 4px; margin-top: 0.5rem;">
            👉 <strong>Action:</strong> Follow the <em>Remediation Steps</em> in the Threat Intelligence Inspector card on the right to decouple callers or extract services.
          </div>
        </div>`;
      return;
    }

    this.diffContainer.innerHTML = `<div class="diff-empty animate-pulse">🤖 Consulting Groq AI Security Engineer to synthesize surgical patch & Git diff...</div>`;

    try {
      const patchData = await api.generateAiPatch({
        file_path: finding.file_path,
        finding_id: finding.finding_id,
        title: finding.title,
        cwe_id: finding.cwe_id,
        line_number: finding.start_line || finding.line_number || 1,
        category: finding.category,
        recommendation: finding.recommendation || (finding.remediation_steps ? finding.remediation_steps.join("; ") : ""),
      });

      if (!patchData || !patchData.patch_id) {
        throw new Error(patchData.detail || "AI did not generate a patch for this finding.");
      }

      this.currentPatch = patchData;
      this.renderDiff(patchData);

      this.btnValidate.classList.remove("hidden");
      this.btnApproveApply.classList.remove("hidden");
      this.btnRollback.classList.add("hidden");
      this.validationBadge.classList.add("hidden");

    } catch (err) {
      this.diffContainer.innerHTML = `<div class="diff-empty text-red-400">Failed to generate AI patch: ${err.message}</div>`;
    }
  }

  renderDiff(patchOrDiff) {
    if (!patchOrDiff) {
      this.diffContainer.innerHTML = `<div class="diff-empty">Empty diff. No changes proposed.</div>`;
      return;
    }

    const unifiedDiff = patchOrDiff.git_diff || patchOrDiff.unified_diff || (typeof patchOrDiff === "string" ? patchOrDiff : "");
    const hunks = patchOrDiff.hunks || [];
    const filePath = patchOrDiff.file_path || "patched";
    const additions = patchOrDiff.additions_count ?? patchOrDiff.additions ?? 0;
    const deletions = patchOrDiff.deletions_count ?? patchOrDiff.deletions ?? 0;

    if (!unifiedDiff && hunks.length === 0) {
      this.diffContainer.innerHTML = `<div class="diff-empty">Empty diff. No changes proposed.</div>`;
      return;
    }

    let html = `<div class="diff-hunk">`;
    html += `<div class="diff-hunk-header">--- a/${this.escapeHtml(filePath)}  +++ b/${this.escapeHtml(filePath)} (+${additions}, -${deletions})</div>`;

    if (hunks.length > 0 && hunks[0].lines) {
      hunks.forEach(h => {
        html += `<div class="diff-hunk-header">${this.escapeHtml(h.header || `@@ -${h.old_start},${h.old_lines} +${h.new_start},${h.new_lines} @@`)}</div>`;
        (h.lines || []).forEach(l => {
          if (l.type === "addition") {
            html += `<div class="diff-line addition">+ ${this.escapeHtml(l.content)}</div>`;
          } else if (l.type === "deletion") {
            html += `<div class="diff-line deletion">- ${this.escapeHtml(l.content)}</div>`;
          } else {
            html += `<div class="diff-line">  ${this.escapeHtml(l.content)}</div>`;
          }
        });
      });
    } else if (unifiedDiff) {
      const lines = unifiedDiff.split("\n");
      lines.forEach(l => {
        if (l.startsWith("+") && !l.startsWith("+++")) {
          html += `<div class="diff-line addition">${this.escapeHtml(l)}</div>`;
        } else if (l.startsWith("-") && !l.startsWith("---")) {
          html += `<div class="diff-line deletion">${this.escapeHtml(l)}</div>`;
        } else if (l.startsWith("@@")) {
          html += `<div class="diff-hunk-header">${this.escapeHtml(l)}</div>`;
        } else {
          html += `<div class="diff-line">${this.escapeHtml(l)}</div>`;
        }
      });
    }

    html += `</div>`;
    this.diffContainer.innerHTML = html;
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
