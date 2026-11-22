/**
 * CodeShield AI - Main Application Coordinator
 * Boots up the UI, handles health telemetry, sidebar tab toggles, and event communication.
 */

import { api } from "./api.js";
import { CodeEditor } from "./editor.js";
import { ProjectController } from "./project.js";
import { FindingsController } from "./findings.js";
import { PatchesController } from "./patches.js";
import { AuditController } from "./audit.js";

document.addEventListener("DOMContentLoaded", async () => {
  console.log("🛡️ Initializing CodeShield AI Desktop UI...");

  // 1. Sidebar Tab Switching (Files vs. Issues)
  const tabFiles = document.getElementById("tabFiles");
  const tabIssues = document.getElementById("tabIssues");
  const viewFiles = document.getElementById("viewFiles");
  const viewIssues = document.getElementById("viewIssues");

  if (tabFiles && tabIssues) {
    tabFiles.addEventListener("click", () => {
      tabFiles.classList.add("active");
      tabIssues.classList.remove("active");
      viewFiles.classList.remove("hidden");
      viewIssues.classList.add("hidden");
    });

    tabIssues.addEventListener("click", () => {
      tabIssues.classList.add("active");
      tabFiles.classList.remove("active");
      viewIssues.classList.remove("hidden");
      viewFiles.classList.add("hidden");
    });
  }

  // 2. Initialize Controllers
  let currentFileContent = "";

  const patches = new PatchesController();

  const editorContainer = document.getElementById("codeEditorContainer");
  const editor = new CodeEditor(editorContainer, (finding) => {
    findings.selectFinding(finding);
    tabIssues.click();
  });

  const findings = new FindingsController({
    onSelectFinding: (f) => {
      const relPath = f.relative_file_path || f.file_path;
      if (project.currentProjectId && relPath) {
        api.getFileContent(project.currentProjectId, relPath).then(res => {
          currentFileContent = res.content || "";
          editor.loadFile(relPath, currentFileContent, findings.findings);
          const line = f.start_line || f.line_number || 1;
          setTimeout(() => editor.jumpToLine(line), 100);
        }).catch(err => console.warn("Failed to load file for finding:", err));
      }
    },
    onProposePatch: (f) => {
      patches.proposeForFinding(f, currentFileContent);
    }
  });

  const project = new ProjectController({
    onFileSelect: (filePath, content) => {
      currentFileContent = content;
      editor.loadFile(filePath, content, findings.findings);
    }
  });

  const audit = new AuditController({
    onAuditComplete: (newFindings) => {
      findings.setFindings(newFindings);
      project.updateFileBadges(newFindings);
      tabIssues.click();
    }
  });

  // Re-hook Project Selection with Audit & Patches
  const origLoadProject = project.loadProject.bind(project);
  project.loadProject = async (pid) => {
    await origLoadProject(pid);
    audit.setProjectId(pid);
    patches.setProjectId(pid);
  };

  // 3. Telemetry Health Ping
  try {
    const health = await api.getHealth();
    updateTelemetryBadge("telemetryTreeSitter", health.tree_sitter_available);
    updateTelemetryBadge("telemetryChroma", health.chromadb_available);
    updateTelemetryBadge("telemetryGroq", health.llm_available);
  } catch (err) {
    console.warn("Could not reach backend health endpoint:", err);
    updateTelemetryBadge("telemetryTreeSitter", false);
    updateTelemetryBadge("telemetryChroma", false);
    updateTelemetryBadge("telemetryGroq", false);
  }

  // 4. Default Project Bootstrap
  // Automatically register & load CodeShield AI project for immediate demonstration
  try {
    const defaultProj = await api.registerProject({
      name: "CodeShield AI",
      root_path: window.location.pathname.includes("Desktop") ? "." : "."
    });
    if (defaultProj && defaultProj.project_id) {
      project.addProjectOption(defaultProj.project_id, defaultProj.name, true);
      await project.loadProject(defaultProj.project_id);
    }
  } catch (e) {
    console.log("Auto-registration note:", e.message);
  }

  // Refresh current file button
  const btnRefresh = document.getElementById("btnRefreshFile");
  if (btnRefresh) {
    btnRefresh.addEventListener("click", async () => {
      if (project.currentProjectId && editor.currentFile) {
        try {
          const res = await api.getFileContent(project.currentProjectId, editor.currentFile);
          currentFileContent = res.content || "";
          editor.loadFile(editor.currentFile, currentFileContent, findings.findings);
        } catch (e) {
          console.error(e);
        }
      }
    });
  }

  console.log("✅ CodeShield AI Frontend ready.");
});

function updateTelemetryBadge(id, isAvailable) {
  const el = document.getElementById(id);
  if (!el) return;
  if (isAvailable) {
    el.classList.remove("offline");
  } else {
    el.classList.add("offline");
  }
}
