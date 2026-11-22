/**
 * CodeShield AI - Project & File Explorer Controller
 * Handles project registration, dropdown switching, and recursive tree rendering.
 */

import { api } from "./api.js";

export class ProjectController {
  constructor(options = {}) {
    this.selectEl = document.getElementById("projectSelect");
    this.treeContainer = document.getElementById("fileTreeContainer");
    this.breadcrumbEl = document.getElementById("breadcrumbPath");
    this.langBadgeEl = document.getElementById("fileLanguageBadge");
    this.onFileSelect = options.onFileSelect || (() => {});
    
    this.currentProjectId = null;
    this.currentProjectName = "";
    this.currentTree = null;
    this.fileFindingsMap = new Map(); // filePath -> count

    this.initModal();
  }

  initModal() {
    const btnNew = document.getElementById("btnNewProject");
    const modal = document.getElementById("modalNewProject");
    const btnClose = document.getElementById("btnCloseModal");
    const btnCancel = document.getElementById("btnCancelModal");
    const btnSubmit = document.getElementById("btnSubmitProject");

    if (btnNew && modal) {
      btnNew.addEventListener("click", () => modal.classList.remove("hidden"));
      const closeModal = () => modal.classList.add("hidden");
      if (btnClose) btnClose.addEventListener("click", closeModal);
      if (btnCancel) btnCancel.addEventListener("click", closeModal);

      if (btnSubmit) {
        btnSubmit.addEventListener("click", async () => {
          const name = document.getElementById("inputProjectName").value.trim();
          const path = document.getElementById("inputProjectPath").value.trim();
          if (!name || !path) {
            alert("Please provide both Project Name and Root Path.");
            return;
          }

          try {
            btnSubmit.disabled = true;
            btnSubmit.textContent = "Registering...";
            const res = await api.registerProject({ name, root_path: path });
            if (res && res.project_id) {
              this.addProjectOption(res.project_id, res.name, true);
              closeModal();
              await this.loadProject(res.project_id);
            } else {
              alert(res.detail || "Failed to register project.");
            }
          } catch (err) {
            alert("Error registering project: " + err.message);
          } finally {
            btnSubmit.disabled = false;
            btnSubmit.textContent = "Register Project";
          }
        });
      }
    }

    if (this.selectEl) {
      this.selectEl.addEventListener("change", async (e) => {
        const pid = e.target.value;
        if (pid) await this.loadProject(pid);
      });
    }
  }

  addProjectOption(id, name, select = false) {
    if (!this.selectEl) return;
    let opt = Array.from(this.selectEl.options).find(o => o.value === id);
    if (!opt) {
      opt = document.createElement("option");
      opt.value = id;
      opt.textContent = name;
      this.selectEl.appendChild(opt);
    }
    if (select) {
      this.selectEl.value = id;
      this.currentProjectId = id;
      this.currentProjectName = name;
    }
  }

  updateFileBadges(findings = []) {
    this.fileFindingsMap.clear();
    findings.forEach(f => {
      const p = (f.relative_file_path || f.file_path || "").replace(/\\/g, "/");
      this.fileFindingsMap.set(p, (this.fileFindingsMap.get(p) || 0) + 1);
    });
    if (this.currentTree) {
      this.renderTree(this.currentTree);
    }
  }

  async loadProject(projectId) {
    this.currentProjectId = projectId;
    const selectedOpt = this.selectEl.options[this.selectEl.selectedIndex];
    this.currentProjectName = selectedOpt ? selectedOpt.textContent : projectId;

    this.treeContainer.innerHTML = `<div class="empty-state">Loading file tree...</div>`;
    try {
      const treeData = await api.getProjectTree(projectId);
      if (treeData && treeData.tree) {
        this.currentTree = treeData.tree;
        this.renderTree(treeData.tree);
      } else {
        this.treeContainer.innerHTML = `<div class="empty-state">Could not load project tree.</div>`;
      }
    } catch (err) {
      this.treeContainer.innerHTML = `<div class="empty-state text-red-400">Error loading tree: ${err.message}</div>`;
    }
  }

  renderTree(node) {
    this.treeContainer.innerHTML = "";
    const el = this.createNodeElement(node, true);
    this.treeContainer.appendChild(el);
  }

  createNodeElement(node, isRoot = false) {
    const isDir = node.type === "directory";
    const container = document.createElement("div");

    const row = document.createElement("div");
    row.className = "tree-node";

    const label = document.createElement("div");
    label.className = "tree-node-label";

    const icon = document.createElement("span");
    icon.textContent = isDir ? "▾ 📁" : "📄";
    label.appendChild(icon);

    const nameSpan = document.createElement("span");
    nameSpan.textContent = node.name;
    label.appendChild(nameSpan);

    row.appendChild(label);

    // Badge if file has findings
    const normPath = (node.relative_path || node.path || "").replace(/\\/g, "/");
    const count = this.fileFindingsMap.get(normPath) || 0;
    if (!isDir && count > 0) {
      const badge = document.createElement("span");
      badge.className = "tree-badge";
      badge.textContent = count;
      row.appendChild(badge);
    }

    container.appendChild(row);

    if (isDir && node.children && node.children.length > 0) {
      const childContainer = document.createElement("div");
      childContainer.className = "tree-folder-children";
      node.children.forEach(child => {
        childContainer.appendChild(this.createNodeElement(child));
      });
      container.appendChild(childContainer);

      row.addEventListener("click", (e) => {
        e.stopPropagation();
        const isCollapsed = childContainer.classList.toggle("hidden");
        icon.textContent = isCollapsed ? "▸ 📁" : "▾ 📁";
      });
    } else if (!isDir) {
      row.addEventListener("click", async (e) => {
        e.stopPropagation();
        this.treeContainer.querySelectorAll(".tree-node").forEach(n => n.classList.remove("selected"));
        row.classList.add("selected");

        const relPath = node.relative_path || node.path;
        if (this.breadcrumbEl) this.breadcrumbEl.textContent = `${this.currentProjectName} > ${relPath.replace(/\\/g, " > ")}`;
        if (this.langBadgeEl) {
          const ext = relPath.split(".").pop();
          this.langBadgeEl.textContent = ext ? ext.toUpperCase() : "PLAIN";
        }

        try {
          const fileData = await api.getFileContent(this.currentProjectId, relPath);
          this.onFileSelect(relPath, fileData.content || "");
        } catch (err) {
          console.error("Error reading file:", err);
        }
      });
    }

    return container;
  }
}
