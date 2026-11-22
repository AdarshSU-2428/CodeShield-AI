/**
 * CodeShield AI - Central API Client Module
 * Handles all HTTP communication with the FastAPI backend endpoints:
 * - /api/health
 * - /api/projects/*
 * - /api/audit/*
 * - /api/patches/*
 */

export const API_BASE = 
  window.location.origin.startsWith("http://127.0.0.1:8000") || window.location.origin.startsWith("http://localhost:8000")
    ? window.location.origin
    : "http://127.0.0.1:8000";

export const api = {
  // --- Health Diagnostics ---
  getHealth: () => 
    fetch(`${API_BASE}/api/health`).then(r => r.json()),

  // --- Project Workspace ---
  registerProject: (data) =>
    fetch(`${API_BASE}/api/projects/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    }).then(r => r.json()),

  getProjectTree: (projectId) =>
    fetch(`${API_BASE}/api/projects/${projectId}/tree`).then(r => r.json()),

  getFileContent: (projectId, filePath) =>
    fetch(`${API_BASE}/api/projects/${projectId}/file-content?path=${encodeURIComponent(filePath)}`).then(r => r.json()),

  // --- Audit Pipelines ---
  startAudit: (data) =>
    fetch(`${API_BASE}/api/audit/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    }).then(r => r.json()),

  getAuditStatus: (jobId) =>
    fetch(`${API_BASE}/api/audit/jobs/${jobId}`).then(r => r.json()),

  getAuditResults: (jobId) =>
    fetch(`${API_BASE}/api/audit/jobs/${jobId}/results`).then(r => r.json()),

  getAuditMarkdownReportUrl: (jobId) =>
    `${API_BASE}/api/audit/jobs/${jobId}/markdown`,

  getAuditSarifUrl: (jobId) =>
    `${API_BASE}/api/audit/jobs/${jobId}/sarif`,

  getPatchedZipUrl: (projectId) =>
    `${API_BASE}/api/projects/${projectId}/export-zip`,

  // --- Mode 1 Surgical File Patching ---
  generateAiPatch: (data) =>
    fetch(`${API_BASE}/api/patches/generate-ai`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    }).then(r => r.json()),

  proposePatch: (data) =>
    fetch(`${API_BASE}/api/patches/propose`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    }).then(r => r.json()),

  validatePatch: (patchId) =>
    fetch(`${API_BASE}/api/patches/${patchId}/validate`, { 
      method: "POST" 
    }).then(r => r.json()),

  approvePatch: (patchId, approvedBy = "reviewer") =>
    fetch(`${API_BASE}/api/patches/${patchId}/approve`, { 
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ approved_by: approvedBy }),
    }).then(async r => {
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail || "Approval failed");
      return data;
    }),

  applyPatch: (patchId, requireApproval = true) =>
    fetch(`${API_BASE}/api/patches/${patchId}/apply?require_approval=${requireApproval}`, { 
      method: "POST" 
    }).then(async r => {
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail || "Apply failed");
      return data;
    }),

  rollbackPatch: (patchId) =>
    fetch(`${API_BASE}/api/patches/${patchId}/rollback`, { 
      method: "POST" 
    }).then(async r => {
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail || "Rollback failed");
      return data;
    }),

  // --- Mode 2 Batch Whole-Project Patching ---
  batchPropose: (data) =>
    fetch(`${API_BASE}/api/patches/batch/propose`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    }).then(r => r.json()),

  batchApply: (data) =>
    fetch(`${API_BASE}/api/patches/batch/apply`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    }).then(r => r.json()),

  batchRollback: (data) =>
    fetch(`${API_BASE}/api/patches/batch/rollback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    }).then(r => r.json()),
};
