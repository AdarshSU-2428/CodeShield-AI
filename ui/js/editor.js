export class CodeEditor {
  constructor(containerElement, onLineClick = null) {
    this.container = containerElement;
    this.onLineClick = onLineClick;
    this.currentFile = null;
    this.currentContent = "";
    this.findings = [];
  }

  loadFile(filePath, content, findings = []) {
    this.currentFile = filePath;
    this.currentContent = content || "";
    const normTarget = filePath.replace(/\\/g, "/");
    this.findings = (findings || []).filter(f => {
      const rel = (f.relative_file_path || f.file_path || "").replace(/\\/g, "/");
      return rel.endsWith(normTarget) || normTarget.endsWith(rel);
    });
    this.render();
  }

  jumpToLine(lineNumber) {
    const el = document.getElementById(`L${lineNumber}`);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      el.classList.add("line-flash");
      setTimeout(() => el.classList.remove("line-flash"), 1500);
    }
  }

  render() {
    if (!this.container) return;
    if (!this.currentContent) {
      this.container.innerHTML = `
        <div class="editor-placeholder">
          <span class="placeholder-icon">💻</span>
          <h3>No File Selected</h3>
          <p>Click on any file from the explorer on the left to view code.</p>
        </div>`;
      return;
    }

    const lines = this.currentContent.split("\n");
    const findingMap = new Map();
    this.findings.forEach(f => {
      const lineNum = f.start_line || f.line_number || 1;
      if (!findingMap.has(lineNum)) findingMap.set(lineNum, []);
      findingMap.get(lineNum).push(f);
    });

    let html = `<div class="code-viewer"><table class="code-table">`;
    lines.forEach((lineText, idx) => {
      const lineNum = idx + 1;
      const lineFindings = findingMap.get(lineNum) || [];
      const hasFinding = lineFindings.length > 0;
      const sev = hasFinding ? (lineFindings[0].severity || "HIGH").toLowerCase() : "";
      const highlightClass = hasFinding ? `line-highlight-${sev}` : "";

      html += `
        <tr class="code-line ${highlightClass}" id="L${lineNum}" data-line="${lineNum}">
          <td class="line-gutter">${lineNum}</td>
          <td class="line-marker" title="${hasFinding ? lineFindings[0].title : ''}">${hasFinding ? "⚠️" : ""}</td>
          <td class="line-content"><code>${this.escapeHtml(lineText)}</code></td>
        </tr>
      `;
    });
    html += `</table></div>`;
    this.container.innerHTML = html;

    // Attach click listener for highlighted lines
    this.container.querySelectorAll(".code-line").forEach(tr => {
      tr.addEventListener("click", () => {
        const lineNum = parseInt(tr.getAttribute("data-line"), 10);
        const flist = findingMap.get(lineNum);
        if (flist && flist.length > 0 && typeof this.onLineClick === "function") {
          this.onLineClick(flist[0]);
        }
      });
    });
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
