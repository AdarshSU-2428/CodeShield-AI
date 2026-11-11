from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import uuid

from app.analysis.attribution_helper import FindingAttributionHelper
from app.analysis.cross_file import CrossFileContextResolver
from app.analysis.parser import ParserRegistry, parser_registry
from app.analysis.quality_analyzer import ArchitecturalSmellDetector, CodeQualityAnalyzer
from app.analysis.rule_engine import RuleEngine, default_rule_engine
from app.analysis.scanner import RepositoryScanner
from app.core.enums import Confidence, FindingCategory, JobStatus, Severity
from app.core.interfaces.filesystem import FileSystem
from app.core.models.audit import AuditFinding, AuditJob, AuditProgress, AuditReport
from app.core.models.code import SourceFile
from app.core.models.project import Project
from app.infrastructure.filesystem import LocalFileSystem


class AuditService:
    """Orchestrates end-to-end security audits across static rules, code quality, and deep attribution."""

    def __init__(
        self,
        scanner: Optional[RepositoryScanner] = None,
        filesystem: Optional[FileSystem] = None,
        parser_reg: Optional[ParserRegistry] = None,
        rule_engine: Optional[RuleEngine] = None,
        quality_analyzer: Optional[CodeQualityAnalyzer] = None,
        architecture_detector: Optional[ArchitecturalSmellDetector] = None,
        attribution_helper: Optional[FindingAttributionHelper] = None,
        cross_file_resolver: Optional[CrossFileContextResolver] = None,
        ai_analyzer: Optional[Any] = None,
        auto_save_report: bool = True,
    ):
        self._fs: FileSystem = filesystem if filesystem is not None else LocalFileSystem()
        self._scanner: RepositoryScanner = scanner if scanner is not None else RepositoryScanner(filesystem=self._fs)
        self._parsers: ParserRegistry = parser_reg if parser_reg is not None else parser_registry
        self._rule_engine: RuleEngine = rule_engine if rule_engine is not None else default_rule_engine
        self._quality_analyzer: CodeQualityAnalyzer = (
            quality_analyzer if quality_analyzer is not None else CodeQualityAnalyzer()
        )
        self._architecture_detector: ArchitecturalSmellDetector = (
            architecture_detector if architecture_detector is not None else ArchitecturalSmellDetector()
        )
        self._attribution_helper: FindingAttributionHelper = (
            attribution_helper if attribution_helper is not None else FindingAttributionHelper(filesystem=self._fs)
        )
        self._cross_resolver: CrossFileContextResolver = (
            cross_file_resolver if cross_file_resolver is not None else CrossFileContextResolver(filesystem=self._fs)
        )
        self._auto_save_report: bool = auto_save_report

        self._jobs: Dict[str, AuditJob] = {}
        self._reports: Dict[str, AuditReport] = {}
        self._ai_analyzer = ai_analyzer

    def create_job(self, project: Project) -> AuditJob:
        """Initialize and store a new audit job in QUEUED status."""
        job = AuditJob(project_id=project.project_id)
        self._jobs[job.job_id] = job
        return job

    def get_job(self, job_id: str) -> Optional[AuditJob]:
        """Retrieve an audit job by its unique identifier."""
        return self._jobs.get(job_id)

    def get_report(self, job_id: str) -> Optional[AuditReport]:
        """Retrieve the final audit report for a given job."""
        return self._reports.get(job_id)

    def cancel_job(self, job_id: str) -> bool:
        """Cancel an ongoing or queued audit job."""
        job = self.get_job(job_id)
        if not job or job.status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]:
            return False

        job.status = JobStatus.CANCELLED
        job.completed_at = datetime.now(timezone.utc)
        job.progress.current_step = "cancelled"
        return True

    def _update_progress(
        self,
        job: AuditJob,
        step: str,
        percentage: float,
        current_file: Optional[str] = None,
        scanned: Optional[int] = None,
        total: Optional[int] = None,
        findings_count: Optional[int] = None,
        callback: Optional[Callable[[AuditProgress], None]] = None,
    ) -> None:
        """Update job progress telemetry and notify callback."""
        job.progress.current_step = step
        job.progress.percentage = percentage
        job.progress.current_file = current_file
        if scanned is not None:
            job.progress.scanned_files_count = scanned
        if total is not None:
            job.progress.total_files_count = total
        if findings_count is not None:
            job.progress.findings_count = findings_count

        if callback:
            try:
                callback(job.progress)
            except Exception:
                pass

    def run_audit(
        self,
        job_id: str,
        project: Project,
        on_progress: Optional[Callable[[AuditProgress], None]] = None,
    ) -> AuditReport:
        """
        Execute full multi-phase audit pipeline:
        Phase 1: Project File Discovery
        Phase 2: Multi-Language AST Parsing, Static Rules, and Architectural Smells
        Phase 3: Precise Code Attribution, Context Windows, and Severity Prioritization
        """
        job = self.get_job(job_id)
        if not job:
            raise ValueError(f"Audit job '{job_id}' not found.")

        # Guard: If pre-cancelled, finalize immediately
        if job.status == JobStatus.CANCELLED:
            report = AuditReport(
                job_id=job.job_id,
                project_id=project.project_id,
                findings=[],
                summary="Audit job was cancelled by user.",
            )
            self._reports[job.job_id] = report
            return report

        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        all_findings: List[AuditFinding] = []

        try:
            # -------------------------------------------------------------
            # Phase 1: Project Discovery & Scanning (0% - 20%)
            # -------------------------------------------------------------
            self._update_progress(job, "scanning", 5.0, callback=on_progress)
            
            try:
                source_files: List[SourceFile] = self._scanner.scan_project(project)
            except Exception:
                source_files = self._scanner.scan_project(project.root_path)
            
            total_files = len(source_files)
            job.progress.total_files_count = total_files

            self._update_progress(
                job,
                "scanning_complete",
                20.0,
                scanned=total_files,
                total=total_files,
                callback=on_progress,
            )

            if total_files == 0:
                report = AuditReport(
                    job_id=job.job_id,
                    project_id=project.project_id,
                    findings=[],
                    summary="No supported source code files detected in project workspace.",
                )
                job.status = JobStatus.COMPLETED
                job.completed_at = datetime.now(timezone.utc)
                self._reports[job.job_id] = report
                self._update_progress(job, "complete", 100.0, callback=on_progress)
                return report

            # -------------------------------------------------------------
            # Phase 2: Multi-Language Parsing, Rule Engine & Quality (20% - 75%)
            # -------------------------------------------------------------
            parsed_trees: Dict[str, Any] = {}

            for idx, sf in enumerate(source_files, start=1):
                if job.status == JobStatus.CANCELLED:
                    break

                file_path_str = str(sf.file_path)
                pct = 20.0 + ((idx / total_files) * 55.0)
                self._update_progress(
                    job,
                    "ast_parsing",
                    pct,
                    current_file=sf.relative_path or Path(file_path_str).name,
                    scanned=idx,
                    total=total_files,
                    findings_count=len(all_findings),
                    callback=on_progress,
                )

                # 1. AST Parsing & Syntax Error Capturing
                content = sf.content
                if not content and self._fs.exists(sf.file_path):
                    content = self._fs.read_text(sf.file_path)
                    sf.content = content

                tree = None
                if self._parsers.is_supported(sf.language):
                    try:
                        tree = self._parsers.parse_file(sf, content)
                        parsed_trees[file_path_str] = tree
                        if tree and getattr(tree, "root_node", None) and tree.root_node.has_error:
                            syntax_finding = AuditFinding(
                                title=f"Syntax Error in {sf.language.value.capitalize()} File",
                                description=(
                                    f"Tree-sitter parser detected a syntax error while constructing AST for {sf.relative_path}."
                                ),
                                category=FindingCategory.CODE_QUALITY,
                                severity=Severity.LOW,
                                confidence=Confidence.HIGH,
                                file_path=sf.file_path,
                                relative_file_path=str(sf.relative_path).replace("\\", "/") if sf.relative_path else "",
                                start_line=1,
                                end_line=1,
                                source="tree_sitter",
                            )
                            all_findings.append(syntax_finding)
                    except Exception as parse_err:
                        err_finding = AuditFinding(
                            title=f"AST Parsing Failure ({sf.language.value})",
                            description=f"Exception raised while parsing AST: {parse_err}",
                            category=FindingCategory.CODE_QUALITY,
                            severity=Severity.LOW,
                            confidence=Confidence.MEDIUM,
                            file_path=sf.file_path,
                            relative_file_path=str(sf.relative_path).replace("\\", "/") if sf.relative_path else "",
                            start_line=1,
                            end_line=1,
                            source="parser_exception",
                        )
                        all_findings.append(err_finding)

                # 2. Static Security Rules
                rule_findings = self._rule_engine.analyze_file(sf)
                all_findings.extend(rule_findings)

                # 3. Code Quality & Architectural Anti-Pattern Analysis
                quality_findings = (
                    self._quality_analyzer.analyze_file(sf, ast_tree=tree)
                    if hasattr(self._quality_analyzer, "analyze_file")
                    else self._quality_analyzer.evaluate_file(sf)
                )
                all_findings.extend(quality_findings)

                # 4. Optional AI Semantic Vulnerability Analysis
                if self._ai_analyzer and hasattr(self._ai_analyzer, "analyze_file"):
                    try:
                        ai_findings = self._ai_analyzer.analyze_file(sf)
                        all_findings.extend(ai_findings)
                    except Exception:
                        pass

            # Check if job was cancelled during parsing/analysis
            if job.status == JobStatus.CANCELLED:
                report = AuditReport(
                    job_id=job.job_id,
                    project_id=project.project_id,
                    findings=all_findings,
                    summary="Audit job was cancelled by user.",
                )
                self._reports[job.job_id] = report
                self._update_progress(job, "cancelled", job.progress.percentage, callback=on_progress)
                return report

            # Global Architectural Analysis: Circular Dependencies
            arch_findings = (
                self._architecture_detector.analyze_project(source_files)
                if hasattr(self._architecture_detector, "analyze_project")
                else self._architecture_detector.evaluate_architecture(source_files)
            )

            all_findings.extend(arch_findings)

            # -------------------------------------------------------------
            # Phase 3: Exact Attribution & Prioritization (75% - 100%)
            # -------------------------------------------------------------
            self._update_progress(
                job,
                "attributing_findings",
                85.0,
                findings_count=len(all_findings),
                callback=on_progress,
            )

            # Hydrate context snippets & clamp line coordinates
            self._attribution_helper.hydrate_findings(all_findings, context_lines=2)

            # User Story 17: Contextual Multi-Component Linking across files
            if self._cross_resolver:
                for f in all_findings:
                    self._cross_resolver.link_finding_components(f, all_project_files=source_files)

            # User Story 10: Sort findings by deterministic priority/risk score (highest risk first)
            all_findings.sort(key=lambda f: getattr(f, "risk_score", 0.0), reverse=True)

            job.findings = all_findings
            summary_text = (
                f"Audit completed across {total_files} files with {len(all_findings)} finding(s) detected. "
                f"Findings prioritized by risk score."
            )

            report = AuditReport(
                job_id=job.job_id,
                project_id=project.project_id,
                findings=all_findings,
                summary=summary_text,
            )

            self._reports[job.job_id] = report
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)

            self._update_progress(
                job,
                "complete",
                100.0,
                scanned=total_files,
                total=total_files,
                findings_count=len(all_findings),
                callback=on_progress,
            )

            return report

        except Exception as exc:
            job.status = JobStatus.FAILED
            job.completed_at = datetime.now(timezone.utc)
            job.error_message = str(exc)
            self._update_progress(job, "failed", 100.0, callback=on_progress)
            raise exc


# Singleton instance for system-wide auditing
default_audit_service = AuditService()