import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union
import uuid

from app.analysis.ai_analyzer import AIVulnerabilityAnalyzer
from app.analysis.rule_engine import RuleEngine, default_rule_engine
from app.analysis.component_extractor import ComponentExtractor
from app.analysis.parser import ParserRegistry
from app.analysis.scanner import RepositoryScanner
from app.analysis.quality_analyzer import ArchitecturalSmellDetector, CodeQualityAnalyzer
from app.analysis.attribution_helper import FindingAttributionHelper
from app.core.enums import Confidence, FileStatus, FindingCategory, JobStatus, Language, Severity
from app.core.interfaces.filesystem import FileSystem
from app.core.models.audit import AuditFinding, AuditJob, AuditProgress, AuditReport
from app.core.models.project import Project
from app.infrastructure.config import AppConfig, config as default_config
from app.infrastructure.filesystem import LocalFileSystem


class AuditService:
    """
    Orchestrates the complete static analysis and audit lifecycle.
    Manages job states, drives multi-phase scanning and AST extraction,
    and streams real-time progress updates.
    """

    def __init__(
        self,
        scanner: Optional[RepositoryScanner] = None,
        parser_registry: Optional[ParserRegistry] = None,
        extractor: Optional[ComponentExtractor] = None,
        filesystem: Optional[FileSystem] = None,
        config: Optional[AppConfig] = None,
        rule_engine: Optional[RuleEngine] = None,
        ai_analyzer: Optional[AIVulnerabilityAnalyzer] = None,
        quality_analyzer: Optional[CodeQualityAnalyzer] = None,
        architecture_detector: Optional[ArchitecturalSmellDetector] = None,
        reports_dir: Optional[Union[str, Path]] = None,
        auto_save_report: bool = True,
    ):
        self.config = config if config else default_config
        self.filesystem = filesystem if filesystem else LocalFileSystem()
        self.scanner = scanner if scanner else RepositoryScanner(filesystem=self.filesystem, config=self.config)
        self.parser_registry = parser_registry if parser_registry else ParserRegistry()
        self.extractor = extractor if extractor else ComponentExtractor()
        self.rule_engine = rule_engine if rule_engine else default_rule_engine
        self.ai_analyzer = ai_analyzer
        self.quality_analyzer = quality_analyzer if quality_analyzer is not None else CodeQualityAnalyzer()
        self.architecture_detector = architecture_detector if architecture_detector is not None else ArchitecturalSmellDetector()
        self.reports_dir = Path(reports_dir) if reports_dir is not None else Path("data/reports")
        self.auto_save_report = auto_save_report
        
        # In-memory storage for active jobs and final reports
        self._jobs: Dict[str, AuditJob] = {}
        self._reports: Dict[str, AuditReport] = {}

    def create_job(self, project: Project) -> AuditJob:
        """Create and queue a new audit job for the given project."""
        project_id = getattr(project, "project_id", getattr(project, "id", str(project.root_path)))
        
        job = AuditJob(
            project_id=project_id,
            status=JobStatus.QUEUED,
            progress=AuditProgress(current_step="queued", percentage=0.0),
        )
        
        self._jobs[job.job_id] = job
        
        return job

    def get_job(self, job_id: str) -> Optional[AuditJob]:
        """Retrieve an audit job by its UUID."""
        return self._jobs.get(job_id)

    def get_report(self, job_id: str) -> Optional[AuditReport]:
        """Retrieve the final audit report for a completed job."""
        return self._reports.get(job_id)

    def save_report_to_file(
        self,
        report: AuditReport,
        output_dir: Optional[Union[str, Path]] = None,
    ) -> Path:
        target_dir = Path(output_dir) if output_dir is not None else self.reports_dir
        report_path = target_dir / f"audit_report_{report.job_id}.json"
        json_content = json.dumps(report.to_dict(), indent=2)
        self.filesystem.write_text(report_path, json_content)
        return report_path


    def cancel_job(self, job_id: str) -> bool:
        """Cancel an ongoing or queued audit job."""
        job = self.get_job(job_id)
        
        if not job or job.status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]:
            return False
        
        job.status = JobStatus.CANCELLED
        job.progress.current_step = "cancelled"
        job.completed_at = datetime.now(timezone.utc)
        
        return True

    def _update_job_progress(
        self,
        job: AuditJob,
        step: str,
        percentage: float,
        current_file: Optional[str] = None,
        on_progress: Optional[Callable[[AuditProgress], None]] = None,
    ) -> None:
        """Class-level method to update progress metrics and trigger listener callbacks."""
        job.progress.current_step = step
        job.progress.percentage = round(percentage, 1)
        job.progress.current_file = current_file
        job.progress.findings_count = len(job.findings)
        
        if on_progress:
            try:
                on_progress(job.progress)
            except Exception:
                pass

    def run_audit(
        self,
        job_id: str,
        project: Project,
        on_progress: Optional[Callable[[AuditProgress], None]] = None,
    ) -> AuditReport:
        """
        Execute the multi-phase audit pipeline synchronously or within a worker thread:
        Phase 1: Repository Scanning & Filtering (0% - 25%)
        Phase 2: Multi-Language AST Parsing & Extraction (25% - 70%)
        Phase 3: Finding Aggregation & Rule Evaluation (70% - 90%)
        Phase 4: Finalizing & Audit Report Generation (90% - 100%)
        """
        job = self.get_job(job_id)
        
        if not job:
            raise ValueError(f"Audit job with ID '{job_id}' not found.")

        # Check if job was already cancelled before execution
        if job.status == JobStatus.CANCELLED:
            return self._finalize_cancelled(job, project)

        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)

        try:
            # -------------------------------------------------------------
            # Phase 1: Repository Scanning & File Discovery (0% - 25%)
            # -------------------------------------------------------------
            self._update_job_progress(job, "scanning", 5.0, on_progress=on_progress)
            
            scanned_files = self.scanner.scan_project(project)
            
            supported_files = [
                f for f in scanned_files 
                if f.status != FileStatus.UNSUPPORTED and f.language != Language.UNKNOWN
            ]
            
            total_supported = len(supported_files)
            job.progress.total_files_count = total_supported
            job.progress.scanned_files_count = 0
            self._update_job_progress(job, "scanning_complete", 25.0, on_progress=on_progress)

            # Check if job was cancelled during scanning
            if job.status == JobStatus.CANCELLED:
                return self._finalize_cancelled(job, project)

            # -------------------------------------------------------------
            # Phase 2: AST Parsing & Component Extraction (25% - 70%)
            # -------------------------------------------------------------
            all_components = []
            
            for idx, source_file in enumerate(supported_files, start=1):
                # Check for cancellation between files
                if job.status == JobStatus.CANCELLED:
                    return self._finalize_cancelled(job, project)

                file_path_str = str(source_file.file_path)
                pct = 25.0 + (45.0 * (idx / max(1, total_supported)))
                job.progress.scanned_files_count = idx
                
                self._update_job_progress(
                    job, "ast_parsing", pct, current_file=Path(file_path_str).name, on_progress=on_progress
                )

                if not self.filesystem.exists(source_file.file_path):
                    continue

                source_code = self.filesystem.read_text(source_file.file_path)
                
                if not source_code.strip():
                    continue

                parser = self.parser_registry.get_parser(source_file.language)
                
                if parser:
                    try:
                        tree = parser.parse(source_code)
                        components = self.extractor.extract_components(
                            tree=tree,
                            source_code=source_code,
                            source_file=source_file,
                            language=source_file.language,
                        )
                        
                        all_components.extend(components)
                    
                    except Exception:
                        pass

            # -------------------------------------------------------------
            # Phase 3: Finding Aggregation & Quality Checks (70% - 90%)
            # -------------------------------------------------------------
            self._update_job_progress(job, "analyzing_findings", 75.0, on_progress=on_progress)
            
            # Baseline syntax & structural checks across extracted files
            for source_file in supported_files:
                if not self.filesystem.exists(source_file.file_path):
                    continue
                
                code = self.filesystem.read_text(source_file.file_path)
                source_file.content = code
                parser = self.parser_registry.get_parser(source_file.language)
                
                if parser and not parser.is_syntax_valid(code):
                    finding = AuditFinding(
                        title=f"Syntax Error in {Path(source_file.file_path).name}",
                        description="File contains fatal syntax errors that prevent full parsing.",
                        category=FindingCategory.CODE_QUALITY,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        file_path=str(source_file.file_path),
                        start_line=1,
                        end_line=1,
                        recommendation="Fix compilation or syntax errors before security auditing.",
                        source="ast",
                    )
                    
                    job.findings.append(finding)

                # Static security rule analysis
                rule_findings = self.rule_engine.analyze_file(source_file)
                job.findings.extend(rule_findings)

                # AI-assisted semantic vulnerability analysis (US 9)
                if self.ai_analyzer:
                    ai_findings = self.ai_analyzer.analyze_file(source_file)
                    job.findings.extend(ai_findings)

                # Code quality maintainability analysis (US 15)
                if self.quality_analyzer:
                    quality_findings = self.quality_analyzer.evaluate_file(source_file)
                    job.findings.extend(quality_findings)

            # System-wide architectural smell detection (US 15: circular dependencies, god classes)
            if self.architecture_detector:
                arch_findings = self.architecture_detector.evaluate_architecture(supported_files)
                job.findings.extend(arch_findings)

            # Hydrate findings with exact line boundaries and contextual snippets (US 16)
            attribution_helper = FindingAttributionHelper(filesystem=self.filesystem)
            attribution_helper.hydrate_findings(job.findings)

            self._update_job_progress(job, "analyzing_complete", 90.0, on_progress=on_progress)

            # -------------------------------------------------------------
            # Phase 4: Finalizing & Report Generation (90% - 100%)
            # -------------------------------------------------------------
            self._update_job_progress(job, "generating_report", 95.0, on_progress=on_progress)
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)

            summary_text = (
                f"Audit completed: {job.progress.scanned_files_count} files analyzed, "
                f"{len(job.findings)} findings identified."
            )

            report = AuditReport(
                job_id=job.job_id,
                project_id=job.project_id,
                findings=job.findings,
                summary=summary_text,
            )

            self._reports[job.job_id] = report
            if self.auto_save_report:
                try:
                    self.save_report_to_file(report)
                except Exception:
                    pass
            self._update_job_progress(job, "complete", 100.0, on_progress=on_progress)
            
            return report

        except Exception as e:
            job.status = JobStatus.FAILED
            job.error_message = str(e)
            job.completed_at = datetime.now(timezone.utc)
            self._update_job_progress(job, "failed", job.progress.percentage, on_progress=on_progress)
            raise e

    def _finalize_cancelled(self, job: AuditJob, project: Project) -> AuditReport:
        """Helper to create a partial report when a job is cancelled prematurely."""
        job.status = JobStatus.CANCELLED
        job.completed_at = datetime.now(timezone.utc)
        report = AuditReport(
            job_id=job.job_id,
            project_id=job.project_id,
            findings=job.findings,
            summary="Audit job was cancelled by user.",
        )
        
        self._reports[job.job_id] = report
        
        return report
