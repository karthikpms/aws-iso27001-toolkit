"""
CISO Assistant API Client

Handles authentication, finding creation/updates, and evidence uploads
for the CISO Assistant GRC platform.
"""

import logging
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)

API_CALL_DELAY = 0.1  # 100ms between calls per spec


class CISOClientError(Exception):
    """Raised when the CISO Assistant API returns an error."""


class CISOClient:
    """Client for CISO Assistant REST API."""

    def __init__(self, base_url: str, email: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.api_url = f"{self.base_url}/api"
        self.session = requests.Session()
        self._authenticate(email, password)

    def _authenticate(self, email: str, password: str) -> None:
        """Obtain JWT token pair from CISO Assistant."""
        resp = self.session.post(
            f"{self.api_url}/iam/login/",
            json={"username": email, "password": password},
        )
        if resp.status_code != 200:
            raise CISOClientError(
                f"Authentication failed ({resp.status_code}): {resp.text}"
            )
        data = resp.json()
        token = data.get("token")
        if not token:
            raise CISOClientError("No token in authentication response")
        self.session.headers["Authorization"] = f"Token {token}"
        logger.info("Authenticated with CISO Assistant")

    def _request(
        self, method: str, path: str, **kwargs: Any
    ) -> requests.Response:
        """Make an API request with rate limiting."""
        time.sleep(API_CALL_DELAY)
        url = f"{self.api_url}/{path.lstrip('/')}"
        resp = self.session.request(method, url, **kwargs)
        if resp.status_code >= 400:
            raise CISOClientError(
                f"{method.upper()} {path} failed ({resp.status_code}): {resp.text}"
            )
        return resp

    # --- Frameworks ---

    def get_frameworks(self) -> list[dict]:
        """List all loaded compliance frameworks."""
        return self._request("GET", "/frameworks/").json().get("results", [])

    def get_framework_by_name(self, name: str) -> dict | None:
        """Find a framework by name (case-insensitive partial match)."""
        frameworks = self.get_frameworks()
        for fw in frameworks:
            if name.lower() in fw.get("name", "").lower():
                return fw
        return None

    # --- Stored Libraries ---

    def list_stored_libraries(self, search: str = "") -> list[dict]:
        """List available stored libraries (paginated)."""
        results = []
        params = {"search": search} if search else {}
        url = "/stored-libraries/"
        while url:
            resp = self._request("GET", url, params=params).json()
            results.extend(resp.get("results", []))
            next_url = resp.get("next")
            url = next_url.replace(self.api_url, "") if next_url else None
            params = {}  # only pass on first request
        return results

    def import_stored_library(self, library_id: str) -> dict:
        """Import a stored library into the active database."""
        return self._request(
            "POST", f"/stored-libraries/{library_id}/import/"
        ).json()

    # --- Requirement Nodes ---

    def list_requirement_nodes(self, framework_id: str) -> list[dict]:
        """List all requirement nodes for a framework (paginated)."""
        results = []
        url = f"/requirement-nodes/?framework={framework_id}"
        while url:
            resp = self._request("GET", url).json()
            results.extend(resp.get("results", []))
            next_url = resp.get("next")
            url = next_url.replace(self.api_url, "") if next_url else None
        return results

    # --- Compliance Assessments ---

    def list_compliance_assessments(self) -> list[dict]:
        return (
            self._request("GET", "/compliance-assessments/")
            .json()
            .get("results", [])
        )

    def create_compliance_assessment(
        self, name: str, framework_id: str, project_id: str
    ) -> dict:
        return self._request(
            "POST",
            "/compliance-assessments/",
            json={
                "name": name,
                "framework": framework_id,
                "project": project_id,
            },
        ).json()

    # --- Projects ---

    def list_projects(self) -> list[dict]:
        return self._request("GET", "/folders/").json().get("results", [])

    def create_project(self, name: str) -> dict:
        return self._request(
            "POST", "/folders/", json={"name": name}
        ).json()

    # --- Findings Assessments ---

    def list_findings_assessments(self) -> list[dict]:
        return (
            self._request("GET", "/findings-assessments/")
            .json()
            .get("results", [])
        )

    def create_findings_assessment(self, data: dict) -> dict:
        """Create a findings assessment (container for scan findings)."""
        return self._request(
            "POST", "/findings-assessments/", json=data
        ).json()

    # --- Findings ---

    def list_findings(self, search: str = "") -> list[dict]:
        params = {"search": search} if search else {}
        return (
            self._request("GET", "/findings/", params=params)
            .json()
            .get("results", [])
        )

    def create_finding(self, data: dict) -> dict:
        """Create a new finding in CISO Assistant."""
        return self._request("POST", "/findings/", json=data).json()

    def update_finding(self, finding_id: str, data: dict) -> dict:
        """Update an existing finding."""
        return self._request(
            "PATCH", f"/findings/{finding_id}/", json=data
        ).json()

    def delete_finding(self, finding_id: str) -> None:
        """Delete a finding by ID."""
        self._request("DELETE", f"/findings/{finding_id}/")

    def delete_findings_assessment(self, assessment_id: str) -> None:
        """Delete a findings assessment by ID."""
        self._request("DELETE", f"/findings-assessments/{assessment_id}/")

    # --- Requirement Assessments ---

    def list_requirement_assessments(
        self, compliance_assessment_id: str
    ) -> list[dict]:
        """List requirement assessments for a compliance assessment."""
        results = []
        url = f"/requirement-assessments/?compliance_assessment={compliance_assessment_id}"
        while url:
            resp = self._request("GET", url).json()
            results.extend(resp.get("results", []))
            url = resp.get("next")
            if url:
                # Strip base URL if present to get relative path
                url = url.replace(self.api_url, "")
        return results

    def update_requirement_assessment(
        self, assessment_id: str, data: dict
    ) -> dict:
        return self._request(
            "PATCH", f"/requirement-assessments/{assessment_id}/", json=data
        ).json()

    # --- Assets ---

    def list_assets(self, search: str = "") -> list[dict]:
        params = {"search": search} if search else {}
        return (
            self._request("GET", "/assets/", params=params)
            .json()
            .get("results", [])
        )

    def create_asset(self, data: dict) -> dict:
        """Create a new asset in CISO Assistant."""
        return self._request("POST", "/assets/", json=data).json()

    def update_asset(self, asset_id: str, data: dict) -> dict:
        """Update an existing asset."""
        return self._request(
            "PATCH", f"/assets/{asset_id}/", json=data
        ).json()

    # --- Evidence ---

    def upload_evidence(
        self,
        name: str,
        file_path: str,
        folder_id: str,
        applied_controls: list[str] | None = None,
    ) -> dict:
        """Upload an evidence file."""
        with open(file_path, "rb") as f:
            data: dict[str, Any] = {"name": name, "folder": folder_id}
            if applied_controls:
                data["applied_controls"] = applied_controls
            return self._request(
                "POST",
                "/evidences/",
                data=data,
                files={"attachment": f},
            ).json()
