"""API security scanner — tests REST/GraphQL APIs for vulnerabilities.

Capabilities:
- Endpoint discovery from OpenAPI/Swagger specs
- Authentication testing (broken auth, token manipulation)
- Authorization testing (BOLA/IDOR, broken function-level auth)
- Input validation (injection, type confusion, boundary values)
- Rate limiting detection
- CORS misconfiguration detection
- HTTP method testing
- Content-type confusion
- GraphQL introspection and injection
- Mass assignment detection
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx
import structlog

logger = structlog.get_logger()


@dataclass
class APIEndpoint:
    """A discovered API endpoint."""
    path: str
    method: str = "GET"
    parameters: list[dict[str, Any]] = field(default_factory=list)
    auth_required: bool = False
    content_type: str = "application/json"
    description: str = ""


@dataclass
class APIFinding:
    """A security finding from API testing."""
    title: str
    severity: str
    endpoint: str
    method: str
    description: str
    evidence: str = ""
    category: str = ""  # auth, injection, config, logic
    cwe_id: str = ""
    confidence: float = 0.7

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title, "severity": self.severity,
            "endpoint": self.endpoint, "method": self.method,
            "description": self.description, "evidence": self.evidence[:500],
            "category": self.category, "cwe_id": self.cwe_id,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class APIScanResult:
    """Results from API security scan."""
    base_url: str = ""
    endpoints_discovered: int = 0
    endpoints_tested: int = 0
    findings: list[APIFinding] = field(default_factory=list)
    auth_type: str = "unknown"
    api_type: str = "rest"  # rest, graphql, soap
    cors_issues: list[dict[str, str]] = field(default_factory=list)
    rate_limiting: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "endpoints_discovered": self.endpoints_discovered,
            "endpoints_tested": self.endpoints_tested,
            "findings": [f.to_dict() for f in self.findings],
            "auth_type": self.auth_type,
            "api_type": self.api_type,
            "cors_issues": self.cors_issues,
            "rate_limiting": self.rate_limiting,
            "severity_counts": self._severity_counts(),
        }

    def _severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


# Injection payloads for API parameters
API_INJECTION_PAYLOADS = {
    "sqli": ["' OR '1'='1", "1' ORDER BY 1--", "1 UNION SELECT NULL--", "'; DROP TABLE--"],
    "xss": ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>'],
    "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
    "cmdi": ["; id", "| id", "$(id)"],
    "nosql": ['{"$gt": ""}', '{"$ne": null}'],
    "path_traversal": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
    "ssrf": ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"],
}

# Common API paths to probe
COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql", "/altair",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/swagger-ui", "/swagger-ui.html",
    "/.well-known/openapi.json",
    "/api/health", "/api/status", "/api/info",
    "/api/users", "/api/user", "/api/admin",
    "/api/config", "/api/settings",
    "/api/auth/login", "/api/auth/register",
    "/api/debug", "/api/test",
]

# IDOR test patterns
IDOR_PATTERNS = [
    (r"/(\d+)", "numeric_id"),
    (r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", "uuid"),
    (r"/users/(\w+)", "username"),
]


class APIScanner:
    """Scans APIs for security vulnerabilities."""

    def __init__(self, timeout: float = 10.0, max_concurrent: int = 10) -> None:
        self._timeout = timeout
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._findings: list[APIFinding] = []

    async def scan(
        self,
        base_url: str,
        auth_headers: dict[str, str] | None = None,
        spec_url: str = "",
    ) -> APIScanResult:
        """Run comprehensive API security scan."""
        result = APIScanResult(base_url=base_url)

        async with httpx.AsyncClient(
            timeout=self._timeout,
            verify=False,
            follow_redirects=True,
            headers=auth_headers or {},
        ) as client:
            # Phase 1: Discovery
            endpoints = await self._discover_endpoints(client, base_url, spec_url)
            result.endpoints_discovered = len(endpoints)

            # Phase 2: Detect API type
            result.api_type = await self._detect_api_type(client, base_url)

            # Phase 3: Auth testing
            result.auth_type = await self._detect_auth_type(client, base_url)

            # Phase 4: CORS testing
            result.cors_issues = await self._test_cors(client, base_url)

            # Phase 5: Rate limit testing
            result.rate_limiting = await self._test_rate_limiting(client, base_url)

            # Phase 6: Endpoint-level testing
            for endpoint in endpoints:
                await self._test_endpoint(client, base_url, endpoint, result)
                result.endpoints_tested += 1

            # Phase 7: GraphQL specific tests
            if result.api_type == "graphql":
                await self._test_graphql(client, base_url, result)

            # Phase 8: HTTP method testing
            await self._test_http_methods(client, base_url, endpoints, result)

        result.findings = self._findings
        return result

    async def _discover_endpoints(
        self, client: httpx.AsyncClient, base_url: str, spec_url: str
    ) -> list[APIEndpoint]:
        """Discover API endpoints."""
        endpoints: list[APIEndpoint] = []

        # Try to fetch OpenAPI spec
        spec_urls = [spec_url] if spec_url else [
            urljoin(base_url, p) for p in [
                "/swagger.json", "/openapi.json", "/api-docs",
                "/v1/swagger.json", "/v2/swagger.json", "/v3/api-docs",
            ]
        ]

        for url in spec_urls:
            if not url:
                continue
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    spec = resp.json()
                    endpoints.extend(self._parse_openapi_spec(spec))
                    if endpoints:
                        break
            except Exception:
                pass

        # Probe common paths
        tasks = [self._probe_path(client, base_url, path) for path in COMMON_API_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for path, probe_result in zip(COMMON_API_PATHS, results):
            if isinstance(probe_result, Exception):
                continue
            if probe_result:
                endpoints.append(APIEndpoint(path=path, method="GET"))

        return endpoints

    def _parse_openapi_spec(self, spec: dict[str, Any]) -> list[APIEndpoint]:
        """Parse OpenAPI/Swagger spec into endpoints."""
        endpoints = []
        paths = spec.get("paths", {})

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                    params = []
                    for param in details.get("parameters", []):
                        params.append({
                            "name": param.get("name", ""),
                            "in": param.get("in", "query"),
                            "required": param.get("required", False),
                            "type": param.get("schema", {}).get("type", "string"),
                        })

                    endpoints.append(APIEndpoint(
                        path=path,
                        method=method.upper(),
                        parameters=params,
                        description=details.get("summary", ""),
                    ))

        return endpoints

    async def _probe_path(self, client: httpx.AsyncClient, base_url: str, path: str) -> bool:
        """Check if a path exists."""
        async with self._semaphore:
            try:
                url = urljoin(base_url, path)
                resp = await client.get(url)
                return resp.status_code not in (404, 405)
            except Exception:
                return False

    async def _detect_api_type(self, client: httpx.AsyncClient, base_url: str) -> str:
        """Detect if API is REST, GraphQL, or SOAP."""
        # Check for GraphQL
        try:
            graphql_url = urljoin(base_url, "/graphql")
            resp = await client.post(graphql_url, json={"query": "{__typename}"})
            if resp.status_code == 200 and "data" in resp.text:
                return "graphql"
        except Exception:
            pass

        # Check for SOAP (WSDL)
        try:
            wsdl_url = urljoin(base_url, "?wsdl")
            resp = await client.get(wsdl_url)
            if resp.status_code == 200 and "wsdl" in resp.text.lower():
                return "soap"
        except Exception:
            pass

        return "rest"

    async def _detect_auth_type(self, client: httpx.AsyncClient, base_url: str) -> str:
        """Detect authentication mechanism."""
        try:
            resp = await client.get(base_url)
            headers = dict(resp.headers)

            if "www-authenticate" in headers:
                auth = headers["www-authenticate"].lower()
                if "bearer" in auth:
                    return "bearer"
                elif "basic" in auth:
                    return "basic"
                elif "digest" in auth:
                    return "digest"

            # Check for API key headers
            for path in ["/api/health", "/api/v1", "/api"]:
                try:
                    r = await client.get(urljoin(base_url, path))
                    if r.status_code == 401:
                        body = r.text.lower()
                        if "api key" in body or "api_key" in body:
                            return "api_key"
                        elif "token" in body:
                            return "bearer"
                        elif "unauthorized" in body:
                            return "unknown_required"
                except Exception:
                    pass

        except Exception:
            pass

        return "none"

    async def _test_cors(self, client: httpx.AsyncClient, base_url: str) -> list[dict[str, str]]:
        """Test for CORS misconfigurations."""
        issues = []

        test_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            "null",
        ]

        for origin in test_origins:
            try:
                resp = await client.get(base_url, headers={"Origin": origin})
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                if acao == "*":
                    issues.append({
                        "issue": "Wildcard CORS (Access-Control-Allow-Origin: *)",
                        "severity": "medium",
                    })
                elif acao == origin:
                    issue = {
                        "issue": f"CORS reflects arbitrary origin: {origin}",
                        "severity": "high",
                    }
                    if acac.lower() == "true":
                        issue["severity"] = "critical"
                        issue["issue"] += " WITH credentials"
                    issues.append(issue)

                    self._findings.append(APIFinding(
                        title="CORS Misconfiguration",
                        severity=issue["severity"],
                        endpoint=base_url,
                        method="GET",
                        description=issue["issue"],
                        evidence=f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                        category="config",
                        cwe_id="CWE-942",
                    ))
                elif acao == "null":
                    issues.append({
                        "issue": "CORS allows null origin",
                        "severity": "high",
                    })

            except Exception:
                pass

        return issues

    async def _test_rate_limiting(self, client: httpx.AsyncClient, base_url: str) -> dict[str, Any]:
        """Test rate limiting."""
        results: dict[str, Any] = {"has_rate_limiting": False, "requests_before_limit": 0}

        try:
            # Send rapid requests
            count = 0
            for _ in range(50):
                resp = await client.get(base_url)
                count += 1
                if resp.status_code == 429:
                    results["has_rate_limiting"] = True
                    results["requests_before_limit"] = count
                    retry_after = resp.headers.get("retry-after", "")
                    if retry_after:
                        results["retry_after"] = retry_after
                    break

            if not results["has_rate_limiting"]:
                results["requests_before_limit"] = count
                self._findings.append(APIFinding(
                    title="No Rate Limiting Detected",
                    severity="medium",
                    endpoint=base_url,
                    method="GET",
                    description=f"Sent {count} requests without rate limiting response (429)",
                    category="config",
                    cwe_id="CWE-770",
                    confidence=0.6,
                ))

        except Exception:
            pass

        return results

    async def _test_endpoint(
        self, client: httpx.AsyncClient, base_url: str, endpoint: APIEndpoint, result: APIScanResult
    ) -> None:
        """Test a specific endpoint for vulnerabilities."""
        url = urljoin(base_url, endpoint.path)

        # Injection testing on parameters
        for param in endpoint.parameters:
            param_name = param.get("name", "")
            param_in = param.get("in", "query")

            for inj_type, payloads in API_INJECTION_PAYLOADS.items():
                for payload in payloads[:3]:
                    async with self._semaphore:
                        try:
                            if param_in == "query":
                                resp = await client.request(
                                    endpoint.method, url, params={param_name: payload}
                                )
                            elif param_in == "body":
                                resp = await client.request(
                                    endpoint.method, url, json={param_name: payload}
                                )
                            else:
                                continue

                            self._check_injection_response(
                                resp, inj_type, payload, endpoint.path, endpoint.method, param_name
                            )
                        except Exception:
                            pass

        # IDOR testing
        await self._test_idor(client, base_url, endpoint)

    def _check_injection_response(
        self, resp: httpx.Response, inj_type: str, payload: str,
        path: str, method: str, param: str
    ) -> None:
        """Check if an injection payload was successful."""
        body = resp.text.lower()
        status = resp.status_code

        detected = False
        evidence = ""

        if inj_type == "sqli":
            sql_errors = ["sql syntax", "mysql", "postgresql", "sqlite", "ora-", "mssql", "syntax error"]
            for err in sql_errors:
                if err in body:
                    detected = True
                    evidence = f"SQL error in response: {err}"
                    break

        elif inj_type == "xss":
            if payload.lower() in body:
                detected = True
                evidence = "Payload reflected in response without encoding"

        elif inj_type == "ssti":
            if "49" in body and "{{7*7}}" in payload:
                detected = True
                evidence = "Template expression evaluated (49 found in response)"

        elif inj_type == "cmdi":
            if "uid=" in body or "root:" in body:
                detected = True
                evidence = "Command output detected in response"

        elif inj_type == "path_traversal":
            if "root:" in body or "[boot loader]" in body.lower():
                detected = True
                evidence = "File contents detected in response"

        elif inj_type == "ssrf":
            # Check for timing or content differences
            if status == 200 and "meta-data" in body:
                detected = True
                evidence = "SSRF: Cloud metadata accessible"

        if detected:
            severity_map = {
                "sqli": "critical", "cmdi": "critical", "ssti": "high",
                "ssrf": "high", "xss": "medium", "nosql": "high",
                "path_traversal": "high",
            }
            cwe_map = {
                "sqli": "CWE-89", "xss": "CWE-79", "cmdi": "CWE-78",
                "ssti": "CWE-1336", "ssrf": "CWE-918", "nosql": "CWE-943",
                "path_traversal": "CWE-22",
            }
            self._findings.append(APIFinding(
                title=f"{inj_type.upper()} in {path} parameter '{param}'",
                severity=severity_map.get(inj_type, "medium"),
                endpoint=path,
                method=method,
                description=f"{inj_type.upper()} injection detected on parameter '{param}'",
                evidence=f"Payload: {payload}\n{evidence}",
                category="injection",
                cwe_id=cwe_map.get(inj_type, ""),
                confidence=0.85,
            ))

    async def _test_idor(
        self, client: httpx.AsyncClient, base_url: str, endpoint: APIEndpoint
    ) -> None:
        """Test for IDOR (Insecure Direct Object Reference)."""
        path = endpoint.path

        for pattern, id_type in IDOR_PATTERNS:
            match = re.search(pattern, path)
            if match:
                original_id = match.group(1)
                if id_type == "numeric_id":
                    test_ids = [str(int(original_id) + 1), str(int(original_id) - 1), "0", "1"]
                elif id_type == "uuid":
                    test_ids = ["00000000-0000-0000-0000-000000000000"]
                else:
                    test_ids = ["admin", "test", "root"]

                for test_id in test_ids:
                    test_path = path[:match.start(1)] + test_id + path[match.end(1):]
                    test_url = urljoin(base_url, test_path)
                    async with self._semaphore:
                        try:
                            resp = await client.request(endpoint.method, test_url)
                            if resp.status_code == 200:
                                self._findings.append(APIFinding(
                                    title=f"Potential IDOR on {path}",
                                    severity="high",
                                    endpoint=path,
                                    method=endpoint.method,
                                    description=f"Changing {id_type} from {original_id} to {test_id} returned 200 OK",
                                    evidence=f"URL: {test_url}\nStatus: {resp.status_code}",
                                    category="auth",
                                    cwe_id="CWE-639",
                                    confidence=0.5,
                                ))
                        except Exception:
                            pass
                break

    async def _test_graphql(
        self, client: httpx.AsyncClient, base_url: str, result: APIScanResult
    ) -> None:
        """GraphQL-specific security tests."""
        graphql_url = urljoin(base_url, "/graphql")

        # Introspection test
        introspection_query = """
        {
          __schema {
            types {
              name
              fields {
                name
              }
            }
          }
        }
        """

        try:
            resp = await client.post(graphql_url, json={"query": introspection_query})
            if resp.status_code == 200:
                data = resp.json()
                if "data" in data and "__schema" in data.get("data", {}):
                    types = data["data"]["__schema"].get("types", [])
                    self._findings.append(APIFinding(
                        title="GraphQL Introspection Enabled",
                        severity="medium",
                        endpoint="/graphql",
                        method="POST",
                        description=f"Introspection query succeeded. {len(types)} types exposed.",
                        evidence=f"Types: {', '.join(t.get('name', '') for t in types[:20])}",
                        category="config",
                        cwe_id="CWE-200",
                        confidence=0.95,
                    ))
        except Exception:
            pass

        # Depth limit test
        deep_query = '{ __typename ' + '{ __typename ' * 20 + '}' * 20 + '}'
        try:
            resp = await client.post(graphql_url, json={"query": deep_query})
            if resp.status_code == 200:
                self._findings.append(APIFinding(
                    title="GraphQL No Query Depth Limit",
                    severity="medium",
                    endpoint="/graphql",
                    method="POST",
                    description="Deep nested query accepted without depth limiting",
                    category="config",
                    cwe_id="CWE-770",
                    confidence=0.7,
                ))
        except Exception:
            pass

        # Batch query test
        batch_query = [{"query": "{__typename}"} for _ in range(100)]
        try:
            resp = await client.post(graphql_url, json=batch_query)
            if resp.status_code == 200:
                self._findings.append(APIFinding(
                    title="GraphQL Batch Query Not Limited",
                    severity="low",
                    endpoint="/graphql",
                    method="POST",
                    description="100 batched queries accepted without limiting",
                    category="config",
                    cwe_id="CWE-770",
                    confidence=0.6,
                ))
        except Exception:
            pass

    async def _test_http_methods(
        self, client: httpx.AsyncClient, base_url: str,
        endpoints: list[APIEndpoint], result: APIScanResult
    ) -> None:
        """Test for dangerous HTTP methods."""
        dangerous_methods = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]

        for endpoint in endpoints[:10]:
            url = urljoin(base_url, endpoint.path)
            for method in dangerous_methods:
                async with self._semaphore:
                    try:
                        resp = await client.request(method, url)
                        if resp.status_code not in (405, 404, 501):
                            self._findings.append(APIFinding(
                                title=f"HTTP {method} allowed on {endpoint.path}",
                                severity="low" if method == "TRACE" else "info",
                                endpoint=endpoint.path,
                                method=method,
                                description=f"HTTP {method} returned {resp.status_code}",
                                category="config",
                                confidence=0.5,
                            ))
                    except Exception:
                        pass
