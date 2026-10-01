"""f09 — GitHub History: análisis de commits históricos en repos públicos del dominio."""
from __future__ import annotations
import asyncio
import re
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class GithubHistory(BaseModule):
    NAME        = "github_history"
    PHASE       = Phase.HISTORICAL
    DESCRIPTION = "Historial de commits públicos: secrets eliminados, emails, infra histórica"
    TAGS        = ["github", "commits", "history", "secrets"]

    # Patterns para detectar secrets en diffs de commits
    SECRET_PATTERNS = {
        "aws_key":    r"AKIA[0-9A-Z]{16}",
        "private_key":r"-----BEGIN (RSA |EC |)PRIVATE KEY-----",
        "github_pat": r"ghp_[a-zA-Z0-9]{36}",
        "api_key":    r"(?i)api[_-]?key\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,50})",
        "password":   r"(?i)password\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        "jwt":        r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        "stripe":     r"sk_live_[0-9a-zA-Z]{24,}",
    }

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            org_name = target.split(".")[0]
            headers  = {"Accept": "application/vnd.github+json"}
            if self.config.api.github:
                headers["Authorization"] = f"token {self.config.api.github}"

            async with aiohttp.ClientSession(headers=headers) as session:
                # Buscar repos del org/user
                repos_found = []
                for endpoint in [f"/orgs/{org_name}/repos", f"/users/{org_name}/repos"]:
                    async with session.get(
                        f"https://api.github.com{endpoint}",
                        params={"per_page": 30, "sort": "updated"},
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as resp:
                        if resp.status == 200:
                            repos_found = await resp.json()
                            break

                # Para cada repo, analizar commits recientes en busca de secrets
                for repo in repos_found[:5]:   # Limitar a 5 repos para no agotar rate limit
                    repo_name = repo.get("full_name", "")
                    if not repo_name:
                        continue

                    async with session.get(
                        f"https://api.github.com/repos/{repo_name}/commits",
                        params={"per_page": 10},
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as resp:
                        if resp.status == 200:
                            commits = await resp.json()
                            for commit in commits[:5]:
                                sha      = commit.get("sha", "")[:7]
                                message  = commit.get("commit", {}).get("message", "")
                                author   = commit.get("commit", {}).get("author", {})
                                email    = author.get("email", "")

                                # Guardar emails de committers
                                if email and "@" in email and "noreply" not in email:
                                    context.setdefault("commit_emails", []).append(email)
                                    result.add_finding(
                                        type="committer_email",
                                        value=email,
                                        severity=Severity.INFO,
                                        confidence=0.95,
                                        metadata={"repo": repo_name, "sha": sha},
                                        tags=["github", "email"],
                                    )

                                # Commits que mencionan credenciales en el mensaje
                                sensitive_msg_kw = [
                                    "remove password", "delete key", "fix secret",
                                    "remove api key", "wrong credentials", "add token",
                                    "remove token", "credential", "api key",
                                ]
                                if any(kw in message.lower() for kw in sensitive_msg_kw):
                                    result.add_finding(
                                        type="suspicious_commit_message",
                                        value=f"[{repo_name}@{sha}] {message[:100]}",
                                        severity=Severity.MEDIUM,
                                        confidence=0.7,
                                        metadata={
                                            "repo":    repo_name,
                                            "sha":     sha,
                                            "message": message[:200],
                                            "author":  author.get("name"),
                                        },
                                        tags=["github", "commit", "secret"],
                                    )

                                # Obtener diff del commit para buscar secrets eliminados
                                await asyncio.sleep(0.5)   # Rate limit
                                async with session.get(
                                    f"https://api.github.com/repos/{repo_name}/commits/{sha}",
                                    timeout=aiohttp.ClientTimeout(total=10),
                                ) as diff_resp:
                                    if diff_resp.status == 200:
                                        diff_data = await diff_resp.json()
                                        # Analizar archivos del commit
                                        files = diff_data.get("files", [])
                                        for f in files[:10]:
                                            patch = f.get("patch", "")
                                            if not patch:
                                                continue
                                            for secret_type, pattern in self.SECRET_PATTERNS.items():
                                                matches = re.findall(pattern, patch)
                                                for match in matches[:3]:
                                                    snippet = match if isinstance(match, str) else match[0]
                                                    result.add_finding(
                                                        type="historical_secret",
                                                        value=f"Secret {secret_type} en historial de {repo_name}",
                                                        severity=Severity.CRITICAL,
                                                        confidence=0.75,
                                                        metadata={
                                                            "type":    secret_type,
                                                            "repo":    repo_name,
                                                            "sha":     sha,
                                                            "file":    f.get("filename"),
                                                            "snippet": snippet[:50] + "...",
                                                        },
                                                        tags=["github", "secret", "historical"],
                                                    )

            result.risk_score = min(result.critical_count * 3.5 + result.high_count * 2, 10.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
