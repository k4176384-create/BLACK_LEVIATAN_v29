"""f06 — GitHub OSINT: repos, miembros, leaks en código público."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class GithubOsint(BaseModule):
    NAME        = "github"
    PHASE       = Phase.SOCIAL
    DESCRIPTION = "GitHub: repos públicos, miembros, emails en commits y código expuesto"
    TAGS        = ["github", "code", "secrets", "osint"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            org_name   = target.split(".")[0]
            gh_token   = self.config.api.github
            headers    = {"Accept": "application/vnd.github+json"}
            if gh_token:
                headers["Authorization"] = f"token {gh_token}"

            async with aiohttp.ClientSession(headers=headers) as session:
                # Buscar organización
                async with session.get(
                    f"https://api.github.com/orgs/{org_name}",
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        org_data = await resp.json()
                        result.add_finding(
                            type="github_org",
                            value=f"Org encontrada: {org_data.get('login')}",
                            severity=Severity.INFO,
                            confidence=0.95,
                            metadata={
                                "name":         org_data.get("name"),
                                "public_repos": org_data.get("public_repos"),
                                "followers":    org_data.get("followers"),
                                "blog":         org_data.get("blog"),
                                "location":     org_data.get("location"),
                                "email":        org_data.get("email"),
                            },
                            tags=["github", "org"],
                        )
                        if org_data.get("email"):
                            context.setdefault("harvested_emails", []).append(org_data["email"])

                # Buscar repos de la org (top 100)
                async with session.get(
                    f"https://api.github.com/orgs/{org_name}/repos",
                    params={"per_page": 100, "sort": "updated"},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        repos = await resp.json()
                        for repo in repos[:30]:
                            repo_name = repo.get("full_name", "")
                            # Repos de alta sensibilidad
                            sensitive_keywords = [
                                "infra","infrastructure","config","secret","deploy",
                                "k8s","kubernetes","terraform","ansible","salt","puppet",
                                "credentials","internal","private","backup",
                            ]
                            is_sensitive = any(
                                kw in repo_name.lower() or kw in (repo.get("description") or "").lower()
                                for kw in sensitive_keywords
                            )
                            result.add_finding(
                                type="github_repo",
                                value=repo.get("html_url", ""),
                                severity=Severity.MEDIUM if is_sensitive else Severity.INFO,
                                confidence=0.9,
                                metadata={
                                    "name":       repo_name,
                                    "stars":      repo.get("stargazers_count"),
                                    "language":   repo.get("language"),
                                    "updated":    repo.get("updated_at"),
                                    "is_fork":    repo.get("fork"),
                                    "sensitive":  is_sensitive,
                                },
                                tags=["github", "repo"],
                            )

                # GitHub Search: posibles secrets en código público
                search_queries = [
                    f'"{target}" password',
                    f'"{target}" api_key',
                    f'"{target}" token',
                ]
                for q in search_queries:
                    await asyncio.sleep(2)   # GitHub search rate limit
                    async with session.get(
                        "https://api.github.com/search/code",
                        params={"q": q, "per_page": 5},
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as resp:
                        if resp.status == 200:
                            data  = await resp.json()
                            total = data.get("total_count", 0)
                            if total > 0:
                                result.add_finding(
                                    type="github_code_exposure",
                                    value=f"'{q}': {total} archivos en GitHub",
                                    severity=Severity.HIGH if total > 10 else Severity.MEDIUM,
                                    confidence=0.7,
                                    metadata={"query": q, "total": total,
                                              "sample": [i.get("html_url") for i in data.get("items", [])[:3]]},
                                    tags=["github", "code", "secrets"],
                                )

            result.risk_score = min(result.critical_count * 3 + result.high_count * 2 + 1.5, 10.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
