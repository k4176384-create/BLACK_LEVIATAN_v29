"""f03 — Sherlock Deep: username lookup en 30+ plataformas públicas."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity

# Plataformas con patrones de URL para detección de usuarios
PLATFORMS = {
    "Twitter/X":     "https://twitter.com/{}",
    "GitHub":        "https://github.com/{}",
    "Instagram":     "https://www.instagram.com/{}/",
    "LinkedIn":      "https://www.linkedin.com/in/{}/",
    "Reddit":        "https://www.reddit.com/user/{}/",
    "TikTok":        "https://www.tiktok.com/@{}",
    "YouTube":       "https://www.youtube.com/@{}",
    "Twitch":        "https://www.twitch.tv/{}",
    "Pinterest":     "https://www.pinterest.com/{}/",
    "Medium":        "https://medium.com/@{}",
    "DevTo":         "https://dev.to/{}",
    "HackerNews":    "https://news.ycombinator.com/user?id={}",
    "GitLab":        "https://gitlab.com/{}",
    "Bitbucket":     "https://bitbucket.org/{}",
    "Keybase":       "https://keybase.io/{}",
    "Steam":         "https://steamcommunity.com/id/{}",
    "DockerHub":     "https://hub.docker.com/u/{}",
    "PyPI":          "https://pypi.org/user/{}/",
    "NPM":           "https://www.npmjs.com/~{}",
    "Gravatar":      "https://en.gravatar.com/{}",
}


class SherlockDeep(BaseModule):
    NAME        = "sherlock_deep"
    PHASE       = Phase.ENUM
    DESCRIPTION = "Username lookup en 20+ plataformas (perfiles públicos)"
    TAGS        = ["username", "social", "profiles"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()

        # Extraer posibles usernames del target (dominio o email)
        usernames: set[str] = set()
        if "@" in target:
            usernames.add(target.split("@")[0])
        else:
            # Usar parte del dominio como username
            base = target.split(".")[0]
            usernames.add(base)
            usernames.add(target.replace(".", ""))

        # Agregar usernames ya descubiertos en fases anteriores
        for email in context.get("harvested_emails", [])[:5]:
            usernames.add(email.split("@")[0])

        found_profiles: list[dict] = []

        try:
            import aiohttp
            sem = asyncio.Semaphore(10)

            async def check(platform: str, url_template: str, username: str) -> None:
                async with sem:
                    url = url_template.format(username)
                    try:
                        async with aiohttp.ClientSession() as session:
                            async with session.get(
                                url,
                                timeout=aiohttp.ClientTimeout(total=10),
                                ssl=False,
                                allow_redirects=True,
                            ) as resp:
                                # 200 = perfil existe (simplificación)
                                if resp.status == 200:
                                    found_profiles.append({
                                        "platform": platform,
                                        "username": username,
                                        "url":      url,
                                    })
                                    result.add_finding(
                                        type="social_profile",
                                        value=url,
                                        severity=Severity.INFO,
                                        confidence=0.55,  # HTTP 200 ≠ perfil existe — candidato sin verificar
                                        metadata={"platform": platform, "username": username},
                                        tags=["social", "profile", platform.lower()],
                                    )
                    except Exception:
                        pass

            tasks = [
                check(platform, url_tmpl, uname)
                for uname in usernames
                for platform, url_tmpl in PLATFORMS.items()
            ]
            await asyncio.gather(*tasks)

            self.push_to_context(context, "social_profiles", found_profiles)
            result.metadata["found_profiles"] = len(found_profiles)
            result.risk_score = min(len(found_profiles) * 0.3 + 1.0, 5.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
