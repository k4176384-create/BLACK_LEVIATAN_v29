"""f02 — DNS brute force con wordlist y permutaciones."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity

WORDLIST = [
    "www","mail","ftp","api","dev","staging","test","admin","vpn","portal",
    "remote","app","secure","login","dashboard","blog","shop","cdn","assets",
    "static","img","media","upload","download","docs","support","help","status",
    "monitor","git","gitlab","github","jira","confluence","jenkins","ci","beta",
    "alpha","internal","intranet","corp","employee","hr","finance","payment",
    "checkout","store","mx","ns1","ns2","smtp","pop","imap","mx1","mx2",
    "autodiscover","webmail","cpanel","whm","plesk","panel","m","mobile","ws",
    "wss","api2","v1","v2","v3","backend","frontend","auth","sso","oauth",
    "grafana","kibana","elasticsearch","redis","mongodb","mysql","postgres",
    "db","database","cache","proxy","gateway","lb","loadbalancer","edge",
]


class SubPermutation(BaseModule):
    NAME        = "sub_permutation"
    PHASE       = Phase.DISCOVERY
    DESCRIPTION = "DNS brute force: wordlist de 70+ prefijos comunes"
    TAGS        = ["subdomain", "bruteforce", "dns"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import dns.resolver
            import dns.exception

            resolver = dns.resolver.Resolver()
            resolver.timeout   = 3
            resolver.lifetime  = 6
            resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

            found: list[str] = []
            sem = asyncio.Semaphore(30)

            async def check(prefix: str) -> None:
                async with sem:
                    fqdn = f"{prefix}.{target}"
                    loop = asyncio.get_event_loop()
                    try:
                        answers = await loop.run_in_executor(
                            None, resolver.resolve, fqdn, "A"
                        )
                        ips = [str(r) for r in answers]
                        found.append(fqdn)
                        result.add_finding(
                            type="subdomain_brute",
                            value=fqdn,
                            severity=Severity.INFO,
                            confidence=1.0,
                            metadata={"ips": ips, "method": "brute"},
                            tags=["subdomain"],
                        )
                    except Exception:
                        pass

            await asyncio.gather(*[check(w) for w in WORDLIST])

            self.push_to_context(context, "brute_subdomains", found)
            result.metadata["found"] = len(found)
            result.risk_score = min(len(found) * 0.15 + 1.0, 5.0)

        except ImportError:
            result.add_error("dnspython no instalado")
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
