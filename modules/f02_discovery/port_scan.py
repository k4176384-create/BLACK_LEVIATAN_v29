"""f02 — Async TCP port scanner con banner grab para reducir falsos positivos anycast."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity

TOP_PORTS = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
    110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",465:"SMTPS",
    587:"SMTP-TLS",993:"IMAPS",995:"POP3S",1433:"MSSQL",1521:"Oracle",
    2375:"Docker",3000:"Node/Rails",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
    5672:"RabbitMQ",5900:"VNC",6379:"Redis",6443:"K8s API",8080:"HTTP-Alt",
    8443:"HTTPS-Alt",8888:"Jupyter",9000:"PHP/Adminer",9090:"Prometheus",
    9200:"Elasticsearch",9300:"ES-Transport",11211:"Memcached",27017:"MongoDB",
    27018:"MongoDB-Alt",28017:"MongoDB-Web",50000:"SAP",
}
HIGH_RISK_PORTS = {21,23,445,3389,5900,2375,9200,27017,11211,6379}


class PortScan(BaseModule):
    NAME        = "port_scan"
    PHASE       = Phase.DISCOVERY
    DESCRIPTION = "TCP async scan con banner grab — reduce falsos positivos anycast/CDN"
    TAGS        = ["ports", "tcp", "network"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import socket
            try:
                host_ip = socket.gethostbyname(target)
            except socket.gaierror:
                return self.skip(target, "No se pudo resolver el hostname")

            open_ports: list[int] = []
            sem = asyncio.Semaphore(50)   # Reducido para evitar drops en CDN

            async def check_port(port: int) -> None:
                async with sem:
                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(host_ip, port), timeout=2.0
                        )

                        # Banner grab — distingue puertos reales de anycast traps
                        banner = b""
                        try:
                            banner = await asyncio.wait_for(reader.read(128), timeout=1.0)
                        except asyncio.TimeoutError:
                            pass   # Sin banner pero conexión abierta
                        except Exception:
                            pass

                        writer.close()
                        try:
                            await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
                        except Exception:
                            pass

                        has_banner = len(banner) > 0
                        is_high_risk = port in HIGH_RISK_PORTS
                        # Edge detection: si IP es Cloudflare/EDGE, degradar CRITICAL
                        from core.edge_detector import detect_edge
                        edge = detect_edge({}, ip=host_ip, asn=context.get("geo_data",{}).get(host_ip,{}).get("asn",""))
                        is_edge = edge["is_edge"]
                        # ValidationEngine
                        from core.validation import validate_finding
                        meta_tmp = {"ip": host_ip, "port": port, "has_banner": has_banner}
                        val = validate_finding("open_port", f"{host_ip}:{port}", meta_tmp)

                        if is_edge and is_high_risk and not has_banner:
                            confidence = 0.35
                            note = f"EDGE {edge['provider']} — sin banner, altamente sospechoso anycast"
                            sev = Severity.LOW  # degradado, no CRITICAL
                            validation_state = "INFERRED"
                            limitations = "IP pertenece a CDN/EDGE (AS13335). Puerto abierto aparente probablemente no es ORIGIN."
                        elif is_high_risk and not has_banner:
                            confidence = val["confidence"]
                            note = "posible anycast — sin banner"
                            sev = Severity.MEDIUM  # degradado de CRITICAL
                            validation_state = val["validation_state"]
                            limitations = val["limitations"]
                        elif has_banner:
                            confidence = 0.95
                            note = banner[:32].decode("utf-8", errors="replace").strip()
                            sev = Severity.CRITICAL if is_high_risk else Severity.LOW
                            validation_state = "OBSERVED"
                            limitations = ""
                        else:
                            confidence = 0.75
                            note = "conexión aceptada sin banner"
                            sev = Severity.LOW
                            validation_state = "OBSERVED"
                            limitations = ""

                        # Si edge, marcar provenance
                        open_ports.append(port)
                        service = TOP_PORTS.get(port, "unknown")
                        from modules.base_module import ValidationState
                        vs = getattr(ValidationState, validation_state, ValidationState.INFERRED)

                        result.add_finding(
                            type="open_port",
                            value=f"{host_ip}:{port} ({service})",
                            severity=sev,
                            confidence=confidence,
                            metadata={
                                "ip":         host_ip,
                                "port":       port,
                                "service":    service,
                                "banner":     banner[:64].decode("utf-8", errors="replace") if banner else None,
                                "has_banner": has_banner,
                                "note":       note,
                                "edge":       edge,
                            },
                            tags=["port", "tcp"] + (["edge"] if is_edge else []),
                            validation_state=vs,
                            limitations=limitations,
                            evidence={"banner": banner[:64].decode("utf-8", errors="replace") if banner else "", "is_edge": is_edge},
                            provenance={"source": "port_scan", "source_type": "active_tcp", "method": "banner_grab"},
                        )
                    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                        pass

            await asyncio.gather(*[check_port(p) for p in TOP_PORTS])

            self.push_to_context(context, "open_ports", open_ports)
            result.metadata["open_ports"] = open_ports
            result.risk_score = min(
                result.critical_count * 3.0 + len(open_ports) * 0.3,
                10.0
            )
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
