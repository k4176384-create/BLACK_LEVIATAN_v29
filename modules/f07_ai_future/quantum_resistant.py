"""f07 — Quantum Resistant Analysis: detectar uso de criptografía débil."""
from __future__ import annotations
import asyncio
import ssl
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class QuantumResistant(BaseModule):
    NAME        = "quantum_resistant"
    PHASE       = Phase.AI_FUTURE
    DESCRIPTION = "Análisis de criptografía: TLS versión, cipher suites, cert keys"
    TAGS        = ["crypto", "tls", "ssl", "quantum", "certificates"]

    WEAK_CIPHERS = frozenset([
        "RC4","DES","3DES","NULL","EXPORT","ANON",
        "MD5","SHA1","ADH","AECDH",
    ])
    WEAK_TLS = frozenset(["TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"])

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import socket

            # Obtener información del certificado TLS
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            try:
                loop = asyncio.get_event_loop()
                conn_info = await loop.run_in_executor(
                    None, self._get_tls_info, target
                )
                if conn_info:
                    version  = conn_info.get("version", "")
                    cipher   = conn_info.get("cipher", ("", "", 0))
                    cert     = conn_info.get("cert", {})

                    # TLS version check
                    if version in self.WEAK_TLS:
                        result.add_finding(
                            type="weak_tls_version",
                            value=f"TLS version débil: {version}",
                            severity=Severity.HIGH,
                            confidence=1.0,
                            metadata={"version": version},
                            tags=["tls", "crypto"],
                        )
                    else:
                        result.add_finding(
                            type="tls_version",
                            value=f"TLS version: {version}",
                            severity=Severity.INFO,
                            confidence=1.0,
                            tags=["tls"],
                        )

                    # Cipher suite check
                    cipher_name = cipher[0] if cipher else ""
                    if any(w in cipher_name.upper() for w in self.WEAK_CIPHERS):
                        result.add_finding(
                            type="weak_cipher",
                            value=f"Cipher débil: {cipher_name}",
                            severity=Severity.HIGH,
                            confidence=0.95,
                            metadata={"cipher": cipher_name},
                            tags=["cipher", "crypto"],
                        )

                    # Key size check (RSA < 2048 es débil)
                    key_bits = conn_info.get("key_bits", 2048)
                    if key_bits and key_bits < 2048:
                        result.add_finding(
                            type="weak_key_size",
                            value=f"Clave RSA de {key_bits} bits (mínimo recomendado: 2048)",
                            severity=Severity.HIGH,
                            confidence=0.9,
                            metadata={"bits": key_bits},
                            tags=["tls", "key"],
                        )

                    # Self-signed
                    issuer  = cert.get("issuer", {})
                    subject = cert.get("subject", {})
                    if issuer == subject:
                        result.add_finding(
                            type="self_signed_cert",
                            value="Certificado autofirmado detectado",
                            severity=Severity.MEDIUM,
                            confidence=0.95,
                            tags=["tls", "cert"],
                        )

            except Exception as tls_err:
                result.add_error(f"TLS check: {tls_err}")

            result.risk_score = min(result.high_count * 2.5 + result.medium_count * 1.0, 8.0) \
                if hasattr(result, 'medium_count') else min(result.high_count * 2.5, 8.0)

        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result

    def _get_tls_info(self, target: str) -> dict:
        import ssl, socket
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        try:
            with socket.create_connection((target, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    cert       = ssock.getpeercert()
                    version    = ssock.version()
                    cipher     = ssock.cipher()
                    # Intentar obtener key bits desde el certificado
                    key_bits = None
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.primitives.asymmetric import rsa, ec
                        raw = ssock.getpeercert(binary_form=True)
                        parsed = x509.load_der_x509_certificate(raw)
                        pub_key = parsed.public_key()
                        if isinstance(pub_key, rsa.RSAPublicKey):
                            key_bits = pub_key.key_size
                    except Exception:
                        pass
                    return {"version": version, "cipher": cipher,
                            "cert": cert, "key_bits": key_bits}
        except Exception:
            return {}
