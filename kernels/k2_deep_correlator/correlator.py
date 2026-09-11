"""
kernels/k2_deep_correlator/correlator.py — Grafo de Conocimiento + Análisis Temporal
Autor: Luis Sánchez — BLACK LEVIATAN v29

NetworkX + detección de cambios de infraestructura en el tiempo.
Correlaciona IPs, dominios, emails, ASNs y los conecta en un grafo.
"""
from __future__ import annotations
import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

import networkx as nx

if TYPE_CHECKING:
    from bl_config import BLConfig
    from core.event_bus import EventBus

log = logging.getLogger("bl.k2")


@dataclass
class TemporalRecord:
    """Un valor que ha cambiado con el tiempo."""
    entity:    str      # e.g. "sub.example.com"
    attribute: str      # e.g. "resolves_to"
    old_value: str
    new_value: str
    detected_at: float = field(default_factory=time.time)

    @property
    def is_migration(self) -> bool:
        return self.old_value != self.new_value


class KnowledgeGraph:
    """
    Grafo dirigido de entidades OSINT con dimensión temporal.
    Nodos: dominio, IP, email, ASN, cert, org, bucket
    Aristas: resolves_to, owned_by, hosted_on, cert_for, migrated_from
    """

    NODE_TYPES = frozenset(["domain", "subdomain", "ip", "email", "asn", "org",
                             "cert", "bucket", "url", "hash", "cve", "leak"])

    def __init__(self) -> None:
        self._g = nx.DiGraph()
        self._temporal: list[TemporalRecord] = []

    def add_entity(self, name: str, node_type: str, **attrs) -> None:
        attrs["type"] = node_type
        attrs["first_seen"] = attrs.get("first_seen", time.time())
        if self._g.has_node(name):
            # Actualizar atributos, detectar cambios
            existing = self._g.nodes[name]
            for k, v in attrs.items():
                if k in existing and existing[k] != v:
                    self._temporal.append(TemporalRecord(
                        entity=name, attribute=k,
                        old_value=str(existing[k]),
                        new_value=str(v),
                    ))
            self._g.nodes[name].update(attrs)
        else:
            self._g.add_node(name, **attrs)

    def add_relation(
        self,
        source: str,
        target: str,
        relation: str,
        weight: float = 1.0,
        **attrs,
    ) -> None:
        attrs.update({"relation": relation, "weight": weight, "ts": time.time()})
        if self._g.has_edge(source, target):
            self._g[source][target].update(attrs)
        else:
            self._g.add_edge(source, target, **attrs)

    def get_neighbors(self, entity: str, depth: int = 1) -> list[str]:
        if not self._g.has_node(entity):
            return []
        if depth == 1:
            return list(self._g.neighbors(entity))
        return list(nx.ego_graph(self._g, entity, radius=depth).nodes())

    def find_migrations(self) -> list[TemporalRecord]:
        return [r for r in self._temporal if r.is_migration]

    def find_orphans(self) -> list[str]:
        """Entidades sin conexiones — posibles activos olvidados."""
        return [n for n in self._g.nodes if self._g.degree(n) == 0]

    def find_bridges(self) -> list[str]:
        """
        Nodos que conectan comunidades distintas — alta importancia estratégica.
        Ej: un servidor que conecta la infra de AWS antigua con la nueva de Cloudflare.
        """
        undirected = self._g.to_undirected()
        if not nx.is_connected(undirected):
            return []
        try:
            return list(nx.articulation_points(undirected))
        except nx.NetworkXError:
            return []

    def find_clusters(self) -> list[set[str]]:
        """Detectar comunidades / clusters de infraestructura."""
        undirected = self._g.to_undirected()
        return list(nx.connected_components(undirected))

    def get_central_nodes(self, top_n: int = 10) -> list[tuple[str, float]]:
        """Nodos más centrales por PageRank — los más estratégicos."""
        if len(self._g) == 0:
            return []
        try:
            scores = nx.pagerank(self._g, alpha=0.85)
            return sorted(scores.items(), key=lambda x: x[1], reverse=True)[:top_n]
        except nx.PowerIterationFailedConvergence:
            return []

    def find_path(self, source: str, target: str) -> list[str]:
        """Camino más corto entre dos entidades."""
        try:
            return nx.shortest_path(self._g, source, target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def to_graphml(self) -> str:
        """Exporta a GraphML para Gephi/Neo4j."""
        import io
        buf = io.BytesIO()
        nx.write_graphml(self._g, buf)
        return buf.getvalue().decode("utf-8")

    @property
    def node_count(self) -> int:
        return self._g.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._g.number_of_edges()

    def summary(self) -> dict:
        by_type: dict[str, int] = {}
        for _, attrs in self._g.nodes(data=True):
            t = attrs.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
        return {
            "nodes":       self.node_count,
            "edges":       self.edge_count,
            "by_type":     by_type,
            "migrations":  len(self.find_migrations()),
            "clusters":    len(self.find_clusters()),
        }


class UnionFind:
    """
    Union-Find (Disjoint Set Union) para agrupar IPs/dominios relacionados
    en tiempo constante amortizado.
    """
    def __init__(self) -> None:
        self._parent: dict[str, str] = {}
        self._rank:   dict[str, int] = {}

    def find(self, x: str) -> str:
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x]   = 0
        if self._parent[x] != x:
            self._parent[x] = self.find(self._parent[x])   # path compression
        return self._parent[x]

    def union(self, x: str, y: str) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self._rank[rx] < self._rank[ry]:
            rx, ry = ry, rx
        self._parent[ry] = rx
        if self._rank[rx] == self._rank[ry]:
            self._rank[rx] += 1

    def are_connected(self, x: str, y: str) -> bool:
        return self.find(x) == self.find(y)

    def get_groups(self) -> dict[str, list[str]]:
        groups: dict[str, list[str]] = {}
        for node in self._parent:
            root = self.find(node)
            groups.setdefault(root, []).append(node)
        return groups


class DeepCorrelator:
    """
    K2: Motor de correlación. Los módulos llaman sus métodos para
    registrar entidades y relaciones. Al final del scan, el grafo
    se analiza para encontrar patrones y conexiones ocultas.
    """

    def __init__(self, config: "BLConfig", bus: "EventBus") -> None:
        self._config = config
        self._bus    = bus
        self.graph   = KnowledgeGraph()
        self.uf      = UnionFind()

    def register_domain(self, domain: str, **attrs) -> None:
        self.graph.add_entity(domain, "domain", **attrs)

    def register_subdomain(self, sub: str, parent: str, **attrs) -> None:
        self.graph.add_entity(sub, "subdomain", **attrs)
        self.graph.add_relation(sub, parent, "subdomain_of")

    def register_ip(self, ip: str, domain: str, **attrs) -> None:
        self.graph.add_entity(ip, "ip", **attrs)
        self.graph.add_relation(domain, ip, "resolves_to")
        self.uf.union(domain, ip)

    def register_email(self, email: str, domain: str, **attrs) -> None:
        self.graph.add_entity(email, "email", **attrs)
        self.graph.add_relation(email, domain, "belongs_to")

    def register_cert(self, cn: str, domain: str, sans: list[str]) -> None:
        cert_id = f"cert:{cn}"
        self.graph.add_entity(cert_id, "cert", cn=cn)
        self.graph.add_relation(cert_id, domain, "cert_for")
        for san in sans:
            self.graph.add_entity(san, "domain")
            self.graph.add_relation(cert_id, san, "cert_covers")

    def register_historical_ip(self, domain: str, old_ip: str, new_ip: str) -> None:
        self.graph.add_entity(old_ip, "ip", status="historical")
        self.graph.add_relation(domain, old_ip, "previously_resolved_to",
                                weight=0.5, note="Infraestructura migrada")
        if new_ip:
            self.graph.add_entity(new_ip, "ip", status="current")
            self.graph.add_relation(old_ip, new_ip, "migrated_to")

    async def analyze(self) -> dict:
        """Análisis completo del grafo. Llamado al final del scan."""
        bridges     = self.graph.find_bridges()
        migrations  = self.graph.find_migrations()
        orphans     = self.graph.find_orphans()
        central     = self.graph.get_central_nodes(10)
        clusters    = self.graph.find_clusters()
        groups      = self.uf.get_groups()

        analysis = {
            "graph_summary": self.graph.summary(),
            "infrastructure_bridges": bridges,
            "temporal_migrations": [
                {"entity": r.entity, "attribute": r.attribute,
                 "old": r.old_value, "new": r.new_value}
                for r in migrations
            ],
            "orphaned_assets":  orphans,
            "central_entities": [{"entity": e, "score": round(s, 4)} for e, s in central],
            "infrastructure_clusters": len(clusters),
            "union_groups": len(groups),
        }

        await self._bus.publish("k2.analysis_complete", analysis)
        return analysis

    def export_graphml(self) -> str:
        return self.graph.to_graphml()
