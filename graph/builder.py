"""
ArchGuard - Graph Builder
-------------------------
Takes the validated architecture dict from the parser and builds
a graph representation using the specified backend.

Pipeline:
    parser.parse() -> dict -> GraphBuilder.build() -> GraphInterface
"""

from graph.base import GraphInterface
from graph.networkx import NetworkXGraph
from graph.igraph import IGraphGraph


# Available backends - add new ones here as they are implemented
BACKENDS = {
    "networkx": NetworkXGraph,
    "igraph":   IGraphGraph,
}


class GraphBuilder:
    """
    Converts a validated architecture dict into a graph.

    Usage:
        arch   = parse_architecture("S1.yaml")
        builder = GraphBuilder(arch, backend="networkx")
        graph   = builder.build()
    """

    def __init__(self, arch: dict, backend: str = "networkx"):
        if backend not in BACKENDS:
            raise ValueError(
                f"Unknown backend '{backend}'. "
                f"Available backends: {list(BACKENDS.keys())}"
            )
        self.arch    = arch
        self.graph   = BACKENDS[backend]()  # instantiate the chosen backend
        self.backend = backend

    def build(self) -> GraphInterface:
        """
        Build and return the graph from the architecture dict.
        Adds all components as nodes and all data flows as edges.
        """
        self._add_nodes()
        self._add_edges()
        return self.graph


    def _add_nodes(self) -> None:
        """
        Add each component as a node.
        Stores all component attributes directly on the node so the
        STRIDE engine can access them without looking up the original dict.
        """
        for component in self.arch.get("components", []):
            node_id = component["id"]

            # Flatten properties dict into top-level attributes
            # so STRIDE engine can do node.get("logging") instead of
            # node.get("properties", {}).get("logging")
            properties = component.get("properties", {})

            self.graph.add_node(
                node_id,
                name              = component.get("name", node_id),
                type              = component.get("type"),
                trust_zone        = component.get("trust_zone"),
                internet_facing   = component.get("internet_facing", False),
                technologies      = component.get("technologies", []),
                # Flattened properties
                logging           = properties.get("logging", False),
                encrypted_at_rest = properties.get("encrypted_at_rest"),
                stores_credentials= properties.get("stores_credentials", False),
                stores_pii        = properties.get("stores_pii", False),
                entry_point       = properties.get("entry_point", False),
                rate_limiting     = properties.get("rate_limiting", False),
                handles_auth      = properties.get("handles_authentication", False),
                issues_tokens     = properties.get("issues_tokens", False),
            )

    def _add_edges(self) -> None:
        """
        Add each data flow as a directed edge.
        Stores all flow attributes on the edge for STRIDE engine access.
        """
        for flow in self.arch.get("data_flows", []):
            src = flow["source"]
            dst = flow["destination"]

            self.graph.add_edge(
                src, dst,
                flow_id           = flow.get("id"),
                name              = flow.get("name"),
                protocol          = flow.get("protocol"),
                flow_type         = flow.get("flow_type"),
                crosses_boundary  = flow.get("crosses_boundary", False),
                encrypted_in_transit = flow.get("encrypted_in_transit", False),
                authenticated     = flow.get("authenticated", False),
                assets            = flow.get("assets", []),
            )


    def summary(self) -> None:
        """
        Print a structured summary of the built graph.
        Shows nodes, edges and key security-relevant attributes.
        """
        project = self.arch.get("project", {})

        W    = 72
        SEP  = "*" * W
        THIN = "-" * W

        def section(title):
            print(THIN)
            print(f"  {title}")
            print(THIN)

        print("\n" + SEP)
        print(f"  ArchGuard  |  Graph Summary  |  Backend: {self.backend.upper()}")
        print(SEP)
        print(f"  Architecture : {project.get('name', 'N/A')}")
        print(f"  Nodes        : {self.graph.node_count()}")
        print(f"  Edges        : {self.graph.edge_count()}")
        print(SEP)

        section(f"NODES ({self.graph.node_count()})")
        print(f"  {'ID':<25} {'TYPE':<22} {'TRUST ZONE':<18} {'EXPOSURE':<10} {'LOGGING'}")
        print(f"  {'-'*24} {'-'*21} {'-'*17} {'-'*9} {'-'*7}")
        for node in self.graph.get_nodes():
            exposure = "INTERNET" if node.get("internet_facing") else "INTERNAL"
            logging  = "YES" if node.get("logging") else "NO"
            print(f"  {node['id']:<25} {node.get('type','?'):<22} {node.get('trust_zone','?'):<18} {exposure:<10} {logging}")

        section(f"EDGES ({self.graph.edge_count()})")
        print(f"  {'ID':<6} {'FLOW':<50} {'BOUNDARY':<10} {'ENCRYPTED':<11} {'AUTH'}")
        print(f"  {'-'*5} {'-'*49} {'-'*9} {'-'*10} {'-'*6}")
        for edge in self.graph.get_edges():
            flow      = f"{edge['src']} --> {edge['dst']}"
            boundary  = "YES" if edge.get("crosses_boundary") else "NO"
            encrypted = "YES" if edge.get("encrypted_in_transit") else "NO"
            auth      = "YES" if edge.get("authenticated") else "NO"
            print(f"  {edge.get('flow_id','?'):<6} {flow:<50} {boundary:<10} {encrypted:<11} {auth}")

        internet_nodes = self.graph.get_internet_facing_nodes()
        section(f"INTERNET FACING NODES ({len(internet_nodes)})  — Initial Access candidates")
        for node_id in internet_nodes:
            attrs = self.graph.get_node_attributes(node_id)
            print(f"  - {node_id:<25} type: {attrs.get('type','?')}")

        boundary_edges = [e for e in self.graph.get_edges() if e.get("crosses_boundary")]
        section(f"BOUNDARY CROSSING FLOWS ({len(boundary_edges)})  — High risk flows")
        for edge in boundary_edges:
            encrypted = "ENCRYPTED" if edge.get("encrypted_in_transit") else "UNENCRYPTED"
            auth      = "AUTH" if edge.get("authenticated") else "UNAUTH"
            print(f"  - {edge['src']:<25} --> {edge['dst']:<25} [{encrypted}] [{auth}]")

        print("\n" + SEP + "\n")




def build_graph(arch: dict, backend: str = "networkx") -> GraphInterface:
    """
    Build and return a graph from a validated architecture dict.
    Convenience wrapper around GraphBuilder.
    """
    builder = GraphBuilder(arch, backend=backend)
    return builder.build()



if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from parser import parse_architecture

    if len(sys.argv) < 2:
        print("Usage: python graph/builder.py <architecture_file.yaml> [backend]")
        print("       backend: networkx (default) or igraph")
        sys.exit(1)

    file_path = sys.argv[1]
    backend   = sys.argv[2] if len(sys.argv) > 2 else "networkx"

    arch    = parse_architecture(file_path)
    builder = GraphBuilder(arch, backend=backend)
    graph   = builder.build()
    builder.summary()