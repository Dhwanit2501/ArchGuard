"""
ArchGuard - NetworkX Backend
----------------------------
Implements GraphInterface using the NetworkX library.
Uses a directed graph (DiGraph) since data flows have direction.
"""

import networkx as nx
from graph.base import GraphInterface


class NetworkXGraph(GraphInterface):
    """
    NetworkX implementation of GraphInterface.
    Internally uses nx.DiGraph where:
      - Nodes = components
      - Edges = data flows (directed)
    """

    def __init__(self):
        # DiGraph = Directed Graph, edges have a direction (src -> dst)
        # This matters because data flows are one-directional
        self._graph = nx.DiGraph()


    def add_node(self, node_id: str, **attributes) -> None:
        """Add a component as a node with all its attributes."""
        self._graph.add_node(node_id, **attributes)

    def add_edge(self, src: str, dst: str, **attributes) -> None:
        """Add a data flow as a directed edge with all its attributes."""
        self._graph.add_edge(src, dst, **attributes)


    def get_nodes(self) -> list[dict]:
        """Return all nodes as a list of dicts with id and attributes."""
        return [
            {"id": node_id, **attrs}
            for node_id, attrs in self._graph.nodes(data=True)
        ]

    def get_edges(self) -> list[dict]:
        """Return all edges as a list of dicts with src, dst and attributes."""
        return [
            {"src": src, "dst": dst, **attrs}
            for src, dst, attrs in self._graph.edges(data=True)
        ]

    def get_neighbors(self, node_id: str) -> list[str]:
        """Return list of node IDs that node_id has outgoing edges to."""
        return list(self._graph.successors(node_id))

    def get_node_attributes(self, node_id: str) -> dict:
        """Return all attributes of a specific node."""
        return dict(self._graph.nodes[node_id])

    def get_edge_attributes(self, src: str, dst: str) -> dict:
        """Return all attributes of a specific edge."""
        return dict(self._graph.edges[src, dst])


    def crosses_boundary(self, src: str, dst: str) -> bool:
        """
        Returns True if the edge from src to dst crosses a trust zone boundary.
        Checks if src and dst belong to different trust zones.
        """
        # First check if the edge attribute is explicitly set
        edge_attrs = self.get_edge_attributes(src, dst)
        if "crosses_boundary" in edge_attrs:
            return edge_attrs["crosses_boundary"]

        # Fallback: infer from trust zones of src and dst nodes
        src_zone = self._graph.nodes[src].get("trust_zone")
        dst_zone = self._graph.nodes[dst].get("trust_zone")
        return src_zone != dst_zone

    def get_nodes_by_type(self, component_type: str) -> list[str]:
        """Return all node IDs of a given component type."""
        return [
            node_id
            for node_id, attrs in self._graph.nodes(data=True)
            if attrs.get("type") == component_type
        ]

    def get_nodes_by_trust_zone(self, trust_zone: str) -> list[str]:
        """Return all node IDs that belong to a given trust zone."""
        return [
            node_id
            for node_id, attrs in self._graph.nodes(data=True)
            if attrs.get("trust_zone") == trust_zone
        ]

    def get_internet_facing_nodes(self) -> list[str]:
        """Return all node IDs that are internet facing."""
        return [
            node_id
            for node_id, attrs in self._graph.nodes(data=True)
            if attrs.get("internet_facing") is True
        ]


    def node_count(self) -> int:
        """Return total number of nodes."""
        return self._graph.number_of_nodes()

    def edge_count(self) -> int:
        """Return total number of edges."""
        return self._graph.number_of_edges()