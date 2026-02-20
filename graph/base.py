"""
ArchGuard - Graph Interface (Abstract Base Class)
-------------------------------------------------
Defines the contract that all graph backends must implement.
The STRIDE engine and attack path modeler only talk to this interface,
never directly to NetworkX or igraph.
"""

from abc import ABC, abstractmethod


class GraphInterface(ABC):
    """
    Abstract base class for all ArchGuard graph backends.

    Every method here is a contract — any backend (NetworkX, igraph)
    must implement all of these, otherwise Python will raise a TypeError
    when you try to instantiate it.
    """

    @abstractmethod
    def add_node(self, node_id: str, **attributes) -> None:
        """
        Add a component as a node in the graph.
        node_id   : unique component id (e.g. 'api-gateway')
        attributes: any component properties (type, trust_zone, internet_facing etc.)
        """
        pass

    @abstractmethod
    def add_edge(self, src: str, dst: str, **attributes) -> None:
        """
        Add a data flow as a directed edge in the graph.
        src       : source component id
        dst       : destination component id
        attributes: any flow properties (protocol, encrypted_in_transit, authenticated etc.)
        """
        pass


    @abstractmethod
    def get_nodes(self) -> list[dict]:
        """
        Return all nodes as a list of dicts.
        Each dict contains the node id and its attributes.
        e.g. [{"id": "api-gateway", "type": "api-gateway", "trust_zone": "microservices"}, ...]
        """
        pass

    @abstractmethod
    def get_edges(self) -> list[dict]:
        """
        Return all edges as a list of dicts.
        Each dict contains src, dst and edge attributes.
        e.g. [{"src": "web-browser", "dst": "api-gateway", "encrypted_in_transit": True}, ...]
        """
        pass

    @abstractmethod
    def get_neighbors(self, node_id: str) -> list[str]:
        """
        Return list of node IDs that node_id has outgoing edges to.
        Used by the attack path modeler to find reachable components.
        e.g. get_neighbors("api-gateway") -> ["auth-service", "order-service", "inventory-service"]
        """
        pass

    @abstractmethod
    def get_node_attributes(self, node_id: str) -> dict:
        """
        Return all attributes of a specific node.
        e.g. get_node_attributes("api-gateway") -> {"type": "api-gateway", "internet_facing": True, ...}
        """
        pass

    @abstractmethod
    def get_edge_attributes(self, src: str, dst: str) -> dict:
        """
        Return all attributes of a specific edge.
        e.g. get_edge_attributes("web-browser", "api-gateway") -> {"encrypted_in_transit": True, ...}
        """
        pass


    @abstractmethod
    def crosses_boundary(self, src: str, dst: str) -> bool:
        """
        Returns True if the edge from src to dst crosses a trust zone boundary.
        Drives Spoofing and Tampering threat detection in the STRIDE engine.
        """
        pass

    @abstractmethod
    def get_nodes_by_type(self, component_type: str) -> list[str]:
        """
        Return all node IDs of a given component type.
        e.g. get_nodes_by_type("database") -> ["user-db", "order-db", "inventory-db"]
        Used by STRIDE engine to apply type-specific rules.
        """
        pass

    @abstractmethod
    def get_nodes_by_trust_zone(self, trust_zone: str) -> list[str]:
        """
        Return all node IDs that belong to a given trust zone.
        e.g. get_nodes_by_trust_zone("data-layer") -> ["user-db", "order-db", "inventory-db"]
        """
        pass

    @abstractmethod
    def get_internet_facing_nodes(self) -> list[str]:
        """
        Return all node IDs that are internet facing.
        These are the Initial Access candidates in ATT&CK mapping.
        """
        pass


    @abstractmethod
    def node_count(self) -> int:
        """Return total number of nodes in the graph."""
        pass

    @abstractmethod
    def edge_count(self) -> int:
        """Return total number of edges in the graph."""
        pass