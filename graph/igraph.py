"""
ArchGuard - igraph Backend
--------------------------
Implements GraphInterface using the igraph library.
igraph is faster than NetworkX for large graphs but has a different
internal representation - nodes are integers, not strings.
So we maintain an id_to_index mapping to bridge the gap.
"""

import igraph as ig
from graph.base import GraphInterface


class IGraphGraph(GraphInterface):
    """
    igraph implementation of GraphInterface.

    Key difference from NetworkX:
    - igraph nodes are identified by integer index internally
    - We maintain id_to_index and index_to_id dicts to map
      string component IDs <-> igraph integer indices
    """

    def __init__(self):
        self._graph = ig.Graph(directed=True)

        # These two dicts are the bridge between string IDs and igraph indices
        self._id_to_index: dict[str, int] = {}  # "api-gateway" -> 2
        self._index_to_id: dict[int, str] = {}  # 2 -> "api-gateway"

    @staticmethod
    def _vget(vertex, key, default=None):
        """
        Safe attribute access for igraph Vertex objects.
        igraph Vertex does not support .get() like a dict.
        Accessing a missing attribute raises KeyError, so we catch it.
        """
        try:
            return vertex[key]
        except KeyError:
            return default



    def add_node(self, node_id: str, **attributes) -> None:
        """
        Add a component as a node.
        igraph assigns an integer index - we store the mapping.
        """
        # Add vertex to igraph
        self._graph.add_vertex(name=node_id)

        # Get the index igraph assigned to this vertex
        index = self._graph.vs.find(name=node_id).index

        # Store the mapping
        self._id_to_index[node_id] = index
        self._index_to_id[index] = node_id

        # Store all attributes on the vertex
        vertex = self._graph.vs[index]
        for key, value in attributes.items():
            vertex[key] = value

    def add_edge(self, src: str, dst: str, **attributes) -> None:
        """
        Add a data flow as a directed edge.
        Looks up integer indices for src and dst before adding.
        """
        src_idx = self._id_to_index[src]
        dst_idx = self._id_to_index[dst]

        self._graph.add_edge(src_idx, dst_idx)

        # Get the edge that was just added and set its attributes
        edge = self._graph.es[self._graph.get_eid(src_idx, dst_idx)]
        edge["src"] = src
        edge["dst"] = dst
        for key, value in attributes.items():
            edge[key] = value



    def get_nodes(self) -> list[dict]:
        """Return all nodes as a list of dicts with id and attributes."""
        result = []
        for vertex in self._graph.vs:
            node = {"id": self._index_to_id[vertex.index]}
            for attr in self._graph.vertex_attributes():
                if attr != "name":
                    node[attr] = vertex[attr]
            result.append(node)
        return result

    def get_edges(self) -> list[dict]:
        """Return all edges as a list of dicts with src, dst and attributes."""
        result = []
        for edge in self._graph.es:
            e = {
                "src": edge["src"],
                "dst": edge["dst"],
            }
            for attr in self._graph.edge_attributes():
                if attr not in ("src", "dst"):
                    e[attr] = edge[attr]
            result.append(e)
        return result

    def get_neighbors(self, node_id: str) -> list[str]:
        """Return list of node IDs that node_id has outgoing edges to."""
        index = self._id_to_index[node_id]
        neighbor_indices = self._graph.successors(index)
        return [self._index_to_id[i] for i in neighbor_indices]

    def get_node_attributes(self, node_id: str) -> dict:
        """Return all attributes of a specific node."""
        index = self._id_to_index[node_id]
        vertex = self._graph.vs[index]
        return {
            attr: vertex[attr]
            for attr in self._graph.vertex_attributes()
            if attr != "name"
        }

    def get_edge_attributes(self, src: str, dst: str) -> dict:
        """Return all attributes of a specific edge."""
        src_idx = self._id_to_index[src]
        dst_idx = self._id_to_index[dst]
        eid = self._graph.get_eid(src_idx, dst_idx)
        edge = self._graph.es[eid]
        return {
            attr: edge[attr]
            for attr in self._graph.edge_attributes()
            if attr not in ("src", "dst")
        }



    def crosses_boundary(self, src: str, dst: str) -> bool:
        """Returns True if the edge crosses a trust zone boundary."""
        edge_attrs = self.get_edge_attributes(src, dst)
        if "crosses_boundary" in edge_attrs:
            return edge_attrs["crosses_boundary"]

        src_zone = self.get_node_attributes(src).get("trust_zone")
        dst_zone = self.get_node_attributes(dst).get("trust_zone")
        return src_zone != dst_zone

    def get_nodes_by_type(self, component_type: str) -> list[str]:
        """Return all node IDs of a given component type."""
        return [
            self._index_to_id[v.index]
            for v in self._graph.vs
            if self._vget(v, "type") == component_type
        ]

    def get_nodes_by_trust_zone(self, trust_zone: str) -> list[str]:
        """Return all node IDs belonging to a given trust zone."""
        return [
            self._index_to_id[v.index]
            for v in self._graph.vs
            if self._vget(v, "trust_zone") == trust_zone
        ]

    def get_internet_facing_nodes(self) -> list[str]:
        """Return all node IDs that are internet facing."""
        return [
            self._index_to_id[v.index]
            for v in self._graph.vs
            if self._vget(v, "internet_facing") is True
        ]


    def node_count(self) -> int:
        """Return total number of nodes."""
        return self._graph.vcount()

    def edge_count(self) -> int:
        """Return total number of edges."""
        return self._graph.ecount()