"""
ArchGuard - Graph Visualizer
----------------------------
Generates an interactive HTML visualization of the architecture graph
using pyvis. Open the output HTML file in any browser to explore.

Color coding:
  Nodes by trust zone level:
    - untrusted  : red
    - low        : orange
    - medium     : yellow
    - high       : lightgreen
    - trusted    : green

  Node border by exposure:
    - INTERNET   : thick red border
    - INTERNAL   : thin grey border

  Edges by risk:
    - crosses boundary + unencrypted + unauthenticated : red
    - crosses boundary                                 : orange
    - unencrypted                                      : yellow
    - authenticated + encrypted                        : green
"""

from pyvis.network import Network
from graph.base import GraphInterface


# Node background color by trust level
TRUST_COLORS = {
    "untrusted" : "#e74c3c",   # red
    "low"       : "#e67e22",   # orange
    "medium"    : "#f1c40f",   # yellow
    "high"      : "#2ecc71",   # green
    "trusted"   : "#27ae60",   # dark green
}

# Node shape by component type
TYPE_SHAPES = {
    "web-application"   : "square",
    "mobile-application": "square",
    "api-gateway"       : "diamond",
    "microservice"      : "dot",
    "database"          : "database",
    "queue"             : "box",
    "storage"           : "box",
    "load-balancer"     : "diamond",
    "function"          : "dot",
    "external-service"  : "triangle",
    "compute"           : "dot",
    "network-gateway"   : "diamond",
    "iam-identity"      : "star",
    "serverless"        : "dot",
    "object-storage"    : "box",
    "cdn"               : "diamond",
    "llm"               : "star",
    "tool-executor"     : "dot",
    "actor"             : "square",
    "input"             : "triangle",
    "output"            : "triangle",
    "external-system"   : "triangle",
    "agent"             : "star",
    "vector-store"      : "database",
    "memory-store"      : "database",
}

DEFAULT_SHAPE = "dot"
DEFAULT_COLOR = "#95a5a6"  # grey for unknown trust levels


def _node_color(trust_level: str) -> str:
    return TRUST_COLORS.get(trust_level, DEFAULT_COLOR)


def _node_shape(component_type: str) -> str:
    return TYPE_SHAPES.get(component_type, DEFAULT_SHAPE)


def _edge_color(edge: dict) -> str:
    """Determine edge color based on security properties."""
    boundary  = edge.get("crosses_boundary", False)
    encrypted = edge.get("encrypted_in_transit", False)
    auth      = edge.get("authenticated", False)

    if boundary and not encrypted and not auth:
        return "#e74c3c"   # red   - highest risk
    elif boundary and not encrypted:
        return "#e67e22"   # orange - boundary + unencrypted
    elif boundary and not auth:
        return "#f39c12"   # amber  - boundary + unauthenticated
    elif boundary:
        return "#f1c40f"   # yellow - boundary crossing but secured
    elif not encrypted:
        return "#bdc3c7"   # light grey - internal unencrypted
    else:
        return "#2ecc71"   # green  - internal encrypted


def _edge_width(edge: dict) -> int:
    """Thicker edges for higher risk flows."""
    if edge.get("crosses_boundary"):
        return 3
    return 1


def _node_tooltip(node: dict, trust_level: str = "unknown") -> str:
    """Build the hover tooltip for a node."""
    lines = [
        f"ID           : {node['id']}",
        f"Type         : {node.get('type', 'N/A')}",
        f"Trust Zone   : {node.get('trust_zone', 'N/A')}",
        f"Trust Level  : {trust_level.upper()}",
        f"Exposure     : {'INTERNET' if node.get('internet_facing') else 'INTERNAL'}",
        f"Logging      : {'YES' if node.get('logging') else 'NO'}",
    ]
    if node.get("stores_credentials"):
        lines.append("⚠️  Stores Credentials")
    if node.get("stores_pii"):
        lines.append("⚠️  Stores PII")
    if node.get("encrypted_at_rest") is False:
        lines.append("⚠️  NOT Encrypted at Rest")
    return "\n".join(lines)


def _edge_tooltip(edge: dict) -> str:
    """Build the hover tooltip for an edge."""
    lines = [
        f"Flow     : {edge['src']} --> {edge['dst']}",
        f"ID       : {edge.get('flow_id', 'N/A')}",
        f"Protocol : {edge.get('protocol', 'N/A')}",
        f"Boundary : {'YES' if edge.get('crosses_boundary') else 'NO'}",
        f"Encrypted: {'YES' if edge.get('encrypted_in_transit') else 'NO'}",
        f"Auth     : {'YES' if edge.get('authenticated') else 'NO'}",
    ]
    if edge.get("assets"):
        lines.append(f"Assets   : {', '.join(edge['assets'])}")
    return "\n".join(lines)


def visualize(
    graph      : GraphInterface,
    arch       : dict,
    output_path: str = "archguard_graph.html",
) -> str:
    """
    Generate an interactive HTML visualization of the architecture graph.

    Parameters:
        graph       : built GraphInterface object
        arch        : original parsed architecture dict (for metadata)
        output_path : where to save the HTML file

    Returns:
        output_path : path to the saved HTML file
    """
    project = arch.get("project", {})
    title   = f"ArchGuard | {project.get('name', 'Architecture')} | Interactive Graph"

    # Create pyvis network
    net = Network(
        height         = "800px",
        width          = "100%",
        directed       = True,
        notebook       = False,
        heading        = title,
        bgcolor        = "#1a1a2e",   # dark background
        font_color     = "#ffffff",
    )

    # Physics settings for better layout
    net.set_options("""
    {
        "physics": {
            "enabled": true,
            "barnesHut": {
                "gravitationalConstant": -8000,
                "centralGravity": 0.3,
                "springLength": 150,
                "springConstant": 0.04,
                "damping": 0.09
            }
        },
        "edges": {
            "arrows": { "to": { "enabled": true, "scaleFactor": 1 } },
            "smooth": { "type": "dynamic" },
            "font": {
                "size": 12,
                "color": "#ffffff",
                "align": "horizontal"
            }
        },
        "nodes": {
            "font": {
                "strokeWidth": 0
            }
        },
        "interaction": {
            "hover": true,
            "tooltipDelay": 100
        }
    }
    """)

    for node in graph.get_nodes():
        trust_level  = node.get("trust_level") or _get_trust_level(node, arch)
        color        = _node_color(trust_level)
        shape        = _node_shape(node.get("type", ""))
        border_width = 4 if node.get("internet_facing") else 1
        border_color = "#e74c3c" if node.get("internet_facing") else "#7f8c8d"

        net.add_node(
            node["id"],
            label        = node["id"],
            title        = _node_tooltip(node, trust_level),
            color        = {
                "background": color,
                "border"    : border_color,
                "highlight" : {"background": color, "border": "#ffffff"},
            },
            shape        = shape,
            borderWidth  = border_width,
            font         = {"size": 12, "color": "#ffffff", "strokeWidth": 0},
            size         = 20,
        )

    for edge in graph.get_edges():
        net.add_edge(
            edge["src"],
            edge["dst"],
            title  = _edge_tooltip(edge),
            color  = _edge_color(edge),
            width  = _edge_width(edge),
            label  = edge.get("protocol", ""),
            font   = {"size": 12, "color": "#ffffff", "align": "horizontal", "strokeWidth": 0},
        )

    _add_legend(net)

    # Save
    net.save_graph(output_path)
    return output_path


def _get_trust_level(node: dict, arch: dict) -> str:
    """Look up the trust level of a node's zone from the arch dict."""
    zone_id = node.get("trust_zone")
    for tz in arch.get("trust_zones", []):
        if tz["id"] == zone_id:
            return tz["trust_level"]
    return "unknown"


def _add_legend(net: Network) -> None:
    """Add a static legend to the top-left of the graph."""
    legend_items = [
        ("untrusted zone",  "#e74c3c"),
        ("low zone",        "#e67e22"),
        ("medium zone",     "#f1c40f"),
        ("high zone",       "#2ecc71"),
        ("trusted zone",    "#27ae60"),
    ]
    # Place legend nodes in a column at fixed positions
    x, y = -800, -350
    for label, color in legend_items:
        net.add_node(
            f"__legend_{label}",
            label   = label,
            x       = x,
            y       = y,
            color   = {"background": color, "border": "#ffffff"},
            shape   = "dot",
            size    = 12,
            font    = {"size": 11, "color": "#ffffff"},
            physics = False,   # pin legend in place
        )
        y += 50



if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from parser import parse_architecture
    from graph.builder import GraphBuilder

    if len(sys.argv) < 2:
        print("Usage: python graph/visualizer.py <architecture_file.yaml> [backend] [output.html]")
        sys.exit(1)

    file_path   = sys.argv[1]
    backend     = sys.argv[2] if len(sys.argv) > 2 else "networkx"
    output_path = sys.argv[3] if len(sys.argv) > 3 else "archguard_graph.html"

    arch    = parse_architecture(file_path)
    builder = GraphBuilder(arch, backend=backend)
    graph   = builder.build()

    out = visualize(graph, arch, output_path)
    print(f"✅ Graph saved to: {out}")
    print(f"   Open in browser to explore interactively.")


