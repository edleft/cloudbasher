"""Which keepalive layers a node runs, and whether it is recovered when it breaks."""

from __future__ import annotations

from typing import Any, Collection, Optional


KEEPALIVE_POLICIES: tuple[str, ...] = ("session", "container", "native", "off")


DEFAULT_POLICY = "session"


_LAYERS: dict[str, frozenset[int]] = {
    "session": frozenset({1, 2, 3, 4}),
    "container": frozenset({1, 3}),
    "native": frozenset({1, 2, 3}),
    "off": frozenset(),
}


_INTERACTION_DRIVEN: dict[str, frozenset[int]] = {
    "session": frozenset(),
    "container": frozenset(),
    "native": frozenset({1}),
    "off": frozenset(),
}


_default_policy: str = DEFAULT_POLICY


def set_default_policy(policy: str) -> None:
    """Set the process default. An unknown value is IGNORED, not raised."""
    global _default_policy
    if policy in _LAYERS:
        _default_policy = policy


def get_default_policy() -> str:
    return _default_policy


def policy_of(node: Any) -> str:
    """This node's policy: its own if set, else the process default."""
    own = getattr(node, "keepalive_policy", "") or ""
    return own if own in _LAYERS else _default_policy


def runs_layer(node: Any, layer: int) -> bool:
    """Does `node`'s policy run keepalive `layer` (1-4)?"""
    return layer in _LAYERS[policy_of(node)]


_LAYER_LOOP: dict[int, str] = {1: "heartbeat", 2: "heartbeat", 3: "bridge", 4: "heartbeat"}


def layer_loop_name(layer: int) -> str:
    """The background-loop name whose thread ticks `layer`."""
    return _LAYER_LOOP[layer]


def layer_is_live(node: Any, layer: int, live: Optional[Collection[str]] = None) -> bool:
    """Is `layer` BOTH armed by policy and actually running on this node?"""
    if not runs_layer(node, layer):
        return False
    names = node.live_background_loops() if live is None else live
    return layer_loop_name(layer) in names


def layer_follows_interaction(node: Any, layer: int) -> bool:
    """Does this node's policy run `layer` on an INTERACTION rule, not a timer?"""
    return layer in _INTERACTION_DRIVEN[policy_of(node)]


def recovers_session(node: Any) -> bool:
    """May the supervisor proactively rebuild this node's dead SESSION?"""
    return policy_of(node) == "session"


def recovers_container(node: Any) -> bool:
    """May the supervisor proactively repair this node's FAILED container?"""
    return policy_of(node) in ("session", "container")
