"""
NS-BOS Kernel - Generative UI Engine
Adaptive interface generation, user behavior learning,
cross-platform consistency, and accessibility-first design.
"""

import contextlib
import copy
import errno
import html
import json
import logging
import os
import re
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class UIComponent:
    """A single UI component that can be generated"""

    component_type: str  # card, table, chart, form, button, text, etc.
    id: str
    label: str
    data_source: str
    properties: dict = field(default_factory=dict)
    visibility: str = "always"  # always, conditional, role-based
    order: int = 0


@dataclass
class UILayout:
    """A complete UI layout for a specific context"""

    layout_id: str
    context: str  # dashboard, agent-monitor, settings, etc.
    platform: str  # web, desktop, mobile
    components: list[UIComponent] = field(default_factory=list)
    theme: str = "kemet"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class UserBehavior:
    """Tracks user interaction patterns for adaptive UI"""

    user_id: str
    most_used_components: dict[str, int] = field(default_factory=dict)
    least_used_components: dict[str, int] = field(default_factory=dict)
    preferred_layout: str = "default"
    session_count: int = 0
    last_active: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    interaction_patterns: dict[str, Any] = field(default_factory=dict)


def _write_json(path: Path, data, **dump_kwargs) -> None:
    """Write data as JSON, complete or not at all, and durably: a synced
    temporary file renamed over the old one, then the directory synced, so
    a crash or power loss leaves the old file or the new one, never an empty
    one. Each call has its own temporary name, so threads do not collide."""
    _write_durably(path, json.dumps(data, indent=2, **dump_kwargs).encode())


def _write_durably(path: Path, data: bytes) -> None:
    # Cut to 96 bytes, so the temporary file fits whenever path does.
    head = path.name.encode()[:96].decode("utf-8", "ignore")
    tmp = path.with_name(f".{head}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # owner only
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


# errno values for a filesystem that has no hard links (vfat, some FUSE mounts).
_NO_LINKS = frozenset({errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS})


def _keep_aside(path: Path, kind: str) -> Path:
    """Move path to <name>.<kind>-<UTC time>, never over an existing file: a
    second file kept aside in the same second gets -1, -2 and so on, so no
    earlier copy is lost. A hard link takes the new name or fails, so no
    other process can race it; where the filesystem has no hard links, the
    name is checked first."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for n in range(1000):
        aside = path.with_name(f"{path.name}.{kind}-{stamp}" + (f"-{n}" if n else ""))
        try:
            os.link(path, aside)
        except FileExistsError:
            continue
        except OSError as exc:
            if exc.errno not in _NO_LINKS:
                raise
            if os.path.lexists(aside):
                continue
            os.replace(path, aside)
            return aside
        os.unlink(path)
        return aside
    raise FileExistsError(f"no free name to keep {path.name} aside")


def _set_aside(path: Path, exc: Exception, what: str) -> None:
    """Rename an unreadable file to <name>.corrupt-<UTC time>, never delete
    it, and carry on without it."""
    aside = _keep_aside(path, "corrupt")
    logger.error(
        "%s unreadable (%s); kept as %s, skipped", what, type(exc).__name__, aside.name
    )


def _file_name(value: str, what: str) -> str:
    """value as a file name inside its directory, or ValueError."""
    if not isinstance(value, str) or not value or "/" in value or "\0" in value:
        raise ValueError(f"invalid {what} {str(value)[:64]!r}: empty, '/' or NUL")
    if len(f"{value}.json".encode()) > 255:
        raise ValueError(f"{what} {value[:64]!r} is too long for a file name")
    return f"{value}.json"


# Declared field types, checked for anything read from disk or imported: a
# wrong type is accepted by the dataclass and only fails later, in rendering,
# adaptation or the next interaction, every time.
_COMPONENT_FIELDS = {"component_type": str, "id": str, "label": str,
                     "data_source": str, "properties": dict, "visibility": str,
                     "order": int}  # fmt: skip
_LAYOUT_FIELDS = {"layout_id": str, "context": str, "platform": str, "theme": str,
                  "created_at": str, "updated_at": str}  # fmt: skip
_BEHAVIOR_FIELDS = {"user_id": str, "most_used_components": dict, "session_count": int}


def _check_types(obj, fields: dict) -> None:
    """TypeError naming the first field of obj that is not of its type."""
    for name, kind in fields.items():
        value = getattr(obj, name)
        if not isinstance(value, kind):
            raise TypeError(f"{name} is {type(value).__name__}, not {kind.__name__}")


# A component type becomes a class name in the HTML: one word, so it cannot
# add class names of its own.
_COMPONENT_TYPE = re.compile(r"[a-z][a-z0-9-]*")


def _layout_from(data: dict) -> UILayout:
    """A layout from its stored or exported form. Raises ValueError,
    TypeError, KeyError or AttributeError for anything else."""
    now = datetime.now(timezone.utc).isoformat()
    layout = UILayout(
        layout_id=data["layout_id"],
        context=data["context"],
        platform=data["platform"],
        components=[UIComponent(**c) for c in data.get("components", [])],
        theme=data.get("theme", "kemet"),
        created_at=data.get("created_at", now),
        updated_at=data.get("updated_at", now),
    )
    _check_types(layout, _LAYOUT_FIELDS)
    for component in layout.components:
        _check_types(component, _COMPONENT_FIELDS)
    return layout


def _check_component_types(layout: UILayout) -> None:
    """Refuse an imported layout whose component types would not render.
    Not applied on load: stored layouts may hold types such as "line_chart",
    which render as "unknown" and must not be set aside."""
    for component in layout.components:
        if not _COMPONENT_TYPE.fullmatch(component.component_type):
            raise ValueError(
                f"component type {component.component_type[:64]!r} is not a lowercase "
                "letter then lowercase letters, digits or '-'"
            )


def _behavior_from(data: dict) -> UserBehavior:
    """A user's behavior record from its stored form, or TypeError."""
    behavior = UserBehavior(**data)
    _check_types(behavior, _BEHAVIOR_FIELDS)
    if not all(isinstance(n, int) for n in behavior.most_used_components.values()):
        raise TypeError("most_used_components holds a count that is not an integer")
    return behavior


class GenerativeUIEngine:
    """
    Generates adaptive UI layouts based on user behavior,
    context, and platform.
    """

    def __init__(self, ui_dir: str | None = None):
        base = ui_dir or (
            os.environ.get("NGARI_DATA_DIR") or str(Path.home() / ".ngari" / "kernel")
        )
        self.ui_dir = Path(base) / "ui"
        self.ui_dir.mkdir(parents=True, exist_ok=True)

        self.layouts_dir = self.ui_dir / "layouts"
        self.layouts_dir.mkdir(exist_ok=True)

        self.behavior_dir = self.ui_dir / "behavior"
        self.behavior_dir.mkdir(exist_ok=True)

        self.layouts: dict[str, UILayout] = {}
        self.user_behaviors: dict[str, UserBehavior] = {}

        self._load_layouts()
        self._load_behaviors()

    def _load_layouts(self):
        """Load UI layouts from disk. An unreadable layout file is set aside
        and the others still load."""
        for layout_file in self.layouts_dir.glob("*.json"):
            try:
                layout = _layout_from(json.loads(layout_file.read_text()))
                # Kept only if it can be saved and exported again: asdict
                # gives up long before the decoder does.
                json.dumps(asdict(layout))
            except (
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                RecursionError,
            ) as exc:
                _set_aside(layout_file, exc, "UI layout")
                continue
            self.layouts[layout.layout_id] = layout

    def _save_layout(self, layout: UILayout):
        """Save a UI layout to disk"""
        layout.updated_at = datetime.now(timezone.utc).isoformat()
        layout_file = self.layouts_dir / _file_name(layout.layout_id, "layout id")
        _write_json(layout_file, asdict(layout))

    def _load_behaviors(self):
        """Load user behavior data. An unreadable file is set aside and the
        others still load."""
        for behavior_file in self.behavior_dir.glob("*.json"):
            try:
                behavior = _behavior_from(json.loads(behavior_file.read_text()))
                json.dumps(asdict(behavior))  # can be saved again
            except (ValueError, TypeError, AttributeError, RecursionError) as exc:
                _set_aside(behavior_file, exc, "UI behavior")
                continue
            self.user_behaviors[behavior.user_id] = behavior

    def _save_behavior(self, behavior: UserBehavior):
        """Save user behavior data"""
        behavior.last_active = datetime.now(timezone.utc).isoformat()
        behavior_file = self.behavior_dir / _file_name(behavior.user_id, "user id")
        _write_json(behavior_file, asdict(behavior))

    def get_or_create_behavior(self, user_id: str) -> UserBehavior:
        """Get or create user behavior tracking"""
        if user_id not in self.user_behaviors:
            _file_name(user_id, "user id")
            behavior = UserBehavior(user_id=user_id)
            self._save_behavior(behavior)  # kept only once saved
            self.user_behaviors[user_id] = behavior
        return self.user_behaviors[user_id]

    def track_interaction(self, user_id: str, component_id: str):
        """Track user interaction with a component"""
        behavior = self.get_or_create_behavior(user_id)
        behavior.most_used_components[component_id] = (
            behavior.most_used_components.get(component_id, 0) + 1
        )
        behavior.session_count += 1
        self._save_behavior(behavior)

    def generate_layout(
        self, context: str, platform: str, user_id: str | None = None
    ) -> UILayout:
        """Generate an adaptive UI layout"""
        if not isinstance(platform, str) or "_" in platform:
            # The id joins the two with "_": with none in the platform, two
            # pairs cannot share one id, as ("a_b", "c") and ("a", "b_c") would.
            raise ValueError(f"platform {str(platform)[:64]!r} may not contain '_'")
        layout_id = f"{context}_{platform}"
        _file_name(layout_id, "layout id")

        if layout_id in self.layouts:
            layout = self.layouts[layout_id]
        else:
            layout = self._generate_default_layout(context, platform)
            self._save_layout(layout)  # kept only once saved
            self.layouts[layout_id] = layout

        if user_id and user_id in self.user_behaviors:
            layout = self._adapt_layout(layout, self.user_behaviors[user_id])

        return layout

    def _generate_default_layout(self, context: str, platform: str) -> UILayout:
        """Generate a default layout for a context"""
        components = []

        if context == "dashboard":
            components = [
                UIComponent(
                    "card",
                    "revenue-card",
                    "Revenue",
                    "revenue_data",
                    {"metric": "daily_revenue", "format": "currency"},
                    order=0,
                ),
                UIComponent(
                    "card",
                    "agents-card",
                    "Active Agents",
                    "agent_status",
                    {"metric": "active_count"},
                    order=1,
                ),
                UIComponent(
                    "table",
                    "orders-table",
                    "Recent Orders",
                    "orders",
                    {"columns": ["id", "product", "amount", "status"], "limit": 10},
                    order=2,
                ),
                UIComponent(
                    "chart",
                    "revenue-chart",
                    "Revenue Trend",
                    "revenue_history",
                    {"type": "line", "period": "7d"},
                    order=3,
                ),
                UIComponent(
                    "card",
                    "system-card",
                    "System Health",
                    "system_health",
                    {"metrics": ["cpu", "memory", "gpu", "storage"]},
                    order=4,
                ),
            ]
        elif context == "agent-monitor":
            components = [
                UIComponent(
                    "card",
                    "agent-status",
                    "Agent Status",
                    "agent_states",
                    {"show_details": True},
                    order=0,
                ),
                UIComponent(
                    "table",
                    "agent-tasks",
                    "Active Tasks",
                    "agent_tasks",
                    {"columns": ["task_id", "agent", "action", "status"], "limit": 20},
                    order=1,
                ),
                UIComponent(
                    "text",
                    "agent-log",
                    "Agent Log",
                    "agent_log",
                    {"lines": 50, "filter": "error"},
                    order=2,
                ),
            ]
        elif context == "settings":
            components = [
                UIComponent(
                    "form",
                    "general-settings",
                    "General Settings",
                    "settings_general",
                    {"fields": ["theme", "language", "timezone"]},
                    order=0,
                ),
                UIComponent(
                    "form",
                    "agent-settings",
                    "Agent Configuration",
                    "settings_agents",
                    {"fields": ["poll_interval", "max_retries", "log_level"]},
                    order=1,
                ),
                UIComponent(
                    "form",
                    "notification-settings",
                    "Notifications",
                    "settings_notifications",
                    {"fields": ["email", "matrix", "push"]},
                    order=2,
                ),
            ]
        else:
            components = [
                UIComponent(
                    "text",
                    "welcome",
                    "Welcome",
                    "welcome_message",
                    {"content": "NGARi Sovereign Business Operating System"},
                    order=0,
                ),
            ]

        return UILayout(
            layout_id=f"{context}_{platform}",
            context=context,
            platform=platform,
            components=components,
            theme="kemet",
        )

    def _adapt_layout(self, layout: UILayout, behavior: UserBehavior) -> UILayout:
        """A copy of layout ordered by this user's usage. The stored layout is
        shared by every user and is never reordered."""
        layout = copy.deepcopy(layout)
        component_usage = {
            c.id: behavior.most_used_components.get(c.id, 0) for c in layout.components
        }

        # Reorder components by usage (most used first)
        layout.components.sort(key=lambda c: component_usage.get(c.id, 0), reverse=True)

        for i, component in enumerate(layout.components):
            component.order = i

        return layout

    def render_layout(self, layout: UILayout, format: str = "json") -> str:
        """Render a layout in the specified format"""
        if format == "json":
            return json.dumps(asdict(layout), indent=2)
        elif format == "html":
            return self._render_html(layout)
        else:
            return json.dumps(asdict(layout), indent=2)

    def _render_html(self, layout: UILayout) -> str:
        """Render layout as HTML. Every value is escaped: layouts can be
        imported from elsewhere, so labels and ids are untrusted text."""

        def esc(value) -> str:
            return html.escape(str(value), quote=True)

        out = (
            f'<div class="ngari-layout" data-context="{esc(layout.context)}" '
            f'data-platform="{esc(layout.platform)}">\n'
        )
        for component in sorted(layout.components, key=lambda c: c.order):
            # A layout built in code skips the import check: one word or none.
            kind = component.component_type
            kind = kind if _COMPONENT_TYPE.fullmatch(str(kind)) else "unknown"
            out += (
                f'  <div class="ngari-component ngari-{esc(kind)}" '
                f'id="{esc(component.id)}" data-source="{esc(component.data_source)}">\n'
            )
            out += f"    <h3>{esc(component.label)}</h3>\n"
            out += (
                '    <div class="component-content" '
                f'data-properties="{esc(json.dumps(component.properties))}"></div>\n'
            )
            out += "  </div>\n"
        out += "</div>"
        return out

    def get_available_layouts(self) -> list[dict]:
        """Get list of available layouts"""
        return [
            {
                "layout_id": layout.layout_id,
                "context": layout.context,
                "platform": layout.platform,
                "components": len(layout.components),
                "theme": layout.theme,
            }
            for layout in self.layouts.values()
        ]

    def export_layout(self, layout_id: str) -> dict | None:
        """Export a layout for sharing or backup"""
        if layout_id in self.layouts:
            return asdict(self.layouts[layout_id])
        return None

    def import_layout(self, data: dict) -> bool:
        """Import a layout"""
        try:
            layout = _layout_from(data)
            _check_component_types(layout)
            _file_name(layout.layout_id, "layout id")
            self._save_layout(layout)  # kept only once saved
            self.layouts[layout.layout_id] = layout
            return True
        except (ValueError, TypeError, KeyError, AttributeError, OSError) as e:
            logger.error(f"Failed to import layout: {e!r}")
            return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    engine = GenerativeUIEngine()

    dashboard = engine.generate_layout("dashboard", "web", "user-001")
    print(f"Dashboard layout: {len(dashboard.components)} components")

    agent_monitor = engine.generate_layout("agent-monitor", "web")
    print(f"Agent monitor layout: {len(agent_monitor.components)} components")

    engine.track_interaction("user-001", "revenue-card")
    engine.track_interaction("user-001", "revenue-card")
    engine.track_interaction("user-001", "agents-card")

    adapted = engine.generate_layout("dashboard", "web", "user-001")
    print(f"\nAdapted dashboard (first component): {adapted.components[0].label}")

    html = engine.render_layout(dashboard, "html")
    print(f"\nHTML layout generated ({len(html)} bytes)")

    layouts = engine.get_available_layouts()
    print(f"\nAvailable layouts: {len(layouts)}")
    for layout in layouts:
        print(f"  - {layout['layout_id']} ({layout['components']} components)")
