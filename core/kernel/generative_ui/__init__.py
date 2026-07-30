"""
NS BOS Kernel - Generative UI Engine
Adaptive interface generation, user behavior learning,
cross-platform consistency, and accessibility-first design.
"""

import os
import json
import time
import logging
from datetime import datetime
from typing import Optional, Any, Dict, List
from dataclasses import dataclass, asdict, field
from pathlib import Path

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
    components: List[UIComponent] = field(default_factory=list)
    theme: str = "kemet"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class UserBehavior:
    """Tracks user interaction patterns for adaptive UI"""
    user_id: str
    most_used_components: Dict[str, int] = field(default_factory=dict)
    least_used_components: Dict[str, int] = field(default_factory=dict)
    preferred_layout: str = "default"
    session_count: int = 0
    last_active: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    interaction_patterns: Dict[str, Any] = field(default_factory=dict)


class GenerativeUIEngine:
    """
    Generates adaptive UI layouts based on user behavior,
    context, and platform.
    """

    def __init__(self, ui_dir: str = None):
        base = ui_dir or os.environ.get("NGARI_DATA_DIR", str(Path.home() / ".ngari" / "kernel"))
        self.ui_dir = Path(base) / "ui"
        self.ui_dir.mkdir(parents=True, exist_ok=True)

        self.layouts_dir = self.ui_dir / "layouts"
        self.layouts_dir.mkdir(exist_ok=True)

        self.behavior_dir = self.ui_dir / "behavior"
        self.behavior_dir.mkdir(exist_ok=True)

        self.layouts: Dict[str, UILayout] = {}
        self.user_behaviors: Dict[str, UserBehavior] = {}

        self._load_layouts()
        self._load_behaviors()

    def _load_layouts(self):
        """Load UI layouts from disk"""
        for layout_file in self.layouts_dir.glob("*.json"):
            with open(layout_file, "r") as f:
                data = json.load(f)
                components = [UIComponent(**c) for c in data.get("components", [])]
                layout = UILayout(
                    layout_id=data["layout_id"],
                    context=data["context"],
                    platform=data["platform"],
                    components=components,
                    theme=data.get("theme", "kemet"),
                    created_at=data.get("created_at", datetime.utcnow().isoformat()),
                    updated_at=data.get("updated_at", datetime.utcnow().isoformat())
                )
                self.layouts[layout.layout_id] = layout

    def _save_layout(self, layout: UILayout):
        """Save a UI layout to disk"""
        layout.updated_at = datetime.utcnow().isoformat()
        layout_file = self.layouts_dir / f"{layout.layout_id}.json"
        data = asdict(layout)
        with open(layout_file, "w") as f:
            json.dump(data, f, indent=2)

    def _load_behaviors(self):
        """Load user behavior data"""
        for behavior_file in self.behavior_dir.glob("*.json"):
            with open(behavior_file, "r") as f:
                data = json.load(f)
                behavior = UserBehavior(**data)
                self.user_behaviors[behavior.user_id] = behavior

    def _save_behavior(self, behavior: UserBehavior):
        """Save user behavior data"""
        behavior.last_active = datetime.utcnow().isoformat()
        behavior_file = self.behavior_dir / f"{behavior.user_id}.json"
        with open(behavior_file, "w") as f:
            json.dump(asdict(behavior), f, indent=2)

    def get_or_create_behavior(self, user_id: str) -> UserBehavior:
        """Get or create user behavior tracking"""
        if user_id not in self.user_behaviors:
            self.user_behaviors[user_id] = UserBehavior(user_id=user_id)
            self._save_behavior(self.user_behaviors[user_id])
        return self.user_behaviors[user_id]

    def track_interaction(self, user_id: str, component_id: str):
        """Track user interaction with a component"""
        behavior = self.get_or_create_behavior(user_id)
        behavior.most_used_components[component_id] = \
            behavior.most_used_components.get(component_id, 0) + 1
        behavior.session_count += 1
        self._save_behavior(behavior)

    def generate_layout(self, context: str, platform: str,
                        user_id: Optional[str] = None) -> UILayout:
        """Generate an adaptive UI layout"""
        layout_id = f"{context}_{platform}"

        # Check if we have an existing layout
        if layout_id in self.layouts:
            layout = self.layouts[layout_id]
        else:
            # Generate default layout for context
            layout = self._generate_default_layout(context, platform)
            self.layouts[layout_id] = layout
            self._save_layout(layout)

        # Adapt based on user behavior if available
        if user_id and user_id in self.user_behaviors:
            layout = self._adapt_layout(layout, self.user_behaviors[user_id])

        return layout

    def _generate_default_layout(self, context: str, platform: str) -> UILayout:
        """Generate a default layout for a context"""
        components = []

        if context == "dashboard":
            components = [
                UIComponent("card", "revenue-card", "Revenue", "revenue_data",
                           {"metric": "daily_revenue", "format": "currency"}, order=0),
                UIComponent("card", "agents-card", "Active Agents", "agent_status",
                           {"metric": "active_count"}, order=1),
                UIComponent("table", "orders-table", "Recent Orders", "orders",
                           {"columns": ["id", "product", "amount", "status"], "limit": 10}, order=2),
                UIComponent("chart", "revenue-chart", "Revenue Trend", "revenue_history",
                           {"type": "line", "period": "7d"}, order=3),
                UIComponent("card", "system-card", "System Health", "system_health",
                           {"metrics": ["cpu", "memory", "gpu", "storage"]}, order=4),
            ]
        elif context == "agent-monitor":
            components = [
                UIComponent("card", "agent-status", "Agent Status", "agent_states",
                           {"show_details": True}, order=0),
                UIComponent("table", "agent-tasks", "Active Tasks", "agent_tasks",
                           {"columns": ["task_id", "agent", "action", "status"], "limit": 20}, order=1),
                UIComponent("text", "agent-log", "Agent Log", "agent_log",
                           {"lines": 50, "filter": "error"}, order=2),
            ]
        elif context == "settings":
            components = [
                UIComponent("form", "general-settings", "General Settings", "settings_general",
                           {"fields": ["theme", "language", "timezone"]}, order=0),
                UIComponent("form", "agent-settings", "Agent Configuration", "settings_agents",
                           {"fields": ["poll_interval", "max_retries", "log_level"]}, order=1),
                UIComponent("form", "notification-settings", "Notifications", "settings_notifications",
                           {"fields": ["email", "matrix", "push"]}, order=2),
            ]
        else:
            components = [
                UIComponent("text", "welcome", "Welcome", "welcome_message",
                           {"content": "NGARI Sovereign Business Operating System"}, order=0),
            ]

        return UILayout(
            layout_id=f"{context}_{platform}",
            context=context,
            platform=platform,
            components=components,
            theme="kemet"
        )

    def _adapt_layout(self, layout: UILayout, behavior: UserBehavior) -> UILayout:
        """Adapt layout based on user behavior"""
        # Sort components by usage frequency
        component_usage = {
            c.id: behavior.most_used_components.get(c.id, 0)
            for c in layout.components
        }

        # Reorder components by usage (most used first)
        layout.components.sort(
            key=lambda c: component_usage.get(c.id, 0),
            reverse=True
        )

        # Update order values
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
        """Render layout as HTML"""
        html = f'<div class="ngari-layout" data-context="{layout.context}" data-platform="{layout.platform}">\n'

        for component in sorted(layout.components, key=lambda c: c.order):
            html += f'  <div class="ngari-component ngari-{component.component_type}" '
            html += f'id="{component.id}" data-source="{component.data_source}">\n'
            html += f'    <h3>{component.label}</h3>\n'
            html += f'    <div class="component-content" data-properties=\'{json.dumps(component.properties)}\'></div>\n'
            html += f'  </div>\n'

        html += '</div>'
        return html

    def get_available_layouts(self) -> List[dict]:
        """Get list of available layouts"""
        return [
            {
                "layout_id": layout.layout_id,
                "context": layout.context,
                "platform": layout.platform,
                "components": len(layout.components),
                "theme": layout.theme
            }
            for layout in self.layouts.values()
        ]

    def export_layout(self, layout_id: str) -> Optional[dict]:
        """Export a layout for sharing or backup"""
        if layout_id in self.layouts:
            return asdict(self.layouts[layout_id])
        return None

    def import_layout(self, data: dict) -> bool:
        """Import a layout"""
        try:
            components = [UIComponent(**c) for c in data.get("components", [])]
            layout = UILayout(
                layout_id=data["layout_id"],
                context=data["context"],
                platform=data["platform"],
                components=components,
                theme=data.get("theme", "kemet"),
                created_at=data.get("created_at", datetime.utcnow().isoformat()),
                updated_at=data.get("updated_at", datetime.utcnow().isoformat())
            )
            self.layouts[layout.layout_id] = layout
            self._save_layout(layout)
            return True
        except Exception as e:
            logger.error(f"Failed to import layout: {e}")
            return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    engine = GenerativeUIEngine()

    # Generate layouts
    dashboard = engine.generate_layout("dashboard", "web", "user-001")
    print(f"Dashboard layout: {len(dashboard.components)} components")

    agent_monitor = engine.generate_layout("agent-monitor", "web")
    print(f"Agent monitor layout: {len(agent_monitor.components)} components")

    # Track interactions
    engine.track_interaction("user-001", "revenue-card")
    engine.track_interaction("user-001", "revenue-card")
    engine.track_interaction("user-001", "agents-card")

    # Generate adapted layout
    adapted = engine.generate_layout("dashboard", "web", "user-001")
    print(f"\nAdapted dashboard (first component): {adapted.components[0].label}")

    # Render as HTML
    html = engine.render_layout(dashboard, "html")
    print(f"\nHTML layout generated ({len(html)} bytes)")

    # List available layouts
    layouts = engine.get_available_layouts()
    print(f"\nAvailable layouts: {len(layouts)}")
    for layout in layouts:
        print(f"  - {layout['layout_id']} ({layout['components']} components)")
