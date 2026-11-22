"""Generative UI engine: default layouts, persistence, behavior tracking,
adaptation, rendering and import/export."""

import json
import os

import pytest

from core.kernel.generative_ui import GenerativeUIEngine, UIComponent, UILayout


@pytest.fixture
def engine(tmp_path):
    return GenerativeUIEngine(str(tmp_path))


@pytest.mark.parametrize(
    ("context", "first", "count"),
    [
        ("dashboard", "revenue-card", 5),
        ("agent-monitor", "agent-status", 3),
        ("settings", "general-settings", 3),
        ("anything-else", "welcome", 1),
    ],
)
def test_each_context_has_a_default_layout(engine, context, first, count):
    layout = engine.generate_layout(context, "web")
    assert layout.layout_id == f"{context}_web"
    assert len(layout.components) == count
    assert layout.components[0].id == first
    assert [c.order for c in layout.components] == list(range(count))


def test_layouts_are_saved_and_reloaded(engine, tmp_path):
    engine.generate_layout("dashboard", "mobile")
    saved = json.loads(
        (tmp_path / "ui" / "layouts" / "dashboard_mobile.json").read_text()
    )
    assert saved["platform"] == "mobile"
    again = GenerativeUIEngine(str(tmp_path))
    assert [c.id for c in again.layouts["dashboard_mobile"].components] == [
        c.id for c in engine.layouts["dashboard_mobile"].components
    ]


def test_a_stored_layout_is_reused(engine):
    first = engine.generate_layout("settings", "web")
    assert engine.generate_layout("settings", "web") is first


def test_interactions_are_counted_and_persisted(engine, tmp_path):
    for component in ("orders-table", "orders-table", "agents-card"):
        engine.track_interaction("u1", component)
    behavior = engine.user_behaviors["u1"]
    assert behavior.most_used_components == {"orders-table": 2, "agents-card": 1}
    assert behavior.session_count == 3
    reloaded = GenerativeUIEngine(str(tmp_path))
    assert reloaded.user_behaviors["u1"].most_used_components["orders-table"] == 2


def test_the_most_used_component_comes_first_for_that_user(engine):
    engine.generate_layout("dashboard", "web")
    for _ in range(3):
        engine.track_interaction("u1", "system-card")
    engine.track_interaction("u1", "orders-table")
    adapted = engine.generate_layout("dashboard", "web", "u1")
    assert [c.id for c in adapted.components[:2]] == ["system-card", "orders-table"]
    assert [c.order for c in adapted.components] == list(range(5))


def test_an_unknown_user_gets_the_default_order(engine):
    layout = engine.generate_layout("dashboard", "web", "nobody")
    assert layout.components[0].id == "revenue-card"


def test_json_rendering_round_trips(engine):
    layout = engine.generate_layout("agent-monitor", "desktop")
    data = json.loads(engine.render_layout(layout, "json"))
    assert data["layout_id"] == "agent-monitor_desktop"
    assert json.loads(engine.render_layout(layout, "other")) == data


def test_html_rendering_lists_components_in_order(engine):
    layout = engine.generate_layout("settings", "web")
    html = engine.render_layout(layout, "html")
    assert html.startswith('<div class="ngari-layout" data-context="settings"')
    positions = [html.index(f'id="{c.id}"') for c in layout.components]
    assert positions == sorted(positions)
    assert html.count("<h3>") == 3


def test_export_then_import_into_another_engine(engine, tmp_path):
    engine.generate_layout("dashboard", "web")
    exported = engine.export_layout("dashboard_web")
    other = GenerativeUIEngine(str(tmp_path / "other"))
    assert other.import_layout(exported) is True
    assert other.export_layout("dashboard_web")["components"] == exported["components"]
    assert engine.export_layout("missing") is None


def test_a_bad_component_is_refused_on_import(engine):
    bad = {"layout_id": "x", "context": "c", "platform": "web",
           "components": [{"unexpected": 1}]}  # fmt: skip
    assert engine.import_layout(bad) is False
    assert "x" not in engine.layouts


def test_available_layouts_summarise_what_is_stored(engine):
    engine.generate_layout("dashboard", "web")
    engine.generate_layout("settings", "mobile")
    summary = {s["layout_id"]: s["components"] for s in engine.get_available_layouts()}
    assert summary == {"dashboard_web": 5, "settings_mobile": 3}


def test_dataclasses_keep_their_defaults():
    component = UIComponent("card", "c", "C", "src")
    assert (component.visibility, component.order, component.properties) == (
        "always",
        0,
        {},
    )
    assert UILayout("l", "ctx", "web").theme == "kemet"


def test_imported_text_cannot_inject_markup(engine):
    from html.parser import HTMLParser

    hostile = {
        "layout_id": "evil",
        "context": 'x" onmouseover="alert(1)',
        "platform": "web",
        "components": [
            {
                "component_type": "card",
                "id": '"><script>alert(2)</script>',
                "label": "<img src=x onerror=alert(3)>",
                "data_source": "s",
                "properties": {"note": "it's '><script>alert(4)</script>"},
            }
        ],
    }
    assert engine.import_layout(hostile)
    out = engine.render_layout(engine.layouts["evil"], "html")

    tags, attrs = [], []

    class Collect(HTMLParser):
        def handle_starttag(self, tag, a):
            tags.append(tag)
            attrs.extend(name for name, _ in a)

    Collect().feed(out)
    assert set(tags) == {"div", "h3"}
    assert not any(name.startswith("on") for name in attrs)
    # The original text survives, escaped.
    assert "&lt;img src=x onerror=alert(3)&gt;" in out
    import html as _html
    import json as _json
    import re as _re

    props = _re.search(r'data-properties="([^"]*)"', out).group(1)
    assert _json.loads(_html.unescape(props)) == hostile["components"][0]["properties"]


def test_one_users_habits_do_not_reorder_anyone_elses_layout(engine, tmp_path):
    default = [c.id for c in engine.generate_layout("dashboard", "web").components]
    for _ in range(5):
        engine.track_interaction("alice", "system-card")
    alice = engine.generate_layout("dashboard", "web", "alice")
    assert alice.components[0].id == "system-card"

    assert [
        c.id for c in engine.generate_layout("dashboard", "web").components
    ] == default
    assert [
        c.id for c in engine.generate_layout("dashboard", "web", "bob").components
    ] == default
    assert [c.order for c in engine.layouts["dashboard_web"].components] == list(
        range(5)
    )
    assert [
        c.id
        for c in GenerativeUIEngine(str(tmp_path)).layouts["dashboard_web"].components
    ] == default


@pytest.mark.parametrize("name", ["../escaped", "a/b", "", "nul\0"])
def test_ids_that_leave_the_ui_directory_are_refused(engine, tmp_path, name):
    before = sorted(str(p) for p in tmp_path.rglob("*"))
    with pytest.raises(ValueError, match="invalid user id"):
        engine.track_interaction(name, "c")
    with pytest.raises(ValueError, match="invalid layout id"):
        engine.generate_layout(name + "/x", "web")
    assert f"{name}/x_web" not in engine.layouts
    layout = {"layout_id": name, "context": "c", "platform": "web", "components": []}
    assert engine.import_layout(layout) is False
    assert name not in engine.layouts and name not in engine.user_behaviors
    assert sorted(str(p) for p in tmp_path.rglob("*")) == before


@pytest.mark.parametrize(
    "data",
    [
        {"context": "c", "platform": "web"},
        {"layout_id": "x", "platform": "web"},
        {"layout_id": "x", "context": "c"},
        {"layout_id": "x", "context": "c", "platform": "web", "components": [7]},
        "not a dict",
    ],
    ids=["no-id", "no-context", "no-platform", "bad-component", "string"],
)
def test_a_malformed_import_returns_false(engine, data):
    assert engine.import_layout(data) is False
    assert engine.layouts == {}


def test_one_unreadable_layout_does_not_hide_the_others(engine, tmp_path, caplog):
    engine.generate_layout("dashboard", "web")
    engine.generate_layout("settings", "web")
    engine.track_interaction("u1", "c")
    engine.track_interaction("u2", "c")
    layouts = tmp_path / "ui" / "layouts"
    (layouts / "settings_web.json").write_text('{"layout_id": "settings_web", "con')
    (tmp_path / "ui" / "behavior" / "u2.json").write_text("{not json")
    again = GenerativeUIEngine(str(tmp_path))
    assert list(again.layouts) == ["dashboard_web"]
    assert list(again.user_behaviors) == ["u1"]
    assert len(list(layouts.glob("settings_web.json.corrupt-*"))) == 1
    assert "UI layout unreadable" in caplog.text


def test_a_crash_while_saving_a_layout_keeps_the_old_file(
    engine, tmp_path, monkeypatch
):
    engine.generate_layout("dashboard", "web")
    path = tmp_path / "ui" / "layouts" / "dashboard_web.json"
    before = path.read_bytes()

    def full_disk(fd):  # the data is written, then the sync fails
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", full_disk)
    with pytest.raises(OSError):
        engine._save_layout(engine.layouts["dashboard_web"])
    monkeypatch.undo()
    assert path.read_bytes() == before
    assert [p for p in path.parent.iterdir() if p.name.endswith(".tmp")] == []


# -- fields of the wrong type are refused on import and set aside on load ------------


def _component(**changes):
    return {"component_type": "card", "id": "c1", "label": "L", "data_source": "s",
            "properties": {}, "visibility": "always", "order": 0, **changes}  # fmt: skip


def _layout(components=None, **changes):
    return {"layout_id": "x_web", "context": "x", "platform": "web",
            "components": [_component()] if components is None else components,
            "theme": "kemet", **changes}  # fmt: skip


WRONG_LAYOUTS = {
    "order str": _layout([_component(), _component(id="c2", order="1")]),
    "id list": _layout([_component(id=["a"])]),
    "label int": _layout([_component(label=5)]),
    "type null": _layout([_component(component_type=None)]),
    "source int": _layout([_component(data_source=1)]),
    "properties list": _layout([_component(properties=[])]),
    "visibility int": _layout([_component(visibility=3)]),
    "components dict": _layout({"a": _component()}),
    "context int": _layout(context=5),
    "platform null": _layout(platform=None),
    "theme list": _layout(theme=["kemet"]),
    "created_at int": _layout(created_at=0),
}


@pytest.mark.parametrize("data", WRONG_LAYOUTS.values(), ids=WRONG_LAYOUTS.keys())
def test_an_import_with_a_field_of_the_wrong_type_is_refused(engine, tmp_path, data):
    engine.generate_layout("dashboard", "web")
    assert engine.import_layout(data) is False
    assert list(engine.layouts) == ["dashboard_web"]
    assert not (tmp_path / "ui" / "layouts" / "x_web.json").exists()


def test_a_well_formed_import_still_renders_and_adapts(engine):
    assert engine.import_layout(_layout([_component(), _component(id="c2", order=1)]))
    engine.track_interaction("u", "c2")
    assert [c.id for c in engine.generate_layout("x", "web", "u").components] == [
        "c2",
        "c1",
    ]
    assert 'id="c1"' in engine.render_layout(engine.layouts["x_web"], "html")


@pytest.mark.parametrize("name", ["order str", "id list"])
def test_a_layout_file_of_the_wrong_type_is_set_aside(engine, tmp_path, name):
    engine.generate_layout("dashboard", "web")
    layouts = tmp_path / "ui" / "layouts"
    (layouts / "x_web.json").write_text(json.dumps(WRONG_LAYOUTS[name]))
    again = GenerativeUIEngine(str(tmp_path))
    assert list(again.layouts) == ["dashboard_web"]
    assert len(list(layouts.glob("x_web.json.corrupt-*"))) == 1
    again.track_interaction("u", "c1")
    assert again.render_layout(again.generate_layout("x", "web", "u"), "html")


WRONG_BEHAVIORS = {
    "most_used list": {"user_id": "u", "most_used_components": []},
    "count str": {"user_id": "u", "most_used_components": {"c1": "x"}},
    "session_count str": {"user_id": "u", "session_count": "3"},
    "user_id int": {"user_id": 5},
}


@pytest.mark.parametrize("data", WRONG_BEHAVIORS.values(), ids=WRONG_BEHAVIORS.keys())
def test_a_behavior_file_of_the_wrong_type_is_set_aside(engine, tmp_path, caplog, data):
    behavior = tmp_path / "ui" / "behavior"
    (behavior / "u.json").write_text(json.dumps(data))
    again = GenerativeUIEngine(str(tmp_path))
    assert again.user_behaviors == {}
    assert len(list(behavior.glob("u.json.corrupt-*"))) == 1
    assert "UI behavior unreadable" in caplog.text
    again.track_interaction("u", "revenue-card")
    assert (
        again.generate_layout("dashboard", "web", "u").components[0].id
        == "revenue-card"
    )


# -- names that must fit a file name, and saving first ---------------------------------


def test_the_longest_layout_id_that_fits_imports_and_one_more_is_refused(tmp_path):
    from core.kernel.generative_ui import GenerativeUIEngine

    engine = GenerativeUIEngine(str(tmp_path))
    longest = "L" * (255 - len(".json"))  # its temporary name must fit as well
    data = {"layout_id": longest, "context": "c", "platform": "web", "components": []}
    assert engine.import_layout(data) is True
    assert longest in GenerativeUIEngine(str(tmp_path)).layouts  # and it is saved
    assert engine.import_layout({**data, "layout_id": longest + "L"}) is False
    assert longest + "L" not in engine.layouts


def test_a_layout_that_cannot_be_saved_is_not_kept(tmp_path, monkeypatch):
    from core.kernel import generative_ui
    from core.kernel.generative_ui import GenerativeUIEngine

    engine = GenerativeUIEngine(str(tmp_path))

    def disk_full(path, data):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(generative_ui, "_write_durably", disk_full)
    data = {"layout_id": "t", "context": "c", "platform": "web", "components": []}
    assert engine.import_layout(data) is False and "t" not in engine.layouts
    with pytest.raises(OSError):
        engine.generate_layout("dashboard", "web")
    assert "dashboard_web" not in engine.layouts
    with pytest.raises(OSError):
        engine.get_or_create_behavior("user-1")
    assert "user-1" not in engine.user_behaviors


def test_a_name_too_long_for_a_file_is_refused_by_name(tmp_path):
    from core.kernel.generative_ui import GenerativeUIEngine

    engine = GenerativeUIEngine(str(tmp_path))
    with pytest.raises(ValueError, match="too long for a file name"):
        engine.generate_layout("c" * 260, "web")
    with pytest.raises(ValueError, match="too long for a file name"):
        engine.get_or_create_behavior("u" * 260)


# -- names in the HTML and in layout ids -----------------------------------------------


def _classes(html_text):
    from html.parser import HTMLParser

    found = []

    class Collect(HTMLParser):
        def handle_starttag(self, tag, attrs):
            value = dict(attrs).get("class", "")
            if "ngari-component" in value.split():
                found.append(value.split())

    Collect().feed(html_text)
    return found


@pytest.mark.parametrize(
    "kind", ["card ngari-admin-banner", "Card", "card\t", "", "1x"]
)
def test_a_component_type_that_is_not_one_word_is_not_imported(tmp_path, kind):
    engine = GenerativeUIEngine(str(tmp_path))
    data = {"layout_id": "t", "context": "c", "platform": "web", "components": [
        {"component_type": kind, "id": "a", "label": "l", "data_source": "s"}]}  # fmt: skip
    assert engine.import_layout(data) is False and "t" not in engine.layouts


def test_a_component_built_in_code_adds_no_class_names(tmp_path):
    engine = GenerativeUIEngine(str(tmp_path))
    layout = UILayout("t", "c", "web", [
        UIComponent("card ngari-admin-banner", "a", "l", "s"),
        UIComponent("chart", "b", "l", "s", order=1)])  # fmt: skip
    assert _classes(engine.render_layout(layout, "html")) == [
        ["ngari-component", "ngari-unknown"], ["ngari-component", "ngari-chart"]
    ]  # fmt: skip


def test_two_contexts_do_not_share_one_layout(tmp_path):
    engine = GenerativeUIEngine(str(tmp_path))
    engine.generate_layout("a_b", "c")
    with pytest.raises(ValueError, match="may not contain '_'"):
        engine.generate_layout("a", "b_c")
    assert ("a_b", "c") == (
        engine.layouts["a_b_c"].context,
        engine.layouts["a_b_c"].platform,
    )


# -- layouts an earlier kernel saved ---------------------------------------------------


@pytest.mark.parametrize("kind", ["line_chart", "Card"])
def test_a_layout_an_earlier_kernel_saved_is_loaded_and_renders(tmp_path, kind):
    # A stored component type that import refuses is loaded, not set aside:
    # rendering turns it into "unknown".
    layouts = tmp_path / "ui" / "layouts"
    layouts.mkdir(parents=True)
    saved = {"layout_id": "sales_web", "context": "sales", "platform": "web",
             "components": [{"component_type": kind, "id": "a", "label": "l",
                             "data_source": "s", "properties": {}, "visibility": "always",
                             "order": 0}],
             "theme": "kemet", "created_at": "2026-10-01T00:00:00+00:00",
             "updated_at": "2026-10-01T00:00:00+00:00"}  # fmt: skip
    (layouts / "sales_web.json").write_text(json.dumps(saved))
    engine = GenerativeUIEngine(str(tmp_path))
    assert sorted(p.name for p in layouts.iterdir()) == ["sales_web.json"]
    layout = engine.layouts["sales_web"]
    assert _classes(engine.render_layout(layout, "html")) == [
        ["ngari-component", "ngari-unknown"]
    ]
    # The same layout is refused on import.
    assert engine.import_layout(saved) is False
