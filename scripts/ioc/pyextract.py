"""Pull MCP tool definitions out of Python server source without running it."""

from __future__ import annotations

import ast
from pathlib import Path


def _decorator_name(d: ast.expr) -> str:
    node = d.func if isinstance(d, ast.Call) else d
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _const_str(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{...}" for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = _const_str(node.left), _const_str(node.right)
        if a is not None and b is not None:
            return a + b
    return None


def tools_in(path: Path) -> list[dict]:
    """Functions decorated as MCP tools/prompts/resources: name, description, parameter names, returned strings."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return []
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        kinds = [_decorator_name(d) for d in node.decorator_list]
        kind = next((k.split(".")[-1] for k in kinds if k.split(".")[-1] in ("tool", "prompt", "resource")), None)
        if not kind:
            continue
        desc = ast.get_docstring(node) or ""
        name = node.name
        for d in node.decorator_list:
            if isinstance(d, ast.Call):
                for kw in d.keywords:
                    if kw.arg == "description" and _const_str(kw.value):
                        desc = _const_str(kw.value)
                    if kw.arg == "name" and _const_str(kw.value):
                        name = _const_str(kw.value)
                if d.args and kind == "resource" and _const_str(d.args[0]):
                    name = _const_str(d.args[0])
        returns = []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Return) and sub.value is not None:
                s = _const_str(sub.value)
                if s and len(s) > 40:
                    returns.append(s)
        params = [a.arg for a in node.args.args if a.arg not in ("self", "ctx")]
        out.append({"name": name, "kind": kind, "description": desc, "params": params, "returns": returns})
    return out
