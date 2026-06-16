#!/usr/bin/env python3
"""
Static validator for drf-spectacular @extend_schema annotations.

Runs WITHOUT Django/DB. For each views.py it checks:
  1. The file parses (no syntax errors introduced by annotations).
  2. Every bare Name referenced inside an @extend_schema/@extend_schema_view
     decorator resolves to something imported or defined in that module
     (catches "used a serializer you forgot to import").
  3. Every inline_serializer(...) call has a name= kwarg, and those names are
     globally unique across all scanned files (duplicate component names make
     drf-spectacular emit broken/colliding schemas).

Usage:
    python validate_schema_annotations.py [app1 app2 ...]
    # no args  -> scans every <app>/views.py under this directory
Exit code is non-zero if any problem is found.
"""
import ast
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent

# names provided by the decorator ecosystem / builtins we never flag
KNOWN = {
    "extend_schema", "extend_schema_view", "inline_serializer",
    "OpenApiParameter", "OpenApiResponse", "OpenApiExample", "OpenApiRequest",
    "OpenApiTypes", "PolymorphicProxySerializer", "serializers",
    "True", "False", "None", "int", "str", "bool", "float", "list", "dict",
}
DECORATORS = {"extend_schema", "extend_schema_view"}


def module_names(tree):
    """Collect names importable/definable at module scope."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    names.add(t.id)
    return names


def decorator_calls(tree):
    """Yield ast.Call nodes that are @extend_schema / @extend_schema_view."""
    for node in ast.walk(tree):
        decs = getattr(node, "decorator_list", None)
        if not decs:
            continue
        for dec in decs:
            call = dec if isinstance(dec, ast.Call) else None
            func = call.func if call else dec
            name = (
                func.id if isinstance(func, ast.Name)
                else func.attr if isinstance(func, ast.Attribute)
                else None
            )
            if name in DECORATORS and call is not None:
                yield call


def check_file(path, defined, inline_names, problems):
    src = path.read_text()
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as e:
        problems.append(f"{path}: SYNTAX ERROR: {e}")
        return

    local = module_names(tree) | KNOWN
    rel = path.relative_to(BASE)

    for call in decorator_calls(tree):
        for sub in ast.walk(call):
            # collect inline_serializer names + verify name= present
            if (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Name)
                and sub.func.id == "inline_serializer"
            ):
                kw = {k.arg: k.value for k in sub.keywords}
                name_node = kw.get("name")
                if name_node is None or not isinstance(name_node, ast.Constant):
                    problems.append(
                        f"{rel}:{sub.lineno}: inline_serializer missing literal name="
                    )
                else:
                    inline_names.setdefault(name_node.value, []).append(
                        f"{rel}:{sub.lineno}"
                    )
            # bare Name references inside the decorator must resolve
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                if sub.id not in local:
                    problems.append(
                        f"{rel}:{sub.lineno}: '{sub.id}' referenced in @extend_schema "
                        f"but not imported/defined in module"
                    )


def main():
    targets = sys.argv[1:]
    if targets:
        files = [BASE / app / "views.py" for app in targets]
    else:
        files = sorted(BASE.glob("*/views.py"))

    problems = []
    inline_names = {}
    for f in files:
        if not f.exists():
            problems.append(f"{f}: does not exist")
            continue
        check_file(f, set(), inline_names, problems)

    for name, locs in sorted(inline_names.items()):
        if len(locs) > 1:
            problems.append(
                f"DUPLICATE inline_serializer name '{name}' at: {', '.join(locs)}"
            )

    if problems:
        print("FAIL — schema annotation problems:\n")
        for p in problems:
            print("  -", p)
        print(f"\n{len(problems)} problem(s).")
        sys.exit(1)

    print(f"OK — scanned {len(files)} file(s), {len(inline_names)} inline serializer(s), no problems.")


if __name__ == "__main__":
    main()
