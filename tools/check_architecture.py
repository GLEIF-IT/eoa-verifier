"""Check cohesive leaf components, declared dependencies and test support boundaries."""

import ast
from graphlib import CycleError, TopologicalSorter
from importlib.util import resolve_name
from pathlib import Path

PACKAGE = "eoa_verifier"
ROOT = Path(__file__).resolve().parents[1] / "src" / PACKAGE
RULES = {
    "associations": ["associations", "persistence"],
    "delivery": ["delivery", "persistence"],
    "persistence": ["persistence"],
    "receiving": ["persistence", "receiving"],
    "runtime": [
        "associations",
        "delivery",
        "persistence",
        "receiving",
        "runtime",
        "verification",
    ],
    "verification": ["persistence", "verification"],
}
FOREIGN = "vlei_oracle"


def module_name(path, root, package):
    parts = path.relative_to(root).with_suffix("").parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join((package, *parts))


def imports(tree, module, is_package=False):
    """Resolve static import targets, including imported child modules."""
    package = module if is_package else module.rpartition(".")[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            target = node.module or ""
            if node.level:
                target = resolve_name("." * node.level + target, package)
            yield target
            yield from (target + "." + alias.name for alias in node.names)


def cycles(graph):
    """Imported symbols are not modules; retain actual module edges only."""
    try:
        tuple(
            TopologicalSorter(
                {key: values & graph.keys() for key, values in graph.items()}
            ).static_order()
        )
    except CycleError as error:
        return [f"import cycle: {error.args[1]}"]
    return []


def check_tests(root):
    """Tests may share support modules, never import another test module."""
    errors, graph = [], {}
    if not root.exists():
        return errors
    for path in root.rglob("*.py"):
        module = module_name(path, root, "tests")
        targets = set(
            imports(ast.parse(path.read_text()), module, path.name == "__init__.py")
        )
        graph[module] = targets
        for target in targets:
            if any(part.startswith("test_") for part in target.split(".")):
                errors.append(
                    f"{path.relative_to(root)}: import from test module {target}; use tests.support"
                )
    return errors + cycles(graph)


def check(root=ROOT, tests_root=None):
    errors, graph = [], {}
    for path in root.rglob("*.py"):
        relative = path.relative_to(root)
        module = module_name(path, root, PACKAGE)
        tree = ast.parse(path.read_text())
        targets = set(imports(tree, module, path.name == "__init__.py"))
        graph[module] = targets
        if path.name == "__init__.py":
            for node in tree.body:
                if (
                    isinstance(node, ast.Expr)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    continue
                if (
                    relative.parts == ("__init__.py",)
                    and isinstance(node, ast.Assign)
                    and all(
                        isinstance(t, ast.Name) and t.id in {"__version__", "__all__"}
                        for t in node.targets
                    )
                ):
                    try:
                        ast.literal_eval(node.value)
                        continue
                    except (ValueError, TypeError):
                        pass
                errors.append(
                    f"{relative}: initializer must contain only documentation or literal root metadata"
                )
            continue
        if len(relative.parts) != 2 or relative.parts[0] not in RULES:
            errors.append(
                f"{relative}: implementation must live in a known leaf component"
            )
            continue
        component = relative.parts[0]
        for target in targets:
            if target == "tests" or target.startswith("tests."):
                errors.append(f"{relative}: production imports test support {target}")
            if target == FOREIGN or target.startswith(FOREIGN + "."):
                errors.append(f"{relative}: forbidden application dependency {target}")
            if target.startswith(PACKAGE + "."):
                dependency = target.split(".")[1]
                if dependency not in RULES[component]:
                    errors.append(f"{relative}: forbidden dependency on {target}")
            if (
                PACKAGE == "vlei_oracle"
                and component == "associations"
                and any(
                    target == prefix or target.startswith(prefix + ".")
                    for prefix in (
                        "lmdb",
                        "keri.db",
                        "keri.app",
                        "hio",
                        "falcon",
                        "requests",
                        "httpx",
                        "aiohttp",
                    )
                )
            ):
                errors.append(
                    f"{relative}: association policy must not depend on storage/HTTP/runtime {target}"
                )
    tests_root = tests_root if tests_root is not None else root.parents[1] / "tests"
    return errors + cycles(graph) + check_tests(tests_root)


if __name__ == "__main__":
    violations = check()
    if violations:
        raise SystemExit("\n".join(violations))
    print(
        "Architecture OK: cohesive leaf components, allowed dependencies, no cycles or test-module imports"
    )
