"""Check application component imports and leaf layout using only the standard library."""

import ast
from graphlib import CycleError, TopologicalSorter
from importlib.util import resolve_name
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "src" / "eoa_verifier"
COMPONENTS = {"runtime", "receiving", "verification", "associations", "delivery", "persistence"}


def check(root=ROOT):
    """Return violations, including imports inside functions and relative imports."""
    errors, graph = [], {}
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        parts = relative.with_suffix("").parts
        module = ".".join(("eoa_verifier", *parts))
        tree = ast.parse(path.read_text(), filename=str(path))
        if path.name == "__init__.py":
            if parts != ("__init__",) and (len(parts) != 2 or parts[0] not in COMPONENTS):
                errors.append(f"{relative}: initializer must belong to the root or a known leaf component")
            if any(not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)
                        and isinstance(n.value.value, str)) for n in tree.body):
                errors.append(f"{relative}: initializer must contain only documentation")
            continue
        if len(parts) != 2 or parts[0] not in COMPONENTS:
            errors.append(f"{relative}: implementation must live in a known leaf component")
            continue
        component = parts[0]
        allowed = COMPONENTS if component == "runtime" else {component, "persistence"}
        graph[module] = set()
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                target = node.module or ""
                if node.level:
                    target = resolve_name("." * node.level + target, module.rpartition(".")[0])
                targets = [target, *(target + "." + alias.name for alias in node.names)]
            for target in targets:
                if not target.startswith("eoa_verifier."):
                    continue
                target_component = target.split(".")[1]
                if target_component not in allowed:
                    errors.append(f"{relative}:{node.lineno}: forbidden dependency on {target}")
                graph[module].add(target)
    # Imported symbols are not module dependencies; retain only actual modules.
    graph = {module: dependencies & graph.keys() for module, dependencies in graph.items()}
    try:
        tuple(TopologicalSorter(graph).static_order())
    except CycleError as error:
        errors.append(f"application import cycle: {error.args[1]}")
    return errors


if __name__ == "__main__":
    violations = check()
    if violations:
        raise SystemExit("\n".join(violations))
    print("Architecture OK: leaf components, permitted dependencies, no import cycles")
