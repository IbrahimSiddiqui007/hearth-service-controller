from fastapi import HTTPException


def validate_dependencies(services: dict):
    """Validate references and cycles without recursion-depth dependence."""
    visited = set()
    for start in services:
        if start in visited:
            continue
        stack = [(start, False)]
        visiting = set()
        while stack:
            sid, exiting = stack.pop()
            if exiting:
                visiting.remove(sid)
                visited.add(sid)
                continue
            if sid in visiting:
                raise HTTPException(422, f"Dependency cycle involving {sid}")
            if sid in visited:
                continue
            if sid not in services:
                raise HTTPException(422, f"Unknown dependency: {sid}")
            visiting.add(sid)
            stack.append((sid, True))
            stack.extend((dep, False) for dep in reversed(services[sid].get("dependencies", [])))


def startup_order(services: dict, target: str):
    validate_dependencies(services)
    ordered, visited = [], set()
    stack = [(target, False)]
    while stack:
        sid, exiting = stack.pop()
        if exiting:
            ordered.append(sid)
            continue
        if sid in visited:
            continue
        visited.add(sid)
        stack.append((sid, True))
        stack.extend((dep, False) for dep in reversed(services[sid].get("dependencies", [])))
    return ordered
