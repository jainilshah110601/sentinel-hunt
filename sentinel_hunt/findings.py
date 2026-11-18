"""Resolve each proposed finding to the actual rows returned by the query."""
def resolve(report, rows):
    findings = report.get("findings") if isinstance(report, dict) else None
    if not isinstance(findings, list):
        raise ValueError("Expected a findings list")
    output = []
    for item in findings:
        if not isinstance(item, dict):
            raise ValueError("Invalid finding")
        for key in ("title", "assessment", "confidence", "technique", "next_check"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                raise ValueError(f"Missing finding field: {key}")
        # Row IDs start at 1 in the prompt. A zero would silently select the last event.
        ids = item.get("evidence")
        if not isinstance(ids, list) or not ids or any(type(i) is not int or not 1 <= i <= len(rows) for i in ids):
            raise ValueError("Finding references missing evidence")
        if item["confidence"] not in ("low", "medium", "high"):
            raise ValueError("Invalid confidence")
        output.append({**item, "evidence": [{"row": i, "event": rows[i-1]} for i in dict.fromkeys(ids)]})
    return output
