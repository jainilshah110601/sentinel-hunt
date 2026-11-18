"""Read event rows from Azure Log Analytics."""
from datetime import timedelta


def fetch_events(client, workspace, search):
    result = client.query_workspace(
        workspace, search.kql(), timespan=timedelta(hours=search.hours))
    # Missing rows can change the assessment, especially when looking for repeated events.
    if getattr(result, "partial_error", None):
        raise ValueError("Azure returned incomplete results. Narrow the search and retry.")
    table = result.tables[0] if result.tables else None
    return [dict(zip(table.columns, row)) for row in table.rows] if table else []
