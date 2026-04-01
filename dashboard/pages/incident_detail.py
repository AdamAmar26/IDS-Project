import os
import json

import dash
from dash import html, dcc, callback, Output, Input, State, ALL
import dash_bootstrap_components as dbc
import requests

dash.register_page(__name__, path="/incident-detail", name="Incidents")

API = os.environ.get("IDS_API_URL", "http://localhost:8000")

SEVERITY_COLORS = {
    "critical": "danger",
    "high": "warning",
    "medium": "info",
    "low": "secondary",
}


def _safe_get(url, default=None):
    try:
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception:
        return default


layout = dbc.Container(
    [
        dbc.Row(
            [
                dbc.Col(
                    [
                        html.H5("Incidents"),
                        dcc.Dropdown(
                            id="incident-filter-status",
                            placeholder="Filter by status",
                            options=[
                                {"label": s.title(), "value": s}
                                for s in ["open", "acknowledged", "resolved"]
                            ],
                        ),
                    ],
                    width=4,
                ),
                dbc.Col(width=8),
            ],
            className="mb-3",
        ),
        dbc.Row(
            [
                dbc.Col([html.Div(id="incident-list")], width=4),
                dbc.Col(
                    [
                        html.Div(
                            [
                                dbc.Button(
                                    "Acknowledge", id="btn-acknowledge",
                                    color="info", size="sm", className="me-2",
                                    style={"display": "none"},
                                ),
                                dbc.Button(
                                    "Resolve", id="btn-resolve",
                                    color="success", size="sm",
                                    style={"display": "none"},
                                ),
                            ],
                            className="mb-2",
                        ),
                        html.Div(id="incident-detail-panel"),
                    ],
                    width=8,
                ),
            ],
        ),
        dcc.Store(id="selected-incident-id"),
        dcc.Store(id="incident-action-trigger", data=0),
    ],
)


@callback(
    Output("incident-list", "children"),
    [
        Input("refresh-interval", "n_intervals"),
        Input("incident-filter-status", "value"),
        Input("incident-action-trigger", "data"),
    ],
)
def update_incident_list(_, status_filter, __):
    url = f"{API}/incidents?limit=50"
    if status_filter:
        url += f"&status={status_filter}"
    incidents = _safe_get(url, [])
    if not incidents:
        return html.P("No incidents found.", className="text-muted")

    items = []
    for inc in incidents:
        color = SEVERITY_COLORS.get(inc.get("severity", "low"), "secondary")
        items.append(
            dbc.Card(
                dbc.CardBody(
                    [
                        html.Div(
                            [
                                dbc.Badge(
                                    inc.get("severity", "").upper(),
                                    color=color,
                                    className="me-2",
                                ),
                                html.Small(
                                    f"#{inc['id']}  |  {inc.get('status', '')}"
                                ),
                            ]
                        ),
                        html.P(
                            (inc.get("summary", "") or "")[:120],
                            className="mb-0 mt-1 small",
                        ),
                    ]
                ),
                className="mb-2",
                id={"type": "incident-card", "index": inc["id"]},
                style={"cursor": "pointer"},
            )
        )
    return items


@callback(
    Output("selected-incident-id", "data"),
    Input({"type": "incident-card", "index": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def select_incident(clicks):
    ctx = dash.callback_context
    if not ctx.triggered:
        return dash.no_update
    prop_id = ctx.triggered[0]["prop_id"]
    try:
        parsed = json.loads(prop_id.rsplit(".", 1)[0])
        return parsed["index"]
    except Exception:
        return dash.no_update


@callback(
    [
        Output("incident-detail-panel", "children"),
        Output("btn-acknowledge", "style"),
        Output("btn-resolve", "style"),
    ],
    [
        Input("selected-incident-id", "data"),
        Input("refresh-interval", "n_intervals"),
        Input("incident-action-trigger", "data"),
    ],
)
def show_detail(incident_id, _, __):
    hide = {"display": "none"}
    if not incident_id:
        return (
            html.P("Select an incident from the list.", className="text-muted"),
            hide, hide,
        )

    inc = _safe_get(f"{API}/incidents/{incident_id}")
    if not inc:
        return html.P("Incident not found.", className="text-danger"), hide, hide

    color = SEVERITY_COLORS.get(inc.get("severity", "low"), "secondary")
    status = inc.get("status", "open")
    show = {"display": "inline-block"}

    ack_style = show if status == "open" else hide
    res_style = show if status in ("open", "acknowledged") else hide

    card = dbc.Card(
        dbc.CardBody(
            [
                html.H5(
                    [
                        f"Incident #{inc['id']}  ",
                        dbc.Badge(
                            inc.get("severity", "").upper(), color=color
                        ),
                    ]
                ),
                html.Hr(),
                html.H6("Summary"),
                html.P(inc.get("summary", "")),
                html.H6("Explanation"),
                html.Pre(
                    inc.get("explanation", ""),
                    style={"whiteSpace": "pre-wrap", "color": "#ccc"},
                ),
                html.H6("Suggested Actions"),
                html.Pre(
                    inc.get("suggested_actions", ""),
                    style={"whiteSpace": "pre-wrap", "color": "#ccc"},
                ),
                html.H6("Correlated Alerts"),
                html.P(f"Alert IDs: {inc.get('alert_ids', [])}"),
                html.Hr(),
                html.Small(
                    f"Created: {inc.get('created_at', '')} | "
                    f"Updated: {inc.get('updated_at', '')} | "
                    f"Status: {inc.get('status', '')}"
                ),
            ]
        )
    )
    return card, ack_style, res_style


@callback(
    Output("incident-action-trigger", "data"),
    [
        Input("btn-acknowledge", "n_clicks"),
        Input("btn-resolve", "n_clicks"),
    ],
    State("selected-incident-id", "data"),
    prevent_initial_call=True,
)
def handle_status_change(ack_clicks, res_clicks, incident_id):
    if not incident_id:
        return dash.no_update
    ctx = dash.callback_context
    if not ctx.triggered:
        return dash.no_update
    btn_id = ctx.triggered[0]["prop_id"].split(".")[0]
    new_status = "acknowledged" if btn_id == "btn-acknowledge" else "resolved"
    try:
        requests.patch(
            f"{API}/incidents/{incident_id}/status?status={new_status}",
            timeout=5,
        )
    except Exception:
        pass
    return (ack_clicks or 0) + (res_clicks or 0)
