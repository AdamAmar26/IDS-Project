import os

import dash
from dash import html, dcc, callback, Output, Input, dash_table
import dash_bootstrap_components as dbc
import requests

dash.register_page(__name__, path="/telemetry-explorer", name="Telemetry Explorer")

API = os.environ.get("IDS_API_URL", "http://localhost:8000")


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
                dbc.Col([html.H5("Telemetry Explorer")], width=8),
                dbc.Col(
                    [
                        dcc.Dropdown(
                            id="event-type-filter",
                            placeholder="Event type",
                            options=[
                                {"label": t.replace("_", " ").title(), "value": t}
                                for t in [
                                    "new_process",
                                    "system_stats",
                                    "connection",
                                    "net_io",
                                    "login_success",
                                    "login_failure",
                                    "admin_activity",
                                ]
                            ],
                            multi=False,
                        ),
                    ],
                    width=4,
                ),
            ],
            className="mb-3",
        ),
        dbc.Tabs(
            [
                dbc.Tab(
                    label="Raw Events",
                    children=[
                        html.Div(className="mt-3"),
                        dash_table.DataTable(
                            id="raw-events-table",
                            columns=[
                                {"name": "ID", "id": "id"},
                                {"name": "Host", "id": "host_id"},
                                {"name": "Type", "id": "event_type"},
                                {"name": "Time", "id": "timestamp"},
                            ],
                            style_table={"overflowX": "auto"},
                            style_header={
                                "backgroundColor": "#303030",
                                "color": "white",
                            },
                            style_cell={
                                "backgroundColor": "#222",
                                "color": "white",
                                "border": "1px solid #444",
                                "maxWidth": "200px",
                                "overflow": "hidden",
                                "textOverflow": "ellipsis",
                            },
                            page_size=20,
                        ),
                    ],
                ),
                dbc.Tab(
                    label="Feature Windows",
                    children=[
                        html.Div(className="mt-3"),
                        dash_table.DataTable(
                            id="feature-windows-table",
                            columns=[
                                {"name": "ID", "id": "id"},
                                {"name": "Host", "id": "host_id"},
                                {"name": "Start", "id": "window_start"},
                                {"name": "End", "id": "window_end"},
                                {"name": "Conns", "id": "outbound_conn_count"},
                                {"name": "Dest IPs", "id": "unique_dest_ips"},
                                {"name": "Dest Ports", "id": "unique_dest_ports"},
                                {"name": "Failed Logins", "id": "failed_login_count"},
                                {"name": "New Procs", "id": "new_process_count"},
                                {"name": "Avg CPU", "id": "avg_process_cpu"},
                            ],
                            style_table={"overflowX": "auto"},
                            style_header={
                                "backgroundColor": "#303030",
                                "color": "white",
                            },
                            style_cell={
                                "backgroundColor": "#222",
                                "color": "white",
                                "border": "1px solid #444",
                            },
                            page_size=20,
                        ),
                    ],
                ),
            ],
        ),
    ],
)


@callback(
    Output("raw-events-table", "data"),
    [
        Input("refresh-interval", "n_intervals"),
        Input("event-type-filter", "value"),
    ],
)
def update_events(_, event_type):
    url = f"{API}/events?limit=100"
    if event_type:
        url += f"&event_type={event_type}"
    return _safe_get(url, [])


@callback(
    Output("feature-windows-table", "data"),
    Input("refresh-interval", "n_intervals"),
)
def update_windows(_):
    return _safe_get(f"{API}/features?limit=100", [])
