import os
import socket

import dash
from dash import html, dcc, callback, Output, Input
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import requests

dash.register_page(__name__, path="/host-detail", name="Host Detail")

API = os.environ.get("IDS_API_URL", "http://localhost:8000")
DEFAULT_HOST = socket.gethostname()


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
            [dbc.Col(html.H4(f"Host: {DEFAULT_HOST}"), width=6)],
            className="mb-3",
        ),
        dbc.Row(
            [
                dbc.Col(
                    dbc.Card(
                        dbc.CardBody(
                            [
                                html.H6("Alert Count", className="text-muted"),
                                html.H3(id="host-alert-count"),
                            ]
                        )
                    ),
                    width=3,
                ),
                dbc.Col(
                    dbc.Card(
                        dbc.CardBody(
                            [
                                html.H6("Incident Count", className="text-muted"),
                                html.H3(id="host-incident-count"),
                            ]
                        )
                    ),
                    width=3,
                ),
            ],
            className="mb-4",
        ),
        dbc.Row(
            [
                dbc.Col(
                    dbc.Card(
                        dbc.CardBody(
                            [
                                html.H5("Baseline vs Current"),
                                dcc.Graph(id="baseline-vs-current-chart"),
                            ]
                        )
                    ),
                    width=12,
                ),
            ],
            className="mb-4",
        ),
        dbc.Row(
            [
                dbc.Col(
                    dbc.Card(
                        dbc.CardBody(
                            [
                                html.H5("Recent Feature Windows"),
                                dcc.Graph(id="feature-windows-chart"),
                            ]
                        )
                    ),
                    width=12,
                ),
            ],
        ),
    ],
)


@callback(
    [
        Output("host-alert-count", "children"),
        Output("host-incident-count", "children"),
        Output("baseline-vs-current-chart", "figure"),
    ],
    Input("refresh-interval", "n_intervals"),
)
def update_host(_):
    data = _safe_get(f"{API}/hosts/{DEFAULT_HOST}", {})
    alert_count = data.get("alert_count", 0)
    incident_count = data.get("incident_count", 0)

    baseline = data.get("baseline") or {}
    current = data.get("current_features") or {}

    keys = [k for k in baseline.keys() if k != "unusual_hour_flag"] if baseline else []
    if not keys and current:
        keys = [k for k in current.keys() if k != "unusual_hour_flag"]

    fig = go.Figure()
    if keys:
        fig.add_trace(
            go.Bar(
                name="Baseline",
                x=keys,
                y=[baseline.get(k, 0) for k in keys],
                marker_color="#3498db",
            )
        )
        fig.add_trace(
            go.Bar(
                name="Current",
                x=keys,
                y=[current.get(k, 0) for k in keys],
                marker_color="#e74c3c",
            )
        )
    fig.update_layout(
        barmode="group",
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=40, r=20, t=20, b=80),
    )
    return str(alert_count), str(incident_count), fig


@callback(
    Output("feature-windows-chart", "figure"),
    Input("refresh-interval", "n_intervals"),
)
def update_feature_windows(_):
    windows = _safe_get(f"{API}/features?limit=60&host_id={DEFAULT_HOST}", [])
    fig = go.Figure()
    if windows:
        times = [w["window_end"] for w in reversed(windows)]
        for metric in [
            "outbound_conn_count",
            "unique_dest_ips",
            "new_process_count",
            "failed_login_count",
        ]:
            fig.add_trace(
                go.Scatter(
                    x=times,
                    y=[w.get(metric, 0) for w in reversed(windows)],
                    mode="lines",
                    name=metric.replace("_", " ").title(),
                )
            )
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=40, r=20, t=20, b=40),
        xaxis_title="Time",
        yaxis_title="Value",
    )
    return fig
