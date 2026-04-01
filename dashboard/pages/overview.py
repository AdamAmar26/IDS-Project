import os
import dash
from dash import html, dcc, callback, Output, Input, dash_table
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import requests

dash.register_page(__name__, path="/", name="Overview")

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
                dbc.Col(
                    dbc.Card(
                        dbc.CardBody(
                            [
                                html.H6("Total Alerts", className="text-muted"),
                                html.H3(id="metric-total-alerts"),
                            ]
                        )
                    ),
                    width=3,
                ),
                dbc.Col(
                    dbc.Card(
                        dbc.CardBody(
                            [
                                html.H6("Active Incidents", className="text-muted"),
                                html.H3(id="metric-active-incidents"),
                            ]
                        )
                    ),
                    width=3,
                ),
                dbc.Col(
                    dbc.Card(
                        dbc.CardBody(
                            [
                                html.H6("Anomaly Rate", className="text-muted"),
                                html.H3(id="metric-anomaly-rate"),
                            ]
                        )
                    ),
                    width=3,
                ),
                dbc.Col(
                    dbc.Card(
                        dbc.CardBody(
                            [
                                html.H6("Model Status", className="text-muted"),
                                html.H3(id="metric-model-status"),
                            ]
                        )
                    ),
                    width=3,
                ),
            ],
            className="mb-3",
        ),
        # Training progress bar (visible only while training)
        dbc.Row(
            [
                dbc.Col(
                    html.Div(id="training-progress-container"),
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
                                html.H5("Anomaly Score Trend"),
                                dcc.Graph(id="anomaly-trend-chart"),
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
                                html.H5("Recent Alerts"),
                                dash_table.DataTable(
                                    id="recent-alerts-table",
                                    columns=[
                                        {"name": "ID", "id": "id"},
                                        {"name": "Host", "id": "host_id"},
                                        {"name": "Score", "id": "anomaly_score"},
                                        {"name": "Anomaly", "id": "is_anomaly"},
                                        {"name": "Time", "id": "created_at"},
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
                                    page_size=10,
                                ),
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
        Output("metric-total-alerts", "children"),
        Output("metric-active-incidents", "children"),
        Output("metric-anomaly-rate", "children"),
        Output("metric-model-status", "children"),
        Output("training-progress-container", "children"),
    ],
    Input("refresh-interval", "n_intervals"),
)
def update_metrics(_):
    m = _safe_get(f"{API}/metrics", {})
    total = m.get("total_alerts", 0)
    active = m.get("active_incidents", 0)
    rate = m.get("anomaly_rate", 0)
    trained = m.get("model_trained", False)
    samples = m.get("training_samples", 0)
    min_samples = m.get("min_training_samples", 20)
    sec_log = m.get("security_log_available", False)

    if trained:
        status = "Trained"
        progress = html.Div()
    else:
        status = f"Training ({samples}/{min_samples})"
        pct = min(100, int(samples / max(min_samples, 1) * 100))
        children = [
            dbc.Progress(
                value=pct,
                label=f"{pct}%",
                color="info",
                striped=True,
                animated=True,
                className="mb-2",
            ),
            html.Small(
                f"Collecting baseline: {samples} / {min_samples} windows. "
                f"Detection activates once complete.",
                className="text-muted",
            ),
        ]
        if not sec_log:
            children.append(
                dbc.Alert(
                    "Security event log not accessible — run as Administrator "
                    "for full login telemetry.",
                    color="warning",
                    className="mt-2 mb-0 py-2",
                )
            )
        progress = html.Div(children)

    return str(total), str(active), f"{rate:.1%}", status, progress


@callback(
    Output("anomaly-trend-chart", "figure"),
    Input("refresh-interval", "n_intervals"),
)
def update_trend(_):
    alerts = _safe_get(f"{API}/alerts?limit=200", [])
    fig = go.Figure()
    if alerts:
        times = [a["created_at"] for a in reversed(alerts)]
        scores = [a["anomaly_score"] for a in reversed(alerts)]
        fig.add_trace(
            go.Scatter(
                x=times,
                y=scores,
                mode="lines+markers",
                name="Anomaly Score",
                line=dict(color="#e74c3c"),
            )
        )
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=40, r=20, t=20, b=40),
        xaxis_title="Time",
        yaxis_title="Anomaly Score",
    )
    return fig


@callback(
    Output("recent-alerts-table", "data"),
    Input("refresh-interval", "n_intervals"),
)
def update_alerts_table(_):
    return _safe_get(f"{API}/alerts?limit=20", [])
