import dash
import dash_bootstrap_components as dbc
from dash import html, dcc

app = dash.Dash(
    __name__,
    use_pages=True,
    external_stylesheets=[dbc.themes.DARKLY],
    suppress_callback_exceptions=True,
)

app.layout = dbc.Container(
    [
        dbc.NavbarSimple(
            brand="IDS - Intrusion Detection Platform",
            brand_href="/",
            color="dark",
            dark=True,
            children=[
                dbc.NavItem(dbc.NavLink("Overview", href="/")),
                dbc.NavItem(dbc.NavLink("Host Detail", href="/host-detail")),
                dbc.NavItem(dbc.NavLink("Incidents", href="/incident-detail")),
                dbc.NavItem(dbc.NavLink("Telemetry", href="/telemetry-explorer")),
            ],
        ),
        html.Div(className="mt-3"),
        dash.page_container,
        dcc.Interval(id="refresh-interval", interval=10_000, n_intervals=0),
    ],
    fluid=True,
)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8050)
