import dash
from dash import dcc, html, dash_table
import plotly.express as px
import pandas as pd

# Load or simulate your anomaly log data
df = pd.read_csv('Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv') 

app = dash.Dash(__name__)

app.layout = html.Div([
    html.H1("Cybersecurity Intelligence Dashboard"),
    html.Div([
        html.Div([
            dcc.Graph(id='traffic-over-time', figure=px.line(df, x=' Flow Duration', y=' Total Fwd Packets', title='Network Traffic Over Time')),
            dcc.Graph(id='anomaly-severity', figure=px.pie(df, names=' Flow Duration', title='Anomaly Severity Distribution')),
        ], style={'width': '48%', 'display': 'inline-block'}),
        html.Div([
            dcc.Graph(id='top-ips', figure=px.bar(df, x=' Flow Duration', y=' Total Fwd Packets', title='Top Source IPs')),
            dcc.Graph(id='geo-map', figure=px.scatter_geo(df, lat=' Flow Duration', lon=' Total Fwd Packets', color=' Label', title='Attack Geolocation')),
        ], style={'width': '48%', 'display': 'inline-block', 'float': 'right'}),
    ]),
    html.H2("Recent Security Incidents"),
    dash_table.DataTable(
        id='incident-table',
        columns=[{"name": i, "id": i} for i in df.columns],
        data=df.to_dict('records'),
        filter_action="native",
        sort_action="native",
        page_size=10,
        style_table={'overflowX': 'auto'},
    ),
])

if __name__ == '__main__':
    app.run(debug=True)

