"""Local Dash dashboard with live SQLite updates, dataset replay, and measured model results."""
import argparse
import atexit
import json
from datetime import datetime, timezone, timedelta
import pandas as pd
import plotly.graph_objects as go
from dash import Dash, dcc, html, dash_table, Input, Output, State, ctx, no_update
from flask import jsonify, Response, abort
from bot.config import ROOT, FEATURES
from bot.model import Detector
from bot.replay import ReplayController
from bot.storage import EventStore

IST = timezone(timedelta(hours=5, minutes=30))
TEAL, CORAL, GRID = '#087f74', '#d96b50', '#e8eef0'


def local_time(value):
    if not value:
        return '—'
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(IST).strftime('%H:%M:%S')


def chart_layout(figure, height=280, **extra):
    figure.update_layout(template='plotly_white', height=height, paper_bgcolor='white',
                         plot_bgcolor='white', font=dict(family='Segoe UI, Arial', color='#577177', size=11),
                         margin=dict(l=45, r=20, t=20, b=45), hovermode='closest',
                         legend=dict(orientation='h', y=1.14, x=0), **extra)
    figure.update_xaxes(gridcolor=GRID, zeroline=False)
    figure.update_yaxes(gridcolor=GRID, zeroline=False)
    return figure


def traffic_chart(snapshot):
    rows = snapshot['timeline']
    fig = go.Figure()
    if rows:
        x = [datetime.fromisoformat(r['time']).replace(tzinfo=timezone.utc).astimezone(IST).replace(tzinfo=None) for r in rows]
        fig.add_trace(go.Scatter(x=x, y=[r['total'] for r in rows], name='Processed flows',
                                mode='lines', line=dict(color=TEAL, width=2.5), fill='tozeroy',
                                fillcolor='rgba(8,127,116,.08)'))
        fig.add_trace(go.Scatter(x=x, y=[r['flagged'] for r in rows], name='Flagged flows',
                                mode='lines', line=dict(color=CORAL, width=2)))
    else:
        fig.add_annotation(text='Start a replay or capture to see activity', x=.5, y=.5,
                           xref='paper', yref='paper', showarrow=False)
    chart_layout(fig, xaxis_title='Processing time · IST', yaxis_title='Flows / second')
    fig.update_xaxes(type='date', nticks=5, tickformat='%H:%M:%S', tickangle=0)
    return fig


def profile_chart(snapshot):
    fig = go.Figure()
    for anomaly, name, color in [(0, 'Within baseline', TEAL), (1, 'Flagged', CORAL)]:
        rows = [r for r in snapshot['events'] if r['anomaly'] == anomaly]
        if rows:
            fig.add_trace(go.Scatter(
                x=[max(r['features']['flow_duration_us'] / 1e6, .000001) for r in rows],
                y=[r['features']['fwd_bytes'] + r['features']['bwd_bytes'] for r in rows],
                text=[f"Score {r['score']:.4f}<br>{r['features']['fwd_packets']:.0f} forward / {r['features']['bwd_packets']:.0f} reverse packets" for r in rows],
                name=name, mode='markers', marker=dict(size=6, color=color, opacity=.7),
                hovertemplate='%{text}<br>Duration: %{x:.6f}s<br>Payload: %{y:.0f} bytes<extra></extra>'))
    if not snapshot['events']:
        fig.add_annotation(text='Flow measurements will appear here', x=.5, y=.5,
                           xref='paper', yref='paper', showarrow=False)
    chart_layout(fig, xaxis_title='Flow duration · seconds (log scale)', yaxis_title='Total payload · bytes')
    fig.update_xaxes(type='log')
    return fig


def metric_card(label, value, note, element_id=None, accent=False):
    value_props = {'id': element_id} if element_id else {}
    return html.Div([html.Div(label, className='eyebrow'),
                     html.Div(value, className='metric-value' + (' coral' if accent else ''), **value_props),
                     html.Div(note, className='metric-note')], className='metric-card')


def create_app(detector=None, store=None):
    detector = detector or Detector()
    store = store or EventStore()
    replay = ReplayController(detector, store)
    app = Dash(__name__, assets_folder=str(ROOT / 'assets'), title='Anomaly Bot · Network Monitor',
               update_title=None)
    app.detector, app.store, app.replay = detector, store, replay
    test = detector.report['test']
    matrix = test['confusion_matrix']
    app.layout = html.Div([
        html.Aside([
            html.Div([html.Div('A', className='brand-mark'), html.Div(['ANOMALY', html.Small('DETECTION BOT')])], className='brand'),
            html.Div('WORKSPACE', className='nav-heading'),
            html.A('◉  Network activity', href='#overview', className='nav-link selected'),
            html.A('▦  Model evaluation', href='#evaluation', className='nav-link'),
            html.A('↗  How it works', href='#how-it-works', className='nav-link'),
            html.Div([html.Div('LOCAL WORKSPACE', className='nav-heading'),
                      html.P('Your traffic. Your machine.'), html.Small('Events are saved locally in SQLite.')], className='sidebar-foot'),
        ], className='sidebar'),
        html.Main([
            html.Header([html.Div('CYBERSECURITY / NETWORK MONITOR', className='breadcrumb'),
                         html.Div([html.Span(className='status-dot'), 'Runs locally'], className='local-pill')], className='topbar'),
            html.Div([
                html.Div([html.Div('NETWORK INTELLIGENCE', className='eyebrow teal'),
                          html.H1('Network activity'),
                          html.P('Track unusual flows, inspect the signal, and keep a clear record.', className='subtitle')]),
                html.Div('READY', id='mode-badge', className='mode-badge'),
            ], id='overview', className='page-heading'),
            html.Div([
                html.Div([html.Div('Dataset replay', className='control-title'),
                          html.Small('5,000 held-out CICIDS2017 flows · replay sends no network traffic')], className='control-copy'),
                html.Div([dcc.Dropdown(id='replay-speed', options=[{'label': f'{n} flows / sec', 'value': n} for n in [10,50,100]],
                                       value=50, clearable=False, searchable=False, className='speed-select'),
                          html.Button('▶  Start / resume', id='start-replay', n_clicks=0, className='button primary'),
                          html.Button('Pause', id='pause-replay', n_clicks=0, className='button'),
                          html.Button('Stop', id='stop-replay', n_clicks=0, className='button')], className='control-buttons'),
            ], className='control-panel'),
            html.Div('Ready. Start a dataset replay, or run the packet capture component.', id='command-message', className='command-message', role='status'),
            html.Div([
                html.Div([html.Label('Viewing session', htmlFor='session-picker'),
                          dcc.Dropdown(id='session-picker', options=[{'label':'Latest session', 'value':'latest'}],
                                       value='latest', clearable=False, className='session-select')], className='session-control'),
                html.Div('No flows processed yet', id='session-note', className='session-note'),
            ], className='session-row'),
            html.Div([
                metric_card('PROCESSED FLOWS', '0', 'All flows in this session', 'total-flows'),
                metric_card('FLAGGED FLOWS', '0', 'Unusual activity for review', 'flagged-flows', True),
                metric_card('ALERT RATE', '0.0%', 'Share of processed flows flagged', 'alert-rate'),
                metric_card('INFERENCE / FLOW', '—', 'Average model time; excludes capture', 'latency'),
            ], className='metric-grid'),
            html.Div([
                html.Section([html.Div([html.H2('Activity over time'), html.Span('LAST 120 ACTIVE SECONDS', className='chart-tag')], className='panel-heading'),
                              dcc.Graph(id='traffic-chart', config={'displayModeBar':False}, figure=traffic_chart(store.snapshot()))], className='panel'),
                html.Section([html.Div([html.H2('Flow profile'), html.Span('LATEST 300 FLOWS', className='chart-tag')], className='panel-heading'),
                              dcc.Graph(id='profile-chart', config={'displayModeBar':False}, figure=profile_chart(store.snapshot()))], className='panel'),
            ], className='chart-grid'),
            html.Section([
                html.Div([html.Div([html.H2('Recent flows'), html.P('Inspect predictions alongside the recorded flow measurements.', className='panel-description')]),
                          html.A('↓  Export session', id='export-button', href='/export/latest.csv', className='button')], className='panel-heading table-heading'),
                html.Div('CSV replay contains no IP addresses. Dataset labels are reference values, never model inputs.', id='flow-note', className='table-note'),
                dash_table.DataTable(id='flow-table',
                    columns=[{'name': n, 'id': k} for n,k in [
                        ('Time · IST','time'), ('Prediction','prediction'), ('Score','score'),
                        ('Source','source'), ('Destination','destination'), ('Packets F / B','packets'),
                        ('Duration · ms','duration'), ('Dataset label','label'), ('Baseline context','reason')]],
                    data=[], page_size=8, sort_action='native', filter_action='native',
                    style_table={'overflowX':'auto'},
                    style_header={'backgroundColor':'#f5f8f8','color':'#537077','fontWeight':'600','border':'none','borderBottom':'1px solid #e5ecee'},
                    style_cell={'fontFamily':'Segoe UI, Arial','fontSize':12,'padding':'13px 12px','textAlign':'left',
                                'border':'none','borderBottom':'1px solid #eef2f3','color':'#21454b','minWidth':'85px','maxWidth':'240px',
                                'overflow':'hidden','textOverflow':'ellipsis'},
                    style_data_conditional=[{'if':{'filter_query':'{prediction} = "Flagged"','column_id':'prediction'},
                                             'color':CORAL,'fontWeight':'600'},
                                            {'if':{'filter_query':'{prediction} = "Within baseline"','column_id':'prediction'},
                                             'color':TEAL,'fontWeight':'600'}],
                    tooltip_duration=None, tooltip_data=[]),
                html.Div('An anomaly is a signal to investigate. It does not confirm an attack.', className='table-footer'),
            ], className='panel table-panel'),
            html.Section([
                html.Div([html.Div([html.Div('MEASURED PERFORMANCE',className='eyebrow teal'), html.H2('Model evaluation')]),
                          html.Span('ISOLATION FOREST',className='chart-tag')], className='panel-heading'),
                html.P(f"Untouched test partition · {test['rows']:,} flows · CICIDS2017 Friday DDoS dataset", className='panel-description'),
                html.Div([metric_card('ACCURACY', f"{test['accuracy']:.1%}", 'All correctly classified test flows'),
                          metric_card('PRECISION', f"{test['precision']:.1%}", 'Alerts that match attack labels'),
                          metric_card('RECALL', f"{test['recall']:.1%}", 'Attack flows detected'),
                          metric_card('F1 SCORE', f"{test['f1']:.1%}", 'Balance of precision and recall')], className='evaluation-metrics'),
                html.Div([
                    html.Div([html.H3('Test outcomes'), html.Div([
                        html.Div([html.Small('NORMAL, CORRECT'),html.Strong(f"{matrix['true_normal']:,}")]),
                        html.Div([html.Small('ATTACK, DETECTED'),html.Strong(f"{matrix['detected_attack']:,}")]),
                        html.Div([html.Small('FALSE ALERTS'),html.Strong(f"{matrix['false_alert']:,}")],className='warning-cell'),
                        html.Div([html.Small('MISSED ATTACKS'),html.Strong(f"{matrix['missed_attack']:,}")],className='warning-cell'),
                    ],className='matrix-grid')]),
                    html.Div([html.H3('What these results mean'),
                        html.P('The forest learns from benign training flows. Labeled validation flows set the alert threshold. Identical feature vectors stay in the same split.'),
                        html.P(f"Test false-positive rate: {test['false_positive_rate']:.2%}. Threshold: {detector.threshold:.4f}. Scores are not probabilities."),
                        html.P('These results cover one dataset from one day. Live-network accuracy is unmeasured; packet segmentation approximates CICFlowMeter.',className='limitation'),
                        html.A('Download full evaluation report ↗',href='/evaluation.json',target='_blank',className='text-link'),
                    ],className='evaluation-copy'),
                ],className='evaluation-grid'),
            ],id='evaluation',className='panel evaluation-panel'),
            html.Section([
                html.Div('THE PIPELINE', className='eyebrow teal'), html.H2('How it works'),
                html.Div([html.Div([html.Small('01'),html.Strong('Collect'),html.P('Read dataset flows, a PCAP, or live TCP / UDP packets.')]),
                          html.Div([html.Small('02'),html.Strong('Measure'),html.P('Use the same 11 flow features and log transformation.')]),
                          html.Div([html.Small('03'),html.Strong('Detect'),html.P('Score unusual flows against a learned normal baseline.')]),
                          html.Div([html.Small('04'),html.Strong('Review'),html.P('Save local events, inspect the dashboard, and export evidence.')])],className='pipeline-grid'),
            ],id='how-it-works',className='panel pipeline-panel'),
            html.Footer([html.Span('ANOMALY DETECTION BOT'),html.Span('Local alerts active · Slack is optional in capture mode · Refreshes every second')],className='page-footer'),
            dcc.Interval(id='refresh', interval=1000, n_intervals=0),
        ],className='main-content'),
    ],className='app-shell')

    @app.callback(Output('command-message','children'),
                  Input('start-replay','n_clicks'), Input('pause-replay','n_clicks'), Input('stop-replay','n_clicks'),
                  State('replay-speed','value'), prevent_initial_call=True)
    def control(start, pause, stop, rate):
        try:
            action = ctx.triggered_id
            if action == 'start-replay':
                return replay.start(rate)
            if action == 'pause-replay':
                return replay.pause()
            if action == 'stop-replay':
                return replay.stop()
        except Exception as exc:
            return f'Could not start replay: {exc}'
        return no_update

    @app.callback(
        Output('total-flows','children'),Output('flagged-flows','children'),Output('alert-rate','children'),
        Output('latency','children'),Output('mode-badge','children'),Output('session-note','children'),
        Output('traffic-chart','figure'),Output('profile-chart','figure'),Output('flow-table','data'),
        Output('flow-table','tooltip_data'),Output('session-picker','options'),Output('flow-note','children'),
        Output('export-button','href'),
        Input('refresh','n_intervals'),Input('session-picker','value'))
    def refresh(n, selected):
        snapshot = store.snapshot(None if selected == 'latest' else selected)
        session = snapshot['session']
        rows = []
        for r in snapshot['events']:
            f = r['features']
            rows.append(dict(time=local_time(r['observed_at']),prediction='Flagged' if r['anomaly'] else 'Within baseline',
                             score=round(r['score'],4),source=f"{r['source_ip']}:{r['source_port']}" if r['source_ip'] else 'Unavailable in CSV',
                             destination=f"{r['destination_ip']}:{r['destination_port']}" if r['destination_ip'] else 'Unavailable in CSV',
                             packets=f"{f['fwd_packets']:.0f} / {f['bwd_packets']:.0f}",duration=round(f['flow_duration_us']/1000,3),
                             label=r['dataset_label'] or 'Unlabeled',reason=r['reason']))
        options = [{'label':'Latest session','value':'latest'}] + [
            {'label':f"{local_time(s['started_at'])} · {s['mode']} · {s['status']} · {s['id'][:6]}",'value':s['id']} for s in store.sessions()]
        note = 'No flows processed yet'
        badge = 'READY'
        flow_note = 'CSV replay contains no IP addresses. Dataset labels are reference values, never model inputs.'
        if session:
            badge = f"{session['mode'].upper()} · {session['status'].upper()}"
            note = f"Session {session['id'][:6]} · Started {local_time(session['started_at'])} IST · {session['status']}"
            if session['id'] == replay.session_id:
                note += f' · {replay.cursor:,} / {len(replay.frame):,} replayed'
            if session['error']:
                note += f" · Error: {session['error']}"
            if session['mode'] != 'dataset replay':
                flow_note = 'Source and destination are captured endpoints. Live / PCAP flows have no ground-truth attack labels.'
        return (f"{snapshot['total']:,}", f"{snapshot['flagged']:,}",
                f"{snapshot['flagged']/max(snapshot['total'],1):.1%}",
                f"{snapshot['average_ms']:.2f} ms" if snapshot['total'] else '—',badge,note,
                traffic_chart(snapshot),profile_chart(snapshot),rows,
                [{'reason':{'value':row['reason'],'type':'text'}} for row in rows],options,flow_note,
                f"/export/{session['id']}.csv" if session else '/export/latest.csv')

    @app.server.get('/export/<selected>.csv')
    def export(selected):
        snapshot = store.snapshot(None if selected == 'latest' else selected)
        if not snapshot['session']:
            abort(404,description='Start a replay or capture before exporting a session.')
        records = store.export(snapshot['session']['id'])
        if not records:
            abort(404,description='This session has no recorded flows yet.')
        flattened = []
        for record in records:
            features = json.loads(record.pop('features'))
            # Protect CSV spreadsheet users against formula injection from external labels.
            flattened.append({k: ("'" + v if isinstance(v,str) and v.startswith(('=','+','-','@')) else v)
                              for k,v in {**record,**features}.items()})
        return Response(pd.DataFrame(flattened).to_csv(index=False), mimetype='text/csv',
                        headers={'Content-Disposition':f"attachment; filename=flows-{snapshot['session']['id'][:6]}.csv"})

    @app.server.get('/health')
    def health():
        return jsonify(status='ok', model_loaded=True, feature_count=len(FEATURES))

    @app.server.get('/evaluation.json')
    def evaluation():
        return jsonify(detector.report)

    @app.server.get('/api/snapshot')
    def snapshot_api():
        return jsonify(store.snapshot())

    atexit.register(replay.stop)
    return app


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=8050)
    args = parser.parse_args()
    try:
        app = create_app()
        app.run(host='127.0.0.1',port=args.port,debug=False,use_reloader=False)
    except (FileNotFoundError,ValueError) as exc:
        parser.exit(1, f'{exc}\n')
