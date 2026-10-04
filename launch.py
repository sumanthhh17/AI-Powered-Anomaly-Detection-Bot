"""Start the local dashboard and open it in the default browser."""
import importlib.util
import sys
import threading
import webbrowser


def main():
    needed = ['numpy','pandas','sklearn','joblib','dash','plotly','scapy']
    missing = [name for name in needed if importlib.util.find_spec(name) is None]
    if missing:
        print('Missing packages: '+', '.join(missing))
        print('Run SETUP_WINDOWS.cmd once, then START_DASHBOARD.cmd.')
        return 1
    from dashboard import create_app
    try:
        app = create_app()
    except (FileNotFoundError,ValueError) as exc:
        print(exc)
        print('Use the pinned requirements or retrain with python model_training.py.')
        return 1
    threading.Timer(1.5, lambda:webbrowser.open('http://127.0.0.1:8050/')).start()
    print('Keep this window open while using the dashboard. Press Ctrl+C to stop.')
    app.run(host='127.0.0.1',port=8050,debug=False,use_reloader=False)
    return 0


if __name__=='__main__':
    sys.exit(main())
