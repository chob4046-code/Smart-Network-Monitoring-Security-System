import threading
import time
from pathlib import Path

from flask import Flask

from .config import Config
from .db import init_db


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["DB_PATH"]).parent.mkdir(parents=True, exist_ok=True)

    with app.app_context():
        init_db(app.config["DB_PATH"], app.config["ADMIN_PASSWORD"])

    from .routes import bp
    app.register_blueprint(bp)

    if not app.config.get("TESTING"):
        thread = threading.Thread(target=_monitor_loop, args=(app,), daemon=True)
        thread.start()

    return app


def _monitor_loop(app):
    from .monitor import run_monitor_cycle

    while True:
        try:
            with app.app_context():
                run_monitor_cycle(app.config["DB_PATH"], app.config["CONNECT_TIMEOUT"])
        except Exception:
            app.logger.exception("monitor cycle failed")
        time.sleep(app.config["CHECK_INTERVAL"])
