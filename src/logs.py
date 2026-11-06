"""JSON operational logs. Prompts and exception messages never enter the log."""

import json
import logging
import sys
import traceback
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .anon import Anon


class JsonFormatter(logging.Formatter):
    def __init__(self, settings):
        super().__init__()
        self.hosts = settings.hosts
        self.secrets = tuple(
            v
            for v in (
                settings.ingest_key,
                settings.approve_key,
                settings.llm_key,
                settings.tg_token,
                settings.tg_chat,
                settings.admin_password,
            )
            if v
        )

    def format(self, record):
        row = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "event": record.getMessage(),
            "case_id": getattr(record, "case_id", None),
            **getattr(record, "details", {}),
        }
        if record.exc_info:
            row["error_type"] = record.exc_info[0].__name__
            # Stack locations without source, exception values, or frame locals.
            row["traceback"] = [
                {"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                for frame in traceback.extract_tb(record.exc_info[2])
            ]

        def scrub(value):
            if isinstance(value, str):
                for secret in self.secrets:
                    value = value.replace(secret, "[REDACTED]")
                return value
            if isinstance(value, dict):
                return {scrub(str(k)): scrub(v) for k, v in value.items()}
            if isinstance(value, (list, tuple)):
                return [scrub(v) for v in value]
            return value

        return json.dumps(Anon(self.hosts).obj(scrub(row)), ensure_ascii=False, default=str)


def configure_logging(settings):
    logger = logging.getLogger("agentsoc")
    logger.setLevel(settings.log_level)
    logger.propagate = False
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()
    folder = Path(settings.db).parent / "logs"
    folder.mkdir(parents=True, exist_ok=True)
    formatter = JsonFormatter(settings)
    for handler in (
        logging.StreamHandler(sys.stdout),
        RotatingFileHandler(
            folder
            / ("agentsoc-" + settings.log_component + ".log" if settings.log_component else "agentsoc.log"),
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        ),
    ):
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger
