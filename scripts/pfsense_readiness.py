"""Operator-invoked, GET-only pfREST check. The application does not invoke this script."""

import argparse
import json
import logging
import sys
from dataclasses import asdict

from src.response_adapters import PfSenseAdapter, PfSenseReadError
from src.settings import Settings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-ip", required=True, help="Authorized lab IPv4 address")
    args = parser.parse_args()
    # HTTP wire diagnostics can contain untrusted response headers.
    logging.disable(logging.CRITICAL)
    try:
        settings = Settings.from_env()
        if settings.pfsense_live_enabled or settings.response_mode == "pfsense":
            raise ValueError
        observed = PfSenseAdapter(settings).observe(args.source_ip)
    except PfSenseReadError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except ValueError:
        print("Invalid pfSense read-only settings or unauthorized target", file=sys.stderr)
        return 1
    print(json.dumps({**asdict(observed), "traffic_verified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
