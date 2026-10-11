"""Run: python -m scripts.build_ioc_index [--source ...] [--index ...]."""

import argparse
import json

from src.config import get_settings
from src.services.ioc_index import build_index


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Build/reuse local exact-match IOC index outside data/")
    parser.add_argument("--source", default=settings.ioc_data_path)
    parser.add_argument("--index", default=settings.ioc_index_path)
    args = parser.parse_args()
    try:
        print(json.dumps(build_index(args.source, args.index), indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
