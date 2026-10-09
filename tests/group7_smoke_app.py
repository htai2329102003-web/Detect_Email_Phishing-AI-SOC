"""Explicit test factory: real auth/DB/graph, injected provider fakes. Never production."""

import os

from src.agents.graph import build_graph
from src.api.routers import analysis
from tests.external_fakes import fake_services
from tests.http_smoke_app import create_app as database_app


def create_app():
    app = database_app()  # Enforces APP_ENV=test and explicit isolated DB path.
    scenario = os.environ["PHISHHUNTER_EXTERNAL_SCENARIO"]
    if scenario not in {"success", "bec", "timeout", "unavailable"}:
        raise ValueError("Unknown external smoke scenario")
    services, iocs = fake_services(scenario)
    analysis.agent = build_graph(ioc_client=iocs, external_services=services)
    return app
