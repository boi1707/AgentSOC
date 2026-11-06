PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
COMPOSE ?= docker compose
SERVICE := agentsoc-backend

.PHONY: setup test lint up down logs health replay leaks eval demo demo-down frontend local
setup:
	bash scripts/setup.sh
test:
	$(PYTHON) -m pytest -q
lint:
	$(PYTHON) -m ruff check src scripts tests
	$(PYTHON) -m ruff format --check src scripts tests
up:
	$(COMPOSE) up -d --build --wait
down:
	$(COMPOSE) down
logs:
	$(COMPOSE) logs --tail=100 -f
health:
	$(COMPOSE) exec -T $(SERVICE) python -c "import json,urllib.request; print(json.dumps(json.load(urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=5)), indent=2))"
replay:
	docker compose -f docker-compose.demo.yml exec -T api python -m scripts.replay /app/datasets/demo.jsonl --url http://127.0.0.1:8000 --fresh $(ARGS)
leaks:
	$(COMPOSE) exec -T $(SERVICE) python -m scripts.check_leaks $(ARGS)
eval:
	$(COMPOSE) exec -T $(SERVICE) python -m scripts.metrics $(ARGS)
demo:
	docker compose -f docker-compose.demo.yml up -d --build --wait
demo-down:
	docker compose -f docker-compose.demo.yml down
frontend:
	cd frontend && npm ci && npm run build
local:
	$(PYTHON) -m scripts.dev --build
