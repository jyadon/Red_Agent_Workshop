.PHONY: install bootstrap-config dev dev-front dev-agent build lint clean create-user list-users reset-password

# Load variables from `.env` if present and export them to recipe shells, so
# FRONTEND_PORT / AGENT_PORT etc. resolve via `$${VAR:-default}`.
# Source must be plain KEY=VALUE form (no quoting / shell expansion).
ifneq (,$(wildcard .env))
include .env
export
endif

# Auto-source the venv in each target if it exists, so it need not be activated manually.
VENV_DIR ?= venv
VENV_ACTIVATE := $(if $(wildcard $(VENV_DIR)/bin/activate),. $(VENV_DIR)/bin/activate &&,)

install:
	cd front && bun install
	@if [ ! -x $(VENV_DIR)/bin/python ]; then \
		echo "[INFO] $(VENV_DIR)/ not found. Creating it."; \
		python3 -m venv $(VENV_DIR) || { \
			echo "[FATAL] Failed to create the venv. On Kali/Debian: sudo apt install python3-venv"; \
			exit 1; \
		}; \
	fi
	$(VENV_DIR)/bin/pip install -r requirements.txt
	@$(MAKE) --no-print-directory bootstrap-config
	@echo ""
	@echo "[OK] Install complete. Next: set LLM_BASE_URL / LLM_MODEL / LLM_API_KEY in .env, then run 'make dev'."

# Create the runtime config/data files from their samples when missing. Idempotent:
# an existing file is never overwritten, so re-running is safe. SESSION_SIGNING_SECRET
# is deliberately left empty, so a fresh checkout starts with auth disabled (see .env.example).
bootstrap-config:
	@if [ -f .env ]; then \
		echo "[SKIP] .env already exists"; \
	else \
		cp .env.example .env; \
		echo "[NEW ] .env (from .env.example) -- set LLM_BASE_URL / LLM_MODEL / LLM_API_KEY"; \
	fi
	@if [ -f data/findings.json ]; then \
		echo "[SKIP] data/findings.json already exists"; \
	else \
		cp data/findings-sample.json data/findings.json; \
		echo "[NEW ] data/findings.json (from sample) -- replace with real findings when needed"; \
	fi

dev:
	@$(MAKE) -j2 dev-front dev-agent

# Pass `--port` explicitly so Vite listens on the intended port even if vite.config.ts server.port is missed.
dev-front:
	cd front && bun run dev -- --host --port $${FRONTEND_PORT:-5173}

dev-agent:
	@if [ ! -f $(VENV_DIR)/bin/activate ]; then \
		echo ""; \
		echo "[WARN] $(VENV_DIR)/bin/activate not found."; \
		echo "       Attempting to start with the system python."; \
		echo "       To use a venv: python -m venv $(VENV_DIR) && make install"; \
		echo ""; \
	fi
	$(VENV_ACTIVATE) APP_ENV=dev uvicorn agent.main:app --reload --host 0.0.0.0 --port $${AGENT_PORT:-8000}

# Static build (type check + bundle). Used to verify the frontend compiles.
build:
	cd front && bun run build

# Login user management (multi-user operation). e.g. make create-user USER=alice / make list-users
create-user:
	$(VENV_ACTIVATE) python tools/auth/manage_users.py create $(USER)

list-users:
	$(VENV_ACTIVATE) python tools/auth/manage_users.py list

# Reset a login user's password (new password entered interactively, 8+ chars).
# e.g. make reset-password USER=alice
reset-password:
	$(VENV_ACTIVATE) python tools/auth/manage_users.py passwd $(USER)

lint:
	cd front && bun run lint

clean:
	rm -rf front/node_modules
