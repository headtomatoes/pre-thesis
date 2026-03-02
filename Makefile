.PHONY: all build-bpf build-go clean test ml-train ml-export

# ──────────────────────────────────────────────
# Top-level Makefile
# ──────────────────────────────────────────────

BINARY   := bin/controller
GO_SRC   := ./cmd/controller
BPF_DIR  := bpf
ML_DIR   := ml

all: build-bpf build-go

# ── BPF ──────────────────────────────────────
build-bpf:
	$(MAKE) -C $(BPF_DIR)

# ── Go Controller ────────────────────────────
build-go: build-bpf
	@mkdir -p bin
	CGO_ENABLED=1 go build -o $(BINARY) $(GO_SRC)

run: build-go
	sudo $(BINARY) --config configs/config.yaml

# ── Python ML Pipeline ──────────────────────
ml-setup:
	cd $(ML_DIR) && python3 -m venv .venv && \
		. .venv/bin/activate && pip install -r requirements.txt

ml-train:
	cd $(ML_DIR) && . .venv/bin/activate && \
		python3 scripts/preprocess.py && \
		python3 scripts/train.py

ml-export:
	cd $(ML_DIR) && . .venv/bin/activate && \
		python3 scripts/export_onnx.py

# ── Testing ──────────────────────────────────
test:
	go test -v ./tests/...

test-ml:
	cd $(ML_DIR) && . .venv/bin/activate && \
		python3 -m pytest scripts/ -v

# ── Deployment ───────────────────────────────
deploy-up:
	cd deployments && docker-compose up -d

deploy-down:
	cd deployments && docker-compose down

# ── Cleanup ──────────────────────────────────
clean:
	$(MAKE) -C $(BPF_DIR) clean
	rm -rf bin/
	rm -rf $(ML_DIR)/.venv
