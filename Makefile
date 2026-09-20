PYTHON ?= .venv/bin/python
PIP = $(PYTHON) -m pip
.PHONY: setup download data train test run redteam redteam-live report lint authorship
setup:
	python3.11 -m venv .venv
	$(PIP) install -r requirements.txt
	$(PIP) install --no-deps -e .
download:
	$(PYTHON) -m src.data.download --fetch
data:
	$(PYTHON) -m src.data.build
train:
	$(PYTHON) -m src.model.train
lint:
	$(PYTHON) -m ruff check src tests
test: lint
	$(PYTHON) -m pytest -q
run:
	$(PYTHON) -m streamlit run src/app.py --server.address 127.0.0.1 --browser.gatherUsageStats false
redteam:
	$(PYTHON) -m src.redteam.run
redteam-live:
	$(PYTHON) -m src.redteam.run --live
report:
	$(PYTHON) -m src.cli batch data/eval_stream.parquet --report
authorship:
	$(PYTHON) -m src.llm.authorship
