VENV := venv
PY_PATH := $(shell find pytcp -name '*.py')

all: venv

$(VENV)/bin/activate: requirements.txt
	@apt-get install -y python3-venv
	@python3.9 -m venv $(VENV)
	@./$(VENV)/bin/pip install -r requirements.txt

venv: $(VENV)/bin/activate

run: venv
	@./$(VENV)/bin/python3 pytcp/pytcp.py

clean:
	@rm -rf $(VENV)
	@find . -type d -name '__pycache__' -exec rm -rf {} +

lint: venv
	@echo '<<< CODESPELL'
	@./$(VENV)/bin/codespell -w --ignore-words-list="ect,ether,nd,tha" --quiet-level=2 ${PY_PATH} README.md
	@echo '<<< ISORT'
	@./$(VENV)/bin/isort --profile black ${PY_PATH}
	@echo '<<< BLACK'
	@./$(VENV)/bin/black ${PY_PATH}
	@echo '<<< FLAKE8'
	@./$(VENV)/bin/flake8 ${PY_PATH}
	@echo '<<< MYPY'
	@cd pytcp; ../$(VENV)/bin/mypy -p pytcp; cd -

test: venv
	@echo '<<< TESTSLIDE'
	@./$(VENV)/bin/testslide tests/test_*.py

.PHONY: all venv run clean lint
