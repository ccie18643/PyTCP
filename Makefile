PYTHON_VERSION := 3.10
VENV := venv
ROOT_PATH:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
PYTCP_PATH := pytcp
TESTS_PATH := tests
EXAMPLES_PATH := examples
PYTCP_FILES := $(shell find ${PYTCP_PATH} -name '*.py')
TEST_FILES := $(shell find ${TESTS_PATH} -name '*.py')
EXAMPLES_FILES := $(shell find ${EXAMPLES_PATH} -name '*.py')

$(VENV)/bin/activate: requirements.txt
	@python$(PYTHON_VERSION) -m venv $(VENV)
	@echo "export PYTHONPATH=$(ROOT_PATH)" >> venv/bin/activate
	@./$(VENV)/bin/python3 -m pip install --upgrade pip
	@./$(VENV)/bin/pip install -r requirements.txt

venv: $(VENV)/bin/activate

run: venv
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python3 examples/run_stack.py

clean:
	@rm -rf $(VENV)
	@rm -rf dist
	@rm -rf tcp_ip_stack.egg-info
	@find . -type d -name '__pycache__' -exec rm -rf {} +

lint: venv
	@echo '<<< CODESPELL'
	@./$(VENV)/bin/codespell --write-changes ${PYTCP_FILES} ${TEST_FILES} ${EXAMPLES_FILES}
	@echo '<<< ISORT'
	@./$(VENV)/bin/isort ${PYTCP_FILES} ${TEST_FILES} ${EXAMPLES_FILES}
	@echo '<<< BLACK'
	@./$(VENV)/bin/black ${PYTCP_FILES} ${TEST_FILES} ${EXAMPLES_FILES}
	@echo '<<< FLAKE8'
	@./$(VENV)/bin/flake8 ${PYTCP_FILES} ${TEST_FILES} ${EXAMPLES_FILES}
	@echo '<<< MYPY'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/mypy -p ${PYTCP_PATH}
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/mypy -p ${EXAMPLES_PATH}

test_unit: venv
	@echo '<<< TESTSLIDE UNIT'
	@./$(VENV)/bin/testslide tests/unit/*.py

test_integration: venv
	@echo '<<< TESTSLIDE INTEGRATION'
	@./$(VENV)/bin/testslide tests/integration/*.py

test: test_unit test_integration

bridge:
	@brctl addbr br0

install: venv
	@./$(VENV)/bin/pip install -e .

package: venv
	@./$(VENV)/bin/python -m build

dist: package

pypi: dist
	@./$(VENV)/bin/twine check dist/*
	@./$(VENV)/bin/twine upload dist/*

tap:
	@ip tuntap add name tap7 mode tap
	@ip link set dev tap7 up
	@brctl addif br0 tap7
	@echo 'Interface tap7 created and added to bridge br0'

.PHONY: all venv run clean lint bridge tap
