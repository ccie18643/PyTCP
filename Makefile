PYTHON_VERSION := 3.12
VENV := venv
ROOT_PATH:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
PYTCP_PATH := pytcp
TESTS_PATH := tests
EXAMPLES_PATH := examples
PYTCP_FILES := $(shell find ${PYTCP_PATH} -name '*.py')
TEST_FILES := $(shell find ${TESTS_PATH} -name '*.py')
EXAMPLES_FILES := $(shell find ${EXAMPLES_PATH} -name '*.py')

$(VENV)/bin/activate: requirements.txt requirements_dev.txt
	@python$(PYTHON_VERSION) -m venv $(VENV)
	@echo "export PYTHONPATH=$(ROOT_PATH)" >> venv/bin/activate
	@./$(VENV)/bin/python3 -m pip install --upgrade pip
	@./$(VENV)/bin/pip install -r requirements.txt
	@./$(VENV)/bin/pip install -r requirements_dev.txt

venv: $(VENV)/bin/activate

run: venv
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python3 examples/run_stack.py

run_tun: venv
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python3 examples/run_stack.py --interface tun7 --ip4-address 10.0.0.2/24

clean:
	@rm -rf $(VENV)
	@rm -rf dist tcp_ip_stack.egg-info PyTCP.egg-info
	@rm -rf .mypy_cache .pytest_cache .pyre
	@find . -type d -name '__pycache__' -exec rm -rf {} +

lint: venv
	@echo '<<< CODESPELL'
	@./$(VENV)/bin/codespell --write-changes ${PYTCP_FILES}
	@./$(VENV)/bin/codespell --write-changes ${TEST_FILES}
	@./$(VENV)/bin/codespell --write-changes ${EXAMPLES_FILES}
	@echo '<<< ISORT'
	@./$(VENV)/bin/isort ${PYTCP_FILES}
	@./$(VENV)/bin/isort ${TEST_FILES}
	@./$(VENV)/bin/isort ${EXAMPLES_FILES}
	@echo '<<< BLACK'
	@./$(VENV)/bin/black ${PYTCP_FILES}
	@./$(VENV)/bin/black ${TEST_FILES}
	@./$(VENV)/bin/black ${EXAMPLES_FILES}
	@echo '<<< FLAKE8'
	@./$(VENV)/bin/flake8 ${PYTCP_FILES}
	@./$(VENV)/bin/flake8 ${TEST_FILES}
	@./$(VENV)/bin/flake8 ${EXAMPLES_FILES}
	@echo '<<< MYPY'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/mypy -p ${PYTCP_PATH}
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/mypy -p ${TESTS_PATH}
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/mypy -p ${EXAMPLES_PATH}

test_legacy_unit: venv
	@echo '<<< TESTSLIDE LEGACY UNIT'
	@./$(VENV)/bin/testslide tests__legacy/unit/*.py

test_legacy_integration: venv
	@echo '<<< TESTSLIDE LEGACY INTEGRATION'
	@./$(VENV)/bin/testslide tests__legacy/integration/*.py

test_legacy: test_legacy_unit test_legacy_integration

test_unit: venv
	@echo '<<< TESTSLIDE UNIT'
	@./$(VENV)/bin/testslide $(shell find 'tests/unit' -name '*.py')

test_integration: venv
	@echo '<<< TESTSLIDE INTEGRATION'
	@./$(VENV)/bin/testslide $(shell find 'tests/integration' -name '*.py')

test: test_unit test_integration

validate: lint test_unit test_legacy

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
	@echo 'Interface tap7 created and added to bridge br0.'

tun:
	@ip tuntap add name tun7 mode tun
	@ip link set dev tun7 up
	@ip addr add 10.0.0.1/24 dev tun7
	@echo 'Interface tun7 created and assigned 10.0.0.1/24 address.'

.PHONY: all venv run clean lint bridge tap tun
