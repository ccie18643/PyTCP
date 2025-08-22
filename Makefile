VENV := venv
ROOT_PATH:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
PYTCP_PATH := pytcp
NET_ADDR_PATH := net_addr
TESTS_PATH := tests
EXAMPLES_PATH := examples
PYTCP_FILES := $(shell find ${PYTCP_PATH} -name '*.py')
NET_ADDR_FILES := $(shell find ${NET_ADDR_PATH} -name '*.py')
TEST_FILES := $(shell find ${TESTS_PATH} -name '*.py')
EXAMPLES_FILES := $(shell find ${EXAMPLES_PATH} -name '*.py')

$(VENV)/bin/activate: requirements.txt requirements_dev.txt
	@python -m venv $(VENV)
	@echo "export PYTHONPATH=$(ROOT_PATH)" >> venv/bin/activate
	@./$(VENV)/bin/python -m pip install --upgrade pip
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
	@./$(VENV)/bin/codespell --write-changes ${NET_ADDR_FILES}
	@./$(VENV)/bin/codespell --write-changes ${TEST_FILES}
	@./$(VENV)/bin/codespell --write-changes ${EXAMPLES_FILES}
	@echo '<<< ISORT'
	@./$(VENV)/bin/isort ${PYTCP_FILES}
	@./$(VENV)/bin/isort ${NET_ADDR_FILES}
	@./$(VENV)/bin/isort ${TEST_FILES}
	@./$(VENV)/bin/isort ${EXAMPLES_FILES}
	@echo '<<< BLACK'
	@./$(VENV)/bin/black ${PYTCP_FILES}
	@./$(VENV)/bin/black ${NET_ADDR_FILES}
	@./$(VENV)/bin/black ${TEST_FILES}
	@./$(VENV)/bin/black ${EXAMPLES_FILES}
	@echo '<<< FLAKE8'
	@./$(VENV)/bin/flake8 ${PYTCP_FILES}
	@./$(VENV)/bin/flake8 ${NET_ADDR_FILES}
	@./$(VENV)/bin/flake8 ${TEST_FILES}
	@./$(VENV)/bin/flake8 ${EXAMPLES_FILES}
	@echo '<<< MYPY'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/mypy -p ${PYTCP_PATH}
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/mypy -p ${NET_ADDR_PATH}
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
	@./$(VENV)/bin/testslide $(shell find 'tests/pytcp/unit' -name '*.py')
	@./$(VENV)/bin/testslide $(shell find 'tests/net_addr/unit' -name '*.py')

test_integration: venv
	@echo '<<< TESTSLIDE INTEGRATION'
	@./$(VENV)/bin/testslide $(shell find 'tests/pytcp/integration' -name '*.py')

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

tun3:
	@ip tuntap add name tun3 mode tun
	@ip addr add 172.16.1.1/24 dev tun3
	@ip -6 addr add 2001:db8:1::1/64 dev tun3
	@ip -6 addr add fe80::1/64 dev tun3
	@ip link set dev tun3 up
	@echo 'Interface tun3 created and assigned 2001:db8:1::1/64 and 172.16.1.1/24 addresses.'

tun5:
	@ip tuntap add name tun5 mode tun
	@ip addr add 172.16.2.1/24 dev tun5
	@ip -6 addr add 2001:db8:2::1/64 dev tun5
	@ip -6 addr add fe80::1/64 dev tun5
	@ip link set dev tun5 up
	@echo 'Interface tun5 created and assigned 2001:db8:2::1/64 and 172.16.2.1/24 addresses.'

tap7:
	@ip tuntap add name tap7 mode tap
	@ip link set dev tap7 up
	@brctl addif br0 tap7
	@echo 'Interface tap7 created and added to bridge br0.'

tap9:
	@ip tuntap add name tap9 mode tap
	@ip link set dev tap9 up
	@brctl addif br0 tap9
	@echo 'Interface tap9 created and added to bridge br0.'


.PHONY: all venv run clean lint bridge tap7 tap9 tun
