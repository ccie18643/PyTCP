VENV := venv
ROOT_PATH:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
PYTCP_PATH := packages/pytcp/pytcp
NET_ADDR_PATH := packages/net_addr/net_addr
NET_PROTO_PATH := packages/net_proto/net_proto
EXAMPLES_PATH := examples_legacy
PYTCP_FILES := $(shell find ${PYTCP_PATH} -name '*.py')
NET_ADDR_FILES := $(shell find ${NET_ADDR_PATH} -name '*.py')
NET_PROTO_FILES := $(shell find ${NET_PROTO_PATH} -name '*.py')
EXAMPLES_FILES := $(shell find ${EXAMPLES_PATH} -name '*.py')
ROOT_FILES := tests_runner.py

# Every linted file in one list (codespell / isort / black / flake8
# all accept many paths at once), plus the packages mypy checks in
# '-p' package mode.
LINT_FILES := $(PYTCP_FILES) $(NET_ADDR_FILES) $(NET_PROTO_FILES) $(EXAMPLES_FILES) $(ROOT_FILES)
# mypy '-p' takes import names, not paths. net_addr now lives at
# packages/net_addr/net_addr (resolved via its editable install in
# the 'venv' target), so its name is decoupled from its path here.
MYPY_PACKAGES := pytcp net_addr net_proto examples_legacy

# The entire pylint configuration — which checks fire AND which paths
# are exempt — lives in pyproject.toml ([tool.pylint.*]: 'disable = all'
# + a small 'enable' allowlist, and 'ignore-paths' for tests). It is the
# single source of truth shared with ad-hoc / IDE pylint runs. The gate
# below just hands pylint the three package roots and lets config decide
# the rest ('--recursive=y' so pylint walks the tree; tests self-exempt
# via 'ignore-paths').

# If any recipe fails, delete its target file. Without this a
# failed (or interrupted) 'venv' build leaves a half-populated
# venv whose 'bin/activate' is newer than the requirements
# files, so every later 'make' considers the venv up to date
# and never reinstalls — the exact reason a package listed in
# requirements_dev.txt could be missing from the venv.
.DELETE_ON_ERROR:

# 'venv/bin/activate' is the timestamp marker for the venv. It
# is rebuilt whenever either requirements file is newer. The
# rebuild is from a clean slate ('rm -rf') so a stale or
# half-built venv cannot survive, and the marker is 'touch'ed
# only as the LAST step so its mtime reflects a fully
# successful install — not venv-dir creation, which would
# stamp it before pip ran.
$(VENV)/bin/activate: requirements.txt requirements_dev.txt
	@rm -rf $(VENV)
	@python3.14 -m venv $(VENV)
	@echo "export PYTHONPATH=$(ROOT_PATH)" >> $(VENV)/bin/activate
	@./$(VENV)/bin/python -m pip install --upgrade pip
	@./$(VENV)/bin/pip install -r requirements.txt
	@./$(VENV)/bin/pip install -r requirements_dev.txt
	@./$(VENV)/bin/pip install -e packages/net_addr --config-settings editable_mode=compat
	@./$(VENV)/bin/pip install -e packages/net_proto --config-settings editable_mode=compat
	@./$(VENV)/bin/pip install -e packages/pytcp --config-settings editable_mode=compat
	@touch $(VENV)/bin/activate

venv: $(VENV)/bin/activate

run: venv
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python3 examples_legacy/stack.py

# Run as a daemon: the stack plus its AF_UNIX control socket, so
# out-of-process 'pytcp.client' consumers (e.g. examples_legacy/client__*_ipc.py)
# can open sockets and drive the control APIs against this running stack.
# Needs the bridge + TAP first ('sudo make bridge && sudo make tap7').
daemon: venv
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python3 examples_legacy/stack.py --ipc-socket /tmp/pytcp.sock

# Bind the stack to two TAP interfaces at once (multi-homed host). Needs
# the bridge + both taps up first: 'sudo make bridge tap7 tap9'. Each NIC
# autoconfigures (DHCPv4 / SLAAC).
run_multi: venv
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python3 examples_legacy/stack.py --stack-interface tap7 --stack-interface tap9

# Run the stack on a point-to-point TUN interface (no bridge). Needs the
# matching tun device first ('sudo make tun3' / 'sudo make tun5'); each is
# created pre-addressed on the host side, so the stack takes the .2 host
# in the same subnet.
run_tun: venv
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python3 examples_legacy/stack.py --stack-interface tun3 --stack-ip4-address 172.16.1.2/24 --stack-ip6-address 2001:db8:1::2/64

run_tun5: venv
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python3 examples_legacy/stack.py --stack-interface tun5 --stack-ip4-address 172.16.2.2/24 --stack-ip6-address 2001:db8:2::2/64

# Run an example-capture / e2e scenario. Needs root + the TAP/bridge
# (sudo make bridge && sudo make tap7). Usage:
#   sudo make capture SCENARIO=ip6-tcp-monkeys
#   sudo make capture SCENARIO=ip4-udp-monkeys CAPTURE_ARGS="--payload malpa --raw"
# With no SCENARIO it prints the list of scenarios.
SCENARIO ?=
CAPTURE_ARGS ?=
capture: venv
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python -m tools.capture $(SCENARIO) $(CAPTURE_ARGS)

clean:
	@rm -rf $(VENV)
	@rm -rf dist tcp_ip_stack.egg-info PyTCP.egg-info
	@rm -rf .mypy_cache .pytest_cache .pyre
	@find . -type d -name '__pycache__' -exec rm -rf {} +

lint: venv
	@echo '<<< CODESPELL'
	@./$(VENV)/bin/codespell --write-changes $(LINT_FILES)
	@echo '<<< ISORT'
	@./$(VENV)/bin/isort $(LINT_FILES)
	@echo '<<< BLACK'
	@./$(VENV)/bin/black $(LINT_FILES)
	@echo '<<< FLAKE8'
	@./$(VENV)/bin/flake8 $(LINT_FILES)
	@echo '<<< MYPY'
	@for pkg in $(MYPY_PACKAGES); do PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/mypy -p $$pkg || exit 1; done
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/mypy $(ROOT_FILES)
	@echo '<<< PYLINT'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/pylint --score=n --recursive=y $(PYTCP_PATH) $(NET_ADDR_PATH) $(NET_PROTO_PATH)
	@echo '<<< PYRIGHT'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/pyright

test__pytcp__integration: venv
	@echo '<<< UNITTEST PYTCP INTEGRATION'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python tests_runner.py $(shell find 'packages/pytcp/pytcp/tests/integration' -name 'test__*.py')

test__net_addr__unit: venv
	@echo '<<< UNITTEST NET_ADDR UNIT'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python tests_runner.py $(shell find 'packages/net_addr/net_addr/tests/unit' -name 'test__*.py')

test__net_proto__unit: venv
	@echo '<<< UNITTEST NET_PROTO UNIT'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python tests_runner.py $(shell find 'packages/net_proto/net_proto/tests/unit' -name 'test__*.py')

test__examples__unit: venv
	@echo '<<< UNITTEST EXAMPLES UNIT'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python tests_runner.py $(shell find 'examples_legacy/tests/unit' -name 'test__*.py')

test: venv
	@echo '<<< UNITTEST ALL'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python tests_runner.py $(shell find 'packages/net_addr/net_addr/tests' 'packages/net_proto/net_proto/tests' 'packages/pytcp/pytcp/tests' 'examples_legacy/tests' -name 'test__*.py')

validate: lint test

# RX-ring micro-benchmark — measures per-frame overhead of the
# 'select() + os.read() + queue.put()' loop. Run twice (once with
# '-O' to strip __debug__/asserts, once without) and compare.
bench__rx_ring: venv
	@echo '<<< RX-RING BENCH (default)'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python tools/bench_rx_ring.py
	@echo
	@echo '<<< RX-RING BENCH (-O, __debug__ + asserts stripped)'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python -O tools/bench_rx_ring.py

# Profile RX-ring under cProfile, dump top-25 cumulative-time
# entries. Use to find the actual hot spot before deciding whether
# item 5 (RX inner-drain loop) is worth implementing.
profile__rx_ring: venv
	@echo '<<< RX-RING PROFILE (-O)'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python -O -m cProfile \
		-o /tmp/pytcp_rx_ring.prof tools/bench_rx_ring.py \
		--frames 50000 --runs 1
	@./$(VENV)/bin/python -c "import pstats; \
		pstats.Stats('/tmp/pytcp_rx_ring.prof').strip_dirs(\
		).sort_stats('cumulative').print_stats(25)"

# Run the stack in benchmark mode: PYTHONOPTIMIZE=1 strips
# '__debug__'-gated logs / asserts on the hot path, and
# PYTCP_STATS_INTERVAL=5 prints ring + per-protocol counters
# every 5 seconds for live observability under load.
#
# Drive the stack from a SEPARATE terminal with one of the load
# generators below; this target is the receiver side.
benchmark: venv
	@echo 'PyTCP benchmark mode. Drive from another terminal:'
	@echo
	@echo '  sudo hping3 --flood --icmp -d 1472 <stack-ip>'
	@echo
	@PYTCP_STATS_INTERVAL=5 PYTHONOPTIMIZE=1 PYTHONPATH=$(ROOT_PATH) \
		./$(VENV)/bin/python3 examples_legacy/stack.py

bridge:
	@brctl addbr br0

install: venv
	@./$(VENV)/bin/pip install -e packages/pytcp

package: venv
	@./$(VENV)/bin/python -m build packages/pytcp

dist: package

pypi: dist
	@./$(VENV)/bin/twine check packages/pytcp/dist/*
	@./$(VENV)/bin/twine upload packages/pytcp/dist/*

# Build + validate the standalone PyTCP-net_addr dist. Publishing
# is via the OIDC publish.yml workflow on a GitHub Release (no
# local twine upload), mirroring the umbrella PyTCP flow.
build__net_addr: venv
	@./$(VENV)/bin/python -m build packages/net_addr
	@./$(VENV)/bin/twine check packages/net_addr/dist/*

# Build + validate the standalone PyTCP-net_proto dist. Publishing
# is via the OIDC publish.yml workflow on a GitHub Release.
build__net_proto: venv
	@./$(VENV)/bin/python -m build packages/net_proto
	@./$(VENV)/bin/twine check packages/net_proto/dist/*

# Build + validate the PyTCP dist (the dissolved umbrella: the
# pytcp package depending on PyTCP-net_proto + PyTCP-net_addr).
build__pytcp: venv
	@./$(VENV)/bin/python -m build packages/pytcp
	@./$(VENV)/bin/twine check packages/pytcp/dist/*

tun3:
	@ip tuntap add name tun3 mode tun
	@ip addr add 172.16.1.1/24 dev tun3
	@ip -6 addr add 2001:db8:1::1/64 dev tun3
	@ip link set dev tun3 up
	@echo 'Interface tun3 created and assigned 2001:db8:1::1/64 and 172.16.1.1/24 addresses.'

tun5:
	@ip tuntap add name tun5 mode tun
	@ip addr add 172.16.2.1/24 dev tun5
	@ip -6 addr add 2001:db8:2::1/64 dev tun5
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

add_interfaces: tun3 tun5 tap7 tap9

remove_interfaces:
	@ip tuntap del name tun3 mode tun
	@ip tuntap del name tun5 mode tun
	@ip tuntap del name tap7 mode tap
	@ip tuntap del name tap9 mode tap

.PHONY: venv run daemon run_multi run_tun capture clean lint \
	test test__pytcp__integration test__net_addr__unit \
	test__net_proto__unit test__examples__unit validate \
	bench__rx_ring profile__rx_ring benchmark \
	bridge install package dist pypi build__net_addr build__net_proto build__pytcp \
	tun3 tun5 tap7 tap9 add_interfaces remove_interfaces
