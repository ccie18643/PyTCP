#!/bin/bash
PY_PATH="*.py service/*.py client/*.py misc/*.py ether/*.py arp/*.py ip4/*.py ip6/*.py icmp4/*.py icmp6/*.py tcp/*.py udp/*.py dhcp4/*.py"
codespell -w --ignore-words-list="ect,ether,nd,tha" --quiet-level=2 ${PY_PATH} README.md
pyupgrade --py36-plus ${PY_PATH}
isort --profile black ${PY_PATH}
black -l 160 ${PY_PATH}
flake8 ${PY_PATH}
