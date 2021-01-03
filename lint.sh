#!/bin/bash
PY_PATH=$(find . -name '*.py')
codespell -w --ignore-words-list="ect,ether,nd,tha" --quiet-level=2 ${PY_PATH} README.md
isort --profile black ${PY_PATH}
black -l 160 ${PY_PATH}
flake8 ${PY_PATH}
mypy ${PY_PATH}
