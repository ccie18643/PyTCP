#!/bin/bash
PY_PATH=$(find pytcp -name '*.py')
export $MYPYPATH=pytcp
echo '<<< CODESPELL' && \
codespell -w --ignore-words-list="ect,ether,nd,tha" --quiet-level=2 ${PY_PATH} README.md && \
echo '<<< ISORT' && \
isort --profile black ${PY_PATH} && \
echo '<<< BLACK' && \
black ${PY_PATH} && \
echo '<<< FLAKE8' && \
flake8 ${PY_PATH} && \
echo '<<< MYPY' && \
cd pytcp && mypy -p pytcp && cd - && \
echo '<<< TESTSLIDE' && \
testslide tests/test_*.py
