#!/bin/bash
PY_PATH=$(find . -name '*.py')
echo '<<< CODESPELL' && \
codespell -w --ignore-words-list="ect,ether,nd,tha" --quiet-level=2 ${PY_PATH} README.md && \
echo '<<< ISORT' && \
isort --profile black ${PY_PATH} && \
echo '<<< BLACK' && \
black ${PY_PATH} && \
echo '<<< FLAKE8' && \
flake8 ${PY_PATH} && \
echo '<<< MYPY' && \
mypy ${PY_PATH}
