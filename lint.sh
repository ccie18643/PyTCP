#!/bin/bash
PY_PATH="./*.py ./fpp/*.py ./fpa/*.py"
codespell -w --ignore-words-list="ect,ether,nd,tha" --quiet-level=2 ${PY_PATH}
pyupgrade --py36-plus ${PY_PATH}
isort --profile black ${PY_PATH}
black -l 160 ${PY_PATH}
flake8 ${PY_PATH}
