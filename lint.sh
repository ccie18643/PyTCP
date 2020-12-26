#!/bin/bash
codespell -w --ignore-words-list="ect,ether,nd,tha" --quiet-level=2 *py
pyupgrade --py36-plus *py
isort --profile black *.py
black -l 160 *.py
flake8 *.py
