#!/bin/bash
isort --profile black *.py
black -l 160 *.py
flake8 *.py
