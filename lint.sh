#!/bin/bash
pyupgrade --py36-plus *py
isort --profile black *.py
black -l 160 *.py
flake8 *.py
