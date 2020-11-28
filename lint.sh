#!/bin/bash
isort *.py
black *.py
flake8 *.py
