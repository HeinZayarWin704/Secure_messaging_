.PHONY: install test lint

install:
	pip install -e .[test]

test:
	pytest
