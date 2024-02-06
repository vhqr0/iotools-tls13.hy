.PHONY: build
build:
	poetry build

.PHONY: test
test:
	poetry run python -B -m unittest tests -v
