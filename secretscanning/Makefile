all: requirements lint
.PHONY: lint requirements

requirements:
	sudo apt-get -qq install libpcre3-dev
	python3 -m pip install -r requirements.txt > /dev/null 

lint:
	python3 -m pip install -r dev-requirements.txt > /dev/null
	python3 -m black test.py
	ruff --ignore=E501 test.py
	python3 -m flake8 --ignore=E501,W504,E124,E203,W503 test.py
	-yes | python3 -m mypy --install-types
	python3 -m mypy --no-error-summary --ignore-missing-imports --strict test.py
	python3 -m bandit --quiet test.py # --configfile bandit.yml

