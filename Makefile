test:
	@echo "--> Running Python tests"
	py.test tests || exit 1
	@echo ""

develop:
	@echo "--> Installing dependencies"
	pip install --upgrade pip setuptools
	pip install -r requirements.txt
	pip install "file://`pwd`#egg=aspen_ssh[tests]"
	@echo ""

clean:
	@echo "--> Cleaning pyc and build files"
	sudo rm -fr build/ dist/ .eggs/ ./htmlcov
	sudo find . -name '*.egg-info' -exec rm -fr {} +
	sudo find . -name '*.egg' -exec rm -f {} +

coverage:
	@echo "--> Running Python tests with coverage"
	coverage run --branch --source=aspen_ssh -m py.test tests || exit 1
	coverage html
	@echo ""

.PHONY: develop clean test lint coverage
