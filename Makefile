setup-vault:
	 docker exec -it vault /setup.sh

lint:
	uv run pre-commit run --all

test:
	uv run pytest --cov=src --cov-branch --cov-fail-under=95 --cov-report html:coverage_report
