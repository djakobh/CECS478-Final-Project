.PHONY: bootstrap build run test clean

bootstrap:
	mkdir -p data src tests docker
	docker compose build

build:
	docker compose build

run:
	docker compose up

test:
	docker compose run --rm detector ./tests/test_stub

clean:
	docker compose down --rmi local --volumes --remove-orphans
