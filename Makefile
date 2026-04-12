.PHONY: bootstrap build run test clean

# Build the container and set up the environment
bootstrap:
	mkdir -p data src tests docker
	docker compose build

build:
	docker compose build

run:
	docker compose up

test:
	docker compose run --rm detector python -m pytest tests/ -v

clean:
	docker compose down --rmi local --volumes --remove-orphans
