.PHONY: up demo test coverage clean

# Primary acceptance sequence — works on a fresh clone
up:
	docker compose build
	docker compose run --rm traffic_gen

demo:
	docker compose run --rm detector

# Run all unit tests inside the container
test:
	docker compose run --rm --entrypoint "" detector ./tests/run_tests.sh

# Build with gcov instrumentation, run tests, print coverage summary
coverage:
	docker compose run --rm --entrypoint "" detector sh -c "\
	  gcc -fprofile-arcs -ftest-coverage -o /tmp/t_http \
	      tests/test_http_validator.c src/http_validator/http_validator.c && \
	  gcc -fprofile-arcs -ftest-coverage -o /tmp/t_dns \
	      tests/test_dns_validator.c src/dns_validator/dns_validator.c && \
	  gcc -fprofile-arcs -ftest-coverage -o /tmp/t_det \
	      tests/test_detector.c src/detector/detector.c \
	      src/http_validator/http_validator.c src/dns_validator/dns_validator.c && \
	  gcc -fprofile-arcs -ftest-coverage -o /tmp/t_fe \
	      tests/test_feature_extract.c src/feature_extract/feature_extract.c && \
	  /tmp/t_http && /tmp/t_dns && /tmp/t_det && /tmp/t_fe && \
	  gcov src/http_validator/http_validator.c src/dns_validator/dns_validator.c \
	       src/detector/detector.c src/feature_extract/feature_extract.c"

clean:
	docker compose down --rmi local --volumes --remove-orphans
