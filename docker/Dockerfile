FROM gcc:latest

RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*

# Non-root user for least-privilege execution
RUN useradd -m appuser

WORKDIR /app

COPY src/ ./src/
COPY tests/ ./tests/

# Create output directories with correct ownership
RUN mkdir -p data artifacts/release && chown -R appuser:appuser /app

# Build traffic generator
RUN gcc -Wall -Wextra -o traffic_gen \
        src/traffic_gen.c \
        -lpcap

# Build detector (all modules)
RUN gcc -Wall -Wextra -o detector \
        src/main.c \
        src/logger/logger.c \
        src/pcap_reader/pcap_reader.c \
        src/feature_extract/feature_extract.c \
        src/http_validator/http_validator.c \
        src/dns_validator/dns_validator.c \
        src/detector/detector.c \
        src/metrics/metrics.c \
        -lpcap

# Build test binaries
RUN gcc -Wall -Wextra -o tests/test_http_validator \
        tests/test_http_validator.c \
        src/http_validator/http_validator.c

RUN gcc -Wall -Wextra -o tests/test_dns_validator \
        tests/test_dns_validator.c \
        src/dns_validator/dns_validator.c

RUN gcc -Wall -Wextra -o tests/test_detector \
        tests/test_detector.c \
        src/detector/detector.c \
        src/http_validator/http_validator.c \
        src/dns_validator/dns_validator.c

RUN gcc -Wall -Wextra -o tests/test_feature_extract \
        tests/test_feature_extract.c \
        src/feature_extract/feature_extract.c

RUN chmod +x tests/run_tests.sh

USER appuser

CMD ["./detector"]
