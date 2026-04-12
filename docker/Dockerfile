FROM gcc:latest

RUN apt-get update && apt-get install -y libpcap-dev

WORKDIR /app

COPY src/ ./src/
COPY tests/ ./tests/

RUN gcc -o detector src/main.c -lpcap
RUN gcc -o tests/test_stub tests/test_stub.c

CMD ["./detector"]
