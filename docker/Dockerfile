FROM python:3.11-slim

RUN apt-get update && apt-get install -y libpcap-dev tcpdump

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src/ ./src/
COPY tests/ ./tests/

CMD ["python", "src/main.py"]
