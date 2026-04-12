# Protocol Impersonation Detection System

CECS 478 Final Project

## Overview

This project detects protocol impersonation attacks where malicious traffic is used to disguise themselves as legit HTTP or DNS traffic to get by detection systems. It analyzes PCAP files and flags traffic that doesn't behave consistently with the protocol it says it is.

## Setup

Requirements: Docker, Docker Compose, Make

```bash
make bootstrap
```

## Usage

```bash
make run    # start the container
make test   # run tests
make clean  # tear everything down
```

## Project Structure

```
data/       # PCAP files
src/        # source code
tests/      # tests
docker/     # Dockerfile
```

## Goals

- Detection rate >= 85%
- False positive rate <= 15%
- Process a PCAP file in under 5 seconds

