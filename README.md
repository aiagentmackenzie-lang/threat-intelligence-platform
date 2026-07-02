# Threat Intelligence Platform

A modern, security-focused threat intelligence aggregation and analysis platform that collects, normalizes, enriches, correlates, and analyzes threat data from multiple sources.

## Overview

This platform ingests threat data from REST APIs and RSS feeds, extracts Indicators of Compromise (IOCs), correlates sightings, enriches IP reputation via AbuseIPDB and a no-key GeoIP service, optionally analyzes risk with an OpenAI-compatible LLM, and produces structured outputs for analysts and downstream security systems.

> **Honest scope:** MISP, TAXII, and AlienVault OTX feeds are **not yet implemented** — only the environment variables and feed schema placeholders exist. VirusTotal enrichment is declared in the config but the provider functions are stubs that return `null`.

## Supported capabilities

| Capability | Status |
|:---|:---|
| REST API feed ingestion | ✅ Implemented |
| RSS feed ingestion | ⚠️ Simplified regex parser (no full XML parser) |
| Static/demo feed | ✅ Implemented |
| IOC extraction (IP, domain, hash, URL) | ✅ Implemented |
| Normalization + correlation | ✅ Implemented |
| AbuseIPDB IP enrichment | ✅ Implemented |
| GeoIP enrichment | ✅ Implemented (ip-api.com, no API key) |
| VirusTotal enrichment | ❌ Stubbed — returns `null` |
| OpenAI risk analysis | ✅ Implemented (requires `OPENAI_API_KEY`) |
| MISP integration | ❌ Not implemented |
| TAXII ingest | ❌ Not implemented |
| AlienVault OTX ingest | ❌ Not implemented |
| Console / JSON / NDJSON / STIX reporting | ✅ Implemented |

## Architecture

```
Threat Feeds / APIs / RSS / Internal Logs
                │
                ▼
        Ingestion Layer
                │
                ▼
  Normalization Layer (with Zod validation)
                │
                ▼
         IOC Extraction Layer
                │
                ▼
        Correlation Pre-Stage
                │
                ▼
        Enrichment Engine
                │
                ▼
        AI Analysis Layer
                │
                ▼
      Reporting / Export Layer
```

## Quick Start

### Prerequisites

- Node.js >= 20
- Docker & Docker Compose (optional, for containerized deployment)

### Installation

```bash
# Install dependencies
npm install

# Copy environment template
cp .env.example .env

# Edit .env with your API keys (optional for basic testing)
```

### Usage

```bash
# Run the CLI
npm start

# Development mode (with watch)
npm run dev

# Run tests
npm test

# Lint code
npm run lint
```

### Docker

```bash
# Build and run with Docker Compose
docker compose build
docker compose run --rm threat-intel-cli
```

## Configuration

Feed configuration is managed in `config/feeds.json`. All external feeds (AbuseIPDB, Krebs on Security RSS) are disabled by default; a built-in demo feed is enabled so the pipeline can run without API keys.

To enable a real feed:
1. Set `"enabled": true` in `config/feeds.json`
2. Add the required API key to your `.env` file

### Currently wired feed types

- `rest` — HTTP GET with header/basic/query auth, retry/backoff, timeout
- `rss` — Simplified regex-based RSS item extraction
- `static` — Built-in demo IOCs for testing

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `NODE_ENV` | Environment mode (production/development) | No |
| `LOG_LEVEL` | Logging level (debug, info, warn, error) | No |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | For AbuseIPDB feed |
| `VT_API_KEY` | VirusTotal API key | For VT enrichment |
| `MISP_API_KEY` | MISP API key | For MISP integration |
| `MISP_URL` | MISP instance URL | For MISP integration |
| `OPENAI_API_KEY` | OpenAI API key | For AI analysis |

## Security

- API keys are never logged (redacted by Pino)
- Container runs as non-root user
- No secrets committed to version control
- All external inputs validated before processing

## Project Structure

```
threat-intel/
├── src/
│   ├── ingestion/      # Feed fetching
│   ├── processing/     # Normalization, extraction, correlation
│   ├── enrichment/     # External intelligence lookups
│   ├── ai/             # LLM analysis
│   ├── utils/          # Logger, reporter
│   ├── cli/            # Command-line interface
│   └── config/         # Configuration loader
├── config/
│   └── feeds.json      # Feed definitions
├── tests/              # Test suite
├── Dockerfile
├── docker-compose.yml
└── package.json
```

## License

MIT
