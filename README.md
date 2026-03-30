# Threat Intelligence Platform

A modern, security-focused threat intelligence aggregation and analysis platform that collects, normalizes, enriches, correlates, and analyzes threat data from multiple sources.

## Overview

This platform ingests threat data from multiple external and internal sources, extracts Indicators of Compromise (IOCs), enriches them with contextual intelligence, correlates sightings across feeds and telemetry, and produces structured outputs for analysts and downstream security systems.

## Architecture

```
Threat Feeds / APIs / RSS / Internal Logs
                │
                ▼
        Ingestion Layer
                │
                ▼
  Validation + Normalization Layer
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

Feed configuration is managed in `config/feeds.json`. All feeds are disabled by default.

To enable a feed:
1. Set `"enabled": true` in `config/feeds.json`
2. Add the required API key to your `.env` file

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
