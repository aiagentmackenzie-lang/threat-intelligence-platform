# 🧠 Threat Intelligence Platform — Chunked Action Plan

**Project:** Threat Intelligence Aggregation and Analysis Platform  
**Reference Spec:** `/path/to/project/🧠 Threat Intelligence Platform.md`  
**Created:** March 30, 2026  
**Role:** Lead Developer  
**Status:** Planning Phase — Ready for Review  

---

## 📋 Executive Overview

This plan transforms a comprehensive threat intelligence specification into 5 manageable phases with discrete, trackable chunks. Each chunk represents 2-4 hours of focused work and produces a concrete deliverable.

**Architecture Summary:**
```
Ingestion → Normalization → IOC Extraction → Correlation → Enrichment → AI Analysis → Reporting
```

---

## 🎯 Phase 1: Project Foundation & Infrastructure

**Goal:** Establish secure, containerized project foundation with modern Node.js structure

### Chunk 1.1: Project Bootstrap & Tooling Setup
**Estimated Time:** 2 hours  
**Deliverable:** Functional Node.js project with tooling configured

**Tasks:**
- [ ] Initialize Node.js project with `package.json` (type: module, Node >=20)
- [ ] Install dependencies: axios, dotenv, p-limit, pino, zod
- [ ] Configure ESLint for modern JavaScript
- [ ] Set up test framework (Node.js native test runner)
- [ ] Create `.gitignore` with security-focused exclusions
- [ ] Create `.env.example` with all required variables
- [ ] Verify tooling works: `npm test`, `npm run lint`

**Key Files to Create:**
- `package.json`
- `.gitignore`
- `.env.example`
- `.eslintrc.json` (or eslint.config.js)

**Security Checkpoint:**
- [ ] No secrets in any committed files
- [ ] `.env` properly excluded

---

### Chunk 1.2: Directory Structure & Containerization
**Estimated Time:** 2-3 hours  
**Deliverable:** Containerized application ready to run

**Tasks:**
- [ ] Create full directory structure per spec (Section 9)
- [ ] Write `Dockerfile` (multi-stage, non-root user)
- [ ] Write `docker-compose.yml` with environment injection
- [ ] Test container build: `docker compose build`
- [ ] Test container run: `docker compose run --rm threat-intel-cli`
- [ ] Verify non-root execution: `docker run --rm threat-intel-cli whoami`

**Key Files to Create:**
```
threat-intel/
├── src/
│   ├── ingestion/
│   ├── processing/
│   ├── enrichment/
│   ├── ai/
│   ├── utils/
│   ├── cli/
│   └── index.js
├── config/
│   └── feeds.json
├── tests/
├── Dockerfile
├── docker-compose.yml
└── README.md
```

**Security Checkpoint:**
- [ ] Container runs as `node` user, not root
- [ ] No unnecessary packages in final image

---

### Chunk 1.3: Configuration System & Feed Definitions
**Estimated Time:** 2 hours  
**Deliverable:** Config-driven feed system with validation

**Tasks:**
- [ ] Create `config/feeds.json` with sample feeds (disabled)
- [ ] Implement configuration loader with schema validation (Zod)
- [ ] Add feed configuration schema validation
- [ ] Support environment variable interpolation
- [ ] Create config validation script
- [ ] Test: invalid configs fail fast with clear errors

**Key Files:**
- `config/feeds.json`
- `src/config/loader.js`

**Validation Requirements:**
- Each feed must have unique name
- Auth must reference existing env vars
- URLs must be valid format

---

## 🎯 Phase 2: Core Pipeline Components

**Goal:** Build the data processing pipeline: ingestion → normalization → extraction → correlation

### Chunk 2.1: Logging Infrastructure
**Estimated Time:** 1 hour  
**Deliverable:** Production-ready logger with secret redaction

**Tasks:**
- [ ] Implement `src/utils/logger.js` using Pino
- [ ] Configure secret redaction paths (authorization, apiKey, token)
- [ ] Support LOG_LEVEL environment variable
- [ ] Add structured logging format
- [ ] Test: secrets are redacted in logs

**Key Files:**
- `src/utils/logger.js`

**Test Cases:**
- API keys redacted in error logs
- Tokens don't appear in debug output

---

### Chunk 2.2: Ingestion Layer (Feed Fetcher)
**Estimated Time:** 3 hours  
**Deliverable:** Robust feed fetching with auth and error handling

**Tasks:**
- [ ] Implement `src/ingestion/feeds.js` per spec (Section 13.2)
- [ ] Support REST API sources with header auth
- [ ] Add timeout handling (15s default)
- [ ] Add content-length limits (10MB max)
- [ ] Handle partial failures gracefully
- [ ] Implement retry logic with exponential backoff
- [ ] Add comprehensive error logging

**Key Files:**
- `src/ingestion/feeds.js`

**Test Requirements:**
- [ ] Mock server tests for success/failure cases
- [ ] Auth header injection works
- [ ] Timeouts handled gracefully
- [ ] Large responses rejected

---

### Chunk 2.3: Normalization Layer
**Estimated Time:** 2 hours  
**Deliverable:** Schema-validated data normalizer

**Tasks:**
- [ ] Implement `src/processing/normalizer.js` per spec (Section 13.3)
- [ ] Create Zod schema for raw events
- [ ] Handle heterogeneous input formats
- [ ] Normalize timestamps to ISO 8601
- [ ] Preserve source attribution
- [ ] Reject malformed records safely
- [ ] Handle both array and single-item inputs

**Key Files:**
- `src/processing/normalizer.js`

**Validation:**
- Invalid records return null and are filtered
- Valid records have consistent structure

---

### Chunk 2.4: IOC Extraction Engine
**Estimated Time:** 3 hours  
**Deliverable:** Multi-pattern IOC extractor with validation

**Tasks:**
- [ ] Implement `src/processing/extractor.js` per spec (Section 13.4)
- [ ] IPv4 extraction with regex + Node.js validation
- [ ] Domain extraction with normalization
- [ ] Hash extraction (MD5, SHA1, SHA256)
- [ ] Exclude private/loopback IP ranges
- [ ] Normalize casing (lowercase domains/hashes)
- [ ] Attach source and timestamp metadata

**Patterns to Support:**
- IPv4 (validated, non-private)
- Domains (normalized lowercase)
- File hashes (32, 40, 64 char hex)

**Key Files:**
- `src/processing/extractor.js`

**Test Cases:**
- `10.0.0.1` excluded (private)
- `127.0.0.1` excluded (loopback)
- `192.168.1.1` excluded (private)
- `8.8.8.8` included (public)
- `EXAMPLE.COM` → `example.com`

---

### Chunk 2.5: Correlation Engine
**Estimated Time:** 2 hours  
**Deliverable:** Deduplication and multi-source correlation

**Tasks:**
- [ ] Implement `src/processing/correlator.js` per spec (Section 13.5)
- [ ] Deduplicate by IOC type + value
- [ ] Track first seen / last seen timestamps
- [ ] Aggregate source sets
- [ ] Count total sightings
- [ ] Return array of correlated findings

**Key Files:**
- `src/processing/correlator.js`

**Test Verification:**
- Same IP from 3 sources → count: 3, sources array has 3 entries
- Timestamps track earliest and latest

---

## 🎯 Phase 3: Enrichment & Intelligence Layer

**Goal:** Add external intelligence and AI-assisted analysis

### Chunk 3.1: Enrichment Framework
**Estimated Time:** 3 hours  
**Deliverable:** Extensible enrichment system with controlled concurrency

**Tasks:**
- [ ] Implement `src/enrichment/enrich.js` per spec (Section 13.6)
- [ ] Design pluggable enrichment provider interface
- [ ] Implement AbuseIPDB enrichment (reputation, confidence)
- [ ] Add p-limit controlled concurrency (max 10 concurrent)
- [ ] Add rate limit awareness
- [ ] Graceful fallback on enrichment failure
- [ ] Cache enrichment results (optional v1)

**Key Files:**
- `src/enrichment/enrich.js`
- `src/enrichment/providers/abuseipdb.js`

**Configuration:**
- Concurrency limit: 10
- Timeout per enrichment: 10s
- Retry attempts: 2

---

### Chunk 3.2: AI Analysis Integration
**Estimated Time:** 3 hours  **Deliverable:** Schema-validated LLM analysis with fallbacks

**Tasks:**
- [ ] Implement `src/ai/analyzer.js` per spec (Section 13.7)
- [ ] Create Zod schema for AI output validation
- [ ] Support OpenAI API integration
- [ ] Add structured response mode (JSON)
- [ ] Implement fallback for invalid AI responses
- [ ] Add AI analysis bypass option
- [ ] Handle API failures gracefully

**AI Schema:**
```javascript
{
  risk: z.enum(["low", "medium", "high", "critical"]),
  explanation: z.string(),
  recommendation: z.string()
}
```

**Key Files:**
- `src/ai/analyzer.js`

**Security Note:**
- AI output is validated before use
- Invalid output triggers fallback, never crashes

---

## 🎯 Phase 4: CLI Interface & Reporting

**Goal:** Complete CLI tool with multiple output formats

### Chunk 4.1: Reporter Module
**Estimated Time:** 2 hours  
**Deliverable:** Multi-format reporting system

**Tasks:**
- [ ] Implement `src/utils/reporter.js` per spec (Section 13.8)
- [ ] Console/CLI output format
- [ ] JSON export format
- [ ] NDJSON format for streaming
- [ ] STIX 2.1-like export (simplified)
- [ ] Add output file writing capability

**Key Files:**
- `src/utils/reporter.js`

**Output Formats:**
- `--format console` (default)
- `--format json`
- `--format ndjson`
- `--format stix`

---

### Chunk 4.2: CLI Entry Point & Orchestration
**Estimated Time:** 3 hours  
**Deliverable:** Production-ready CLI with full pipeline

**Tasks:**
- [ ] Implement `src/cli/index.js` per spec (Section 13.9)
- [ ] Wire all pipeline stages together
- [ ] Add command-line argument parsing
- [ ] Implement full execution flow:
  1. Load feeds
  2. Fetch raw data
  3. Normalize
  4. Extract IOCs
  5. Correlate
  6. Enrich (concurrent)
  7. AI analyze (concurrent)
  8. Report
- [ ] Add progress indicators
- [ ] Handle fatal errors gracefully

**CLI Arguments:**
- `--config <path>` - Custom config file
- `--format <type>` - Output format
- `--output <file>` - Save to file
- `--no-ai` - Skip AI analysis
- `--feeds <names>` - Filter to specific feeds

**Key Files:**
- `src/cli/index.js`

---

### Chunk 4.3: Documentation & README
**Estimated Time:** 2 hours  
**Deliverable:** Complete project documentation

**Tasks:**
- [ ] Write comprehensive README.md
- [ ] Document installation steps
- [ ] Document configuration options
- [ ] Add usage examples
- [ ] Document security considerations
- [ ] Add troubleshooting section
- [ ] Document API key requirements

**Key Files:**
- `README.md`
- `docs/architecture.md` (optional)

---

## 🎯 Phase 5: Testing & Quality Assurance

**Goal:** Comprehensive test coverage and security validation

### Chunk 5.1: Unit Test Suite
**Estimated Time:** 4 hours  
**Deliverable:** >80% test coverage on core modules

**Tasks:**
- [ ] Write tests for `normalizer.js`
- [ ] Write tests for `extractor.js` (all IOC types)
- [ ] Write tests for `correlator.js`
- [ ] Write tests for `analyzer.js` (including Zod validation)
- [ ] Write tests for `feeds.js` (with mocked axios)
- [ ] Write tests for `enrich.js` (with mocked providers)

**Key Files:**
- `tests/extractor.test.js`
- `tests/correlator.test.js`
- `tests/analyzer.test.js`
- `tests/normalizer.test.js`
- `tests/feeds.test.js`

**Test Coverage Goals:**
- Extractor: 100% (critical security component)
- Correlator: >90%
- Normalizer: >90%
- Analyzer: >80%

---

### Chunk 5.2: Integration & Security Tests
**Estimated Time:** 3 hours  
**Deliverable:** End-to-end tests and security validation

**Tasks:**
- [ ] Write end-to-end pipeline tests
- [ ] Test malformed feed handling
- [ ] Test secret redaction in logs
- [ ] Test invalid AI payload handling
- [ ] Test container security (non-root, no secrets)
- [ ] Test private IP exclusion
- [ ] Test rate limiting behavior
- [ ] Add CI workflow (GitHub Actions)

**Security Tests:**
- [ ] `grep -r "apiKey\|token\|secret" logs/` should find nothing
- [ ] `.env` file never appears in `docker build` layers
- [ ] Container user is `node`, not `root`

---

### Chunk 5.3: Performance & Load Testing
**Estimated Time:** 2 hours  
**Deliverable:** Validated performance characteristics

**Tasks:**
- [ ] Test with 1000 IOCs (measure time)
- [ ] Test with 10,000 IOCs (measure time)
- [ ] Verify concurrency limits work
- [ ] Memory usage profiling
- [ ] Document performance baseline

**Performance Targets:**
- 1000 IOCs: <30 seconds end-to-end
- Memory: <512MB for 10K IOCs
- Concurrency: Respects p-limit(10)

---

## 📊 Project Timeline Summary

| Phase | Chunks | Estimated Hours | Cumulative |
|-------|--------|-----------------|------------|
| Phase 1: Foundation | 3 | 6-7 hrs | 6-7 hrs |
| Phase 2: Core Pipeline | 5 | 11 hrs | 17-18 hrs |
| Phase 3: Enrichment & AI | 2 | 6 hrs | 23-24 hrs |
| Phase 4: CLI & Reporting | 3 | 7 hrs | 30-31 hrs |
| Phase 5: Testing & QA | 3 | 9 hrs | 39-40 hrs |

**Total Estimated Time:** ~40 hours  
**Recommended Pace:** 2-4 hours per day = 10-20 days

---

## 🚀 Quick Start (After Each Phase)

### After Phase 1:
```bash
docker compose build
docker compose run --rm threat-intel-cli
# Should show: "No enabled feeds configured"
```

### After Phase 2:
```bash
npm test
# All core pipeline tests passing
```

### After Phase 3:
```bash
ABUSEIPDB_API_KEY=xxx npm start
# Real enrichment working
```

### After Phase 4:
```bash
npm start -- --format json --output report.json
# Full pipeline execution
```

### After Phase 5:
```bash
npm test
# 80%+ coverage, all tests passing
```

---

## 🛡️ Security Checkpoints by Phase

| Phase | Security Check |
|-------|----------------|
| Phase 1 | No secrets committed, container non-root |
| Phase 2 | Input validation, no injection vulnerabilities |
| Phase 3 | AI output validated, API keys not logged |
| Phase 4 | Safe file writing, no path traversal |
| Phase 5 | Secret redaction verified, container hardened |

---

## 📁 File Reference

**Spec Location:** `/path/to/project/🧠 Threat Intelligence Platform.md`

**This Plan Location:** `PROJECT_PLAN.md`

**Project Root:** `./`

---

## ✅ Ready for Review

This plan is ready for your review. Each chunk is:
- **Independent** - Can be worked on separately
- **Testable** - Has clear success criteria
- **Time-boxed** - 2-4 hour estimates
- **Documented** - References spec sections

**Next Step:** Review this plan and indicate which phase/chunk to begin.

---

*Plan created by: Lead Developer*  
*Date: March 30, 2026*  
*Version: 1.0*
