# Rate Limit Load Testing

This directory contains load tests for verifying the unified rate limiting policy implementation.

## Prerequisites

Install k6:
```bash
# macOS
brew install k6

# Linux
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6

# Windows
choco install k6

# Or use npm
npm install -g k6
```

## Running Tests

### All Scenarios (Full Suite)
```bash
k6 run --env BASE_URL=https://sandbox-verify.provii.app tests/load/rate_limit_test.js
```

### Individual Scenarios

**Burst Attack Test** (100 requests in 10 seconds):
```bash
k6 run --env BASE_URL=https://sandbox-verify.provii.app --env SCENARIO=burst tests/load/rate_limit_test.js
```

**Sustained Load Test** (1000 requests over time):
```bash
k6 run --env BASE_URL=https://sandbox-verify.provii.app --env SCENARIO=sustained tests/load/rate_limit_test.js
```

**Ramp-Up Test** (gradual increase in load):
```bash
k6 run --env BASE_URL=https://sandbox-verify.provii.app --env SCENARIO=ramp tests/load/rate_limit_test.js
```

**Multi-Origin Test** (independent limits per origin):
```bash
k6 run --env BASE_URL=https://sandbox-verify.provii.app --env SCENARIO=multi_origin tests/load/rate_limit_test.js
```

**Header Validation Test** (verify response headers):
```bash
k6 run --env BASE_URL=https://sandbox-verify.provii.app --env SCENARIO=headers tests/load/rate_limit_test.js
```

### Local Development
```bash
# Start wrangler dev first
cd /Users/timoconnor/Desktop/Provii/provii-verifier
wrangler dev

# Then run tests against local
k6 run --env BASE_URL=http://localhost:8787 --env SCENARIO=burst tests/load/rate_limit_test.js
```

## Test Scenarios

### 1. Burst Attack Test
- **Purpose**: Verify per-minute rate limit (100 req/min)
- **Method**: Send 10 requests/second for 10 seconds (100 total)
- **Expected**: First 100 requests succeed, subsequent requests return 429

### 2. Sustained Load Test
- **Purpose**: Verify per-hour rate limit (1000 req/hour)
- **Method**: Send ~17 requests/minute for 3 minutes (~50 requests)
- **Expected**: All requests within limit succeed

### 3. Ramp-Up Test
- **Purpose**: Test behaviour under increasing load
- **Method**: Gradually increase from 10/min to 120/min
- **Expected**: 429 responses start appearing around 100/min

### 4. Multi-Origin Test
- **Purpose**: Verify origins have independent rate limits
- **Method**: 5 origins each making 10 requests
- **Expected**: All requests succeed (each origin under limit)

### 5. Header Validation Test
- **Purpose**: Verify correct rate limit headers
- **Method**: Make requests until rate limited, check headers
- **Expected**: All required headers present with correct values

## Expected Results

### Success Criteria

**Rate Limit Enforcement:**
- Per-minute limit (100 req/min) enforced within ±5 requests
- Per-hour limit (1000 req/hour) enforced within ±10 requests
- 429 responses include required headers

**Response Headers (2xx):**
```http
X-RateLimit-Limit-Minute: 100
X-RateLimit-Remaining-Minute: 95
X-RateLimit-Reset-Minute: 1699564800
X-RateLimit-Limit-Hour: 1000
X-RateLimit-Remaining-Hour: 950
X-RateLimit-Reset-Hour: 1699564860
```

**Response Headers (429):**
```http
Retry-After: 60
X-RateLimit-Limit-Minute: 100
X-RateLimit-Remaining-Minute: 0
X-RateLimit-Reset-Minute: 1699564800
```

**Performance:**
- p95 response time < 500ms
- No dropped requests (except expected 429s)
- Circuit breaker triggers at ~50,000 req/min (503 response)

## Metrics

Key metrics tracked:
- `rate_limit_hits`: Counter of 429 responses
- `rate_limit_success_rate`: Percentage of successful requests
- `response_time`: Response time distribution (p50, p95, p99)
- `http_req_duration`: HTTP request duration
- `http_req_failed`: Failed request rate

## Interpreting Results

### Good Results
```
✓ burst: status is 200 or 429
✓ burst: has Retry-After header
✓ headers: rate limit was triggered
✓ headers: limit enforced around correct threshold
```

### Bad Results (Investigate)
```
✗ burst: status is 200 or 429 (500 errors indicate backend issues)
✗ headers: has Retry-After header (missing required headers)
✗ headers: limit enforced around correct threshold (limits not enforced)
```

## Troubleshooting

**Issue: All requests return 429 immediately**
- Check if rate limit state persisted from previous test
- Wait 60 seconds for minute window to reset
- Use different origin identifier

**Issue: No 429 responses**
- Verify BASE_URL is correct
- Check that rate limiting is enabled
- Increase request rate or duration

**Issue: Inconsistent results**
- Rate limits are per-worker in-memory (may reset)
- Use consistent origin identifier
- Wait for windows to reset between tests

**Issue: Circuit breaker triggers (503)**
- Too many concurrent VUs
- Reduce rate or duration
- This is expected for global limit tests

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Rate Limit Load Test

on:
  pull_request:
    paths:
      - 'src/security/rate_limit.rs'

jobs:
  load-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install k6
        run: |
          sudo gpg -k
          sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
          echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
          sudo apt-get update
          sudo apt-get install k6

      - name: Run load tests
        run: |
          k6 run --env BASE_URL=https://sandbox-verify.provii.app \
            --env SCENARIO=burst \
            tests/load/rate_limit_test.js
```

## References

- [k6 Documentation](https://k6.io/docs/)
- [Rate Limiting Implementation](../../src/security/rate_limit.rs)
