// FILE PATH: ./loadtests/shyntr_load_test.js
import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Trend, Rate } from 'k6/metrics';
import encoding from 'k6/encoding';

// Custom metrics for deep observability
const tokenExchangeTrend = new Trend('token_exchange_duration');
const introspectionTrend = new Trend('token_introspection_duration');
const errorRate = new Rate('error_rate');

// Test configuration: Ramp-up, sustained peak, and ramp-down
export const options = {
    stages: [
        { duration: '30s', target: 50 },  // Ramp up to 50 Virtual Users (VUs)
        { duration: '1m', target: 50 },   // Sustained load
        { duration: '30s', target: 0 },   // Ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<500'], // 95% of all requests should be under 500ms
        token_exchange_duration: ['p(95)<600'],
        error_rate: ['rate<0.01'],        // Error rate must be less than 1%
    },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:7496';
const CLIENT_ID = __ENV.CLIENT_ID || 'load-test-client';
const CLIENT_SECRET = __ENV.CLIENT_SECRET || 'load-test-secret';
const TENANT_ID = __ENV.TENANT_ID || 'default';

export default function () {
    const encodedCredentials = encoding.b64encode(`${CLIENT_ID}:${CLIENT_SECRET}`);
    const authHeaders = {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': `Basic ${encodedCredentials}`,
        },
    };

    group('1. OIDC Discovery & JWKS (Read-Heavy)', function () {
        const discRes = http.get(`${BASE_URL}/t/${TENANT_ID}/.well-known/openid-configuration`);
        const discSuccess = check(discRes, {
            'discovery status is 200': (r) => r.status === 200,
        });
        errorRate.add(!discSuccess);

        const jwksRes = http.get(`${BASE_URL}/t/${TENANT_ID}/.well-known/jwks.json`);
        const jwksSuccess = check(jwksRes, {
            'jwks status is 200': (r) => r.status === 200,
        });
        errorRate.add(!jwksSuccess);
    });

    group('2. Zero Trust M2M Flow (CPU & DB-Heavy)', function () {
        const tokenPayload = {
            grant_type: 'client_credentials',
            scope: 'openid',
        };

        const tokenRes = http.post(`${BASE_URL}/t/${TENANT_ID}/oauth2/token`, tokenPayload, authHeaders);
        tokenExchangeTrend.add(tokenRes.timings.duration);

        const tokenSuccess = check(tokenRes, {
            'token status is 200': (r) => r.status === 200,
            'has access_token': (r) => r.json('access_token') !== undefined,
        });
        errorRate.add(!tokenSuccess);

        if (tokenSuccess) {
            const token = tokenRes.json('access_token');
            const introPayload = { token: token };

            const introRes = http.post(`${BASE_URL}/t/${TENANT_ID}/oauth2/introspect`, introPayload, authHeaders);
            introspectionTrend.add(introRes.timings.duration);

            const introSuccess = check(introRes, {
                'introspect status is 200': (r) => r.status === 200,
                'token is active': (r) => r.json('active') === true,
            });
            errorRate.add(!introSuccess);
        }
    });

    sleep(1);
}