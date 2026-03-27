import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Trend, Rate } from 'k6/metrics';
import { SharedArray } from 'k6/data';

const assertions = new SharedArray('precomputed_assertions', function () {
    return JSON.parse(open('./assertions.json'));
});

const tokenExchangeTrend = new Trend('token_exchange_duration');
const errorRate = new Rate('error_rate');

export const options = {
    stages: [
        { duration: '30s', target: 1000 },
        { duration: '1m', target: 1000 },
        { duration: '30s', target: 0 },
    ],
    thresholds: {
        http_req_duration: ['p(95)<200'],
        token_exchange_duration: ['p(95)<250'],
        error_rate: ['rate<0.01'],
    },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:7496';
const TENANT_ID = __ENV.TENANT_ID || 'default';

export default function () {
    group('Zero Trust M2M Flow (PKI-Based)', function () {
        const tokenEndpoint = `${BASE_URL}/t/${TENANT_ID}/oauth2/token`;

        const assertionIndex = (__VU * 1000 + __ITER) % assertions.length;
        const clientAssertion = assertions[assertionIndex];

        const tokenPayload = {
            grant_type: 'client_credentials',
            scope: 'openid',
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion: clientAssertion,
        };

        const tokenRes = http.post(tokenEndpoint, tokenPayload, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        });

        tokenExchangeTrend.add(tokenRes.timings.duration);

        const tokenSuccess = check(tokenRes, {
            'token status is 200': (r) => r.status === 200,
            'has access_token': (r) => r.json('access_token') !== undefined,
        });

        if (!tokenSuccess) {
            console.error(`Auth Failed: ${tokenRes.status} - ${tokenRes.body}`);
        }

        errorRate.add(!tokenSuccess);
    });

    sleep(1);
}