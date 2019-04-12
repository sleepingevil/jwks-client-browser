# jwks-client-browser ![npm](https://img.shields.io/npm/v/jwks-client-browser.svg)

[![CircleCI](https://circleci.com/gh/sleepingevil/jwks-client-browser/tree/master.svg?style=shield&circle-token=bb6e7035614311760a76fa79719408011684f75e)](https://circleci.com/gh/sleepingevil/jwks-client-browser/tree/master.svg?label=circleci)
[![codecov](https://codecov.io/gh/sleepingevil/jwks-client-browser/branch/master/graph/badge.svg)](https://codecov.io/gh/sleepingevil/jwks-client-browser)
![Dependencies](https://img.shields.io/david/sleepingevil/jwks-client-browser.svg)
[![install size](https://packagephobia.now.sh/badge?p=jwks-client-browser)](https://packagephobia.now.sh/result?p=jwks-client-browser)
![npm downloads](https://img.shields.io/npm/dt/jwks-client-browser.svg)
[![Known Vulnerabilities](https://snyk.io/test/npm/jwks-client-browser/badge.svg)](https://snyk.io/test/npm/jwks-client-browser)
![NPM](https://img.shields.io/npm/l/jwks-client-browser.svg)

This pacakge was created, because the current JWKS clients available only work in node, but not in the browser. This client is specifically designed to work in the browser. Given a JWKS endpoint URL and a `kid` it will retrieve the public key that you can use for JWT verification.

## Installation

```bash
npm i jwks-client-browser
```

or

```bash
yarn add jwks-client-browser
```

## Usage

### JavaScript

```javascript
import JwksClient from 'jwks-client-browser';

const kid = JSON.parse(atob(token.split('.')[0])).kid

const jwksClient = new JwksClient({ url: '[your_jwks_endpoint]' });

const signingKey = jwksClient.getSigningKey(kid);
```

### TypeScript

```typescript
import JwksClient, { ISigningKeyPem } from 'jwks-client-browser';

const kid: string = JSON.parse(atob(token.split('.')[0])).kid

const jwksClient: JwksClient = new JwksClient({ url: '[your_jwks_endpoint]' });

const signingKey: ISigningKeyPem = jwksClient.getSigningKey(kid);
```

Once you acquired the public key, you can use it to verify the token. Here's an example using the `jsonwebtoken` package:

```typescript
import jwt from 'jsonwebtoken';

const signingKey: ISigningKeyPem = jwksClient.getSigningKey(kid);

jwt.verify(token, signingKey.publicKey);
```

## Disclaimer
This is still a draft version of the package. Contributions are welcome!
