import JwksClient from './JwksClient';
import axios from 'axios';

const mockedAxios = axios as jest.Mocked<any>;

const validJwks = {
  'keys': [
    {
      'alg': 'RS256',
      'kty': 'RSA',
      'use': 'sig',
      'x5c': [
        'testPublicKey',
      ],
      'n': 'testN',
      'e': 'AQAB',
      'kid': 'testKid',
      'x5t': 'testX5t',
    },
]};

const validJwksWithNoSigningKey = {
  'keys': [
    {
      'alg': 'RS256',
      'kty': 'RSA',
      'use': 'nosig',
      'x5c': [
        'testPublicKey',
      ],
      'n': 'testN',
      'e': 'AQAB',
      'kid': 'testKid',
      'x5t': 'testX5t',
    },
]};

const validJwksWithEmptyCert = {
  'keys': [
    {
      'alg': 'RS256',
      'kty': 'RSA',
      'use': 'sig',
      'x5c': [
        '',
      ],
      'n': 'testN',
      'e': 'AQAB',
      'kid': 'testKid',
      'x5t': 'testX5t',
    },
]};

const validJwksWithNoCert = {
  'keys': [
    {
      'alg': 'RS256',
      'kty': 'RSA',
      'use': 'sig',
      'x5c': [],
      'n': 'testN',
      'e': 'AQAB',
      'kid': 'testKid',
      'x5t': 'testX5t',
    },
]};

describe('JwksClient', () => {
  let jwksClient: JwksClient;

  afterEach(() => {
    jest.resetAllMocks();
  });

  it('should do a GET request to the given URL', async () => {
    jwksClient = new JwksClient({
      url: 'https://testURL',
    });
    mockedAxios.mockReturnValueOnce(Promise.resolve({
      status: 200,
      data: validJwks,
    }));
    await expect(jwksClient.getSigningKey('testKid'));
    expect(mockedAxios).toHaveBeenCalledWith({
      method: 'GET',
      url: 'https://testURL',
    });
  });

  describe('When jwks GET request fails', () => {
    beforeEach(() => {
      mockedAxios.mockReturnValueOnce(Promise.reject(new Error('testError')));
      jwksClient = new JwksClient({
        url: 'https://testURL',
      });
    });

    it('should reject with error message', async () => {
      await expect(jwksClient.getSigningKey('testKid')).rejects.toThrow('Couldn\'t load jwks, testError');
    });
  });

  describe('When jwks GET request passes, but response is malformed', () => {
    beforeEach(() => {
      jwksClient = new JwksClient({
        url: 'https://testURL',
      });
    });

    it('should reject with error message', async () => {
      mockedAxios.mockReturnValueOnce(Promise.resolve({
        status: 109,
        data: {
          someProperty: 'someText',
        },
      }));
      await expect(jwksClient.getSigningKey('testKid')).rejects.toThrow('Couldn\'t get JWKS, Http Error 109');
    });

    it('should reject with error message', async () => {
      mockedAxios.mockReturnValueOnce(Promise.resolve({
        status: 200,
        data: {
          someProperty: 'someText',
        },
      }));
      await expect(jwksClient.getSigningKey('testKid')).rejects.toThrow('The JWKS did not contain any keys');
    });
  });

  describe('When jwks GET request passes, but there are no signing keys', () => {
    beforeEach(() => {
      mockedAxios.mockReturnValueOnce(Promise.resolve({
        status: 200,
        data: validJwksWithNoSigningKey,
      }));
      jwksClient = new JwksClient({
        url: 'https://testURL',
      });
    });

    it('should reject with error message', async () => {
      await expect(jwksClient.getSigningKey('testKid')).rejects.toThrow('The JWKS did not contain any signing keys');
    });
  });

  describe('When jwks GET request passes, but the signing key is empty', () => {
    beforeEach(() => {
      mockedAxios.mockReturnValueOnce(Promise.resolve({
        status: 200,
        data: validJwksWithEmptyCert,
      }));
      jwksClient = new JwksClient({
        url: 'https://testURL',
      });
    });

    it('should return an empty public key', async () => {
      await expect(jwksClient.getSigningKey('testKid')).resolves.toEqual({
        'kid': 'testKid',
        'nbf': undefined,
        'publicKey': '',
      });
    });
  });

  describe('When jwks GET request passes, but the signing key list is empty', () => {
    beforeEach(() => {
      mockedAxios.mockReturnValueOnce(Promise.resolve({
        status: 200,
        data: validJwksWithNoCert,
      }));
      jwksClient = new JwksClient({
        url: 'https://testURL',
      });
    });

    it('should reject with error message', async () => {
      await expect(jwksClient.getSigningKey('testKid')).rejects.toThrow('The JWKS did not contain any signing keys');
    });
  });

  describe('When jwks GET request passes', () => {
    beforeEach(() => {
      mockedAxios.mockReturnValueOnce(Promise.resolve({
        status: 200,
        data: validJwks,
      }));
      jwksClient = new JwksClient({
        url: 'https://testURL',
      });
    });

    it('Should throw if public key is not present for given kid', async () => {
      await expect(jwksClient.getSigningKey('wrongKid')).rejects.toThrow('Unable to find a signing key that matches \'wrongKid\'');
    });

    it('Should return the public key for the given kid', async () => {
      await expect(jwksClient.getSigningKey('testKid')).resolves.toEqual({
        'kid': 'testKid',
        'nbf': undefined,
        'publicKey': `-----BEGIN CERTIFICATE-----\ntestPublicKey\n-----END CERTIFICATE-----\n`,
      });
    });

    it('Should cache the result, and not make a call for the same kid the second time', async () => {
      await jwksClient.getSigningKey('testKid');
      await jwksClient.getSigningKey('testKid');

      expect(axios).toHaveBeenCalledTimes(1);
    });
  });
});
