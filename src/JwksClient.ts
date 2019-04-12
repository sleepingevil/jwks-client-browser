import axios, { AxiosResponse } from 'axios';

interface IJwksClientOptions {
  url: string;
}

export default class JwksClient implements IJwksClient {
  private options: IJwksClientOptions;
  private savedSigningKeys: Map<string, ISigningKeyPem>;

  constructor(options: IJwksClientOptions) {
    this.options = options;
    this.savedSigningKeys = new Map();
  }

  public getSigningKey(kid: string) {
    const getSigningKeyPromise = () => new Promise<ISigningKeyPem>((resolve, reject) => {
      const callback: GetSigningKeysCallback = (err, keys) => {
        if (!keys || keys.length === 0) {
          return reject(err);
        } else {
          const signingKey = keys.find((key) => key.kid === kid);

          if (!signingKey) {
            const error: Error = new SigningKeyNotFoundError(`Unable to find a signing key that matches '${kid}'`);
            return reject(error);
          }

          this.savedSigningKeys.set(kid, signingKey);

          return resolve(signingKey);
        }
      };

      this.getSigningKeys(callback);
    });
    const savedSigningKey = this.savedSigningKeys.get(kid);
    return savedSigningKey ? Promise.resolve(savedSigningKey) : getSigningKeyPromise();
  }

  private getJwks(cb: GetJwksCallback) {
    const request = {
      method: 'GET',
      url: this.options.url,
    };
    axios(request)
      .then((res: AxiosResponse<IJwksResponseBody>) => {
        if (res.status < 200 || res.status >= 300) {
          return cb(new JwksError(`Couldn't get JWKS, Http Error ${res.status}`));
        }

        cb(null, res.data.keys);
      })
      .catch((err: Error) => cb(new JwksError(`Couldn't load jwks, ${err.message}`)));
  }

  private getSigningKeys(cb: GetSigningKeysCallback) {
    const callback: GetJwksCallback = (err, keys) => {
      if (err) {
        return cb(err);
      }

      if (!keys || !keys.length) {
        return cb(new JwksError('The JWKS did not contain any keys'));
      }

      const signingKeys = keys
        .filter((key) => key.use === 'sig' // JWK property `use` determines the JWK is for signing
          && key.kty === 'RSA' // We are only supporting RSA
          && key.kid           // The `kid` must be present to be useful for later
          && key.x5c && key.x5c.length, // Has useful public keys (we aren't using n or e)
        ).map((key) => {
          return { kid: key.kid, nbf: key.nbf, publicKey: certToPEM(key.x5c[0]) };
        });

      // If at least a single signing key doesn't exist we have a problem... Kaboom.
      if (!signingKeys.length) {
        return cb(new JwksError('The JWKS did not contain any signing keys'));
      }

      // Returns all of the available signing keys.
      return cb(null, signingKeys);
    };

    this.getJwks(callback);
  }
}

function certToPEM(cert: string): string {

  const match = cert.match(/.{1,64}/g);
  if (match) {
    cert = match.join('\n');
    cert = `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----\n`;
    return cert;
  }

  return '';
}

type GetSigningKeysCallback = (err: Error | null, signingKey?: ISigningKeyPem[]) => void;

type GetJwksCallback = (err: Error | null, signingKey?: ISigningKey[]) => void;

interface IJwksResponseBody {
  keys: ISigningKey[];
}

interface ISigningKey {
  alg: string;
  kty: string;
  use: string;
  x5c: string[];
  n: string;
  e: string;
  kid: string;
  x5t: string;
  nbf: string;
}

export interface ISigningKeyPem {
  kid: string;
  nbf: string;
  publicKey: string;
}

class SigningKeyNotFoundError extends Error {}

class JwksError extends Error {}

export interface IJwksClient {
  getSigningKey: (kid: string) => Promise<ISigningKeyPem>;
}
