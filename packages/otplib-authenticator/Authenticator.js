import totp from 'otplib-totp';
import { secretKey } from 'otplib-utils';
import check from './check';
import checkDelta from './checkDelta';
import decodeKey from './decodeKey';
import encodeKey from './encodeKey';
import keyuri from './keyuri';
import token from './token';

const TOTP = totp.TOTP;

/**
 * Google Authenticator adapter
 *
 * ## References
 * -   http://en.wikipedia.org/wiki/Google_Authenticator
 *
 * ## Algorithm
 *
 * ```
 * secret := base32decode(secret)
 * message := floor(current Unix time / 30)
 * hash := HMAC-SHA1(secret, message)
 * offset := last nibble of hash
 * truncatedHash := hash[offset..offset+3]  //4 bytes starting at the offset
 * set the first bit of truncatedHash to zero  //remove the most significant bit
 * code := truncatedHash mod 1000000
 * pad code with 0 until length of code is 6
 *
 * return code
 * ```
 *
 * @class Authenticator
 * @module otplib-authenticator/Authenticator
 * @extends {TOTP}
 * @since 3.0.0
 */
class Authenticator extends TOTP {
  constructor() {
    super();
  }

  /**
   * returns an Authenticator class
   *
   * @return {class}
   */
  getClass() {
    return Authenticator;
  }

  /**
   * getter for defaultOptions
   *
   * @return {object}
   */
  get defaultOptions() {
    return {
      base32Decode: decodeKey,
      base32Encode: encodeKey,
      encoding: 'hex',
      epoch: null,
      step: 30,
      window: 0
    };
  }

  /**
   * @see {@link module:impl/authenticator/encodeKey}
   */
  encode(...args) {
    const opt = this.optionsAll;
    return opt.base32Encode(...args);
  }

  /**
   * @see {@link module:impl/authenticator/decodeKey}
   */
  decode(...args) {
    const opt = this.optionsAll;
    return opt.base32Decode(...args);
  }

  /**
   * @see {@link module:impl/authenticator/keyuri}
   */
  keyuri(...args) {
    return keyuri(...args);
  }

  /**
   * Generates and encodes a secret key
   *
   * @param {number} length - secret key length (not encoded key length)
   * @return {string}
   * @see {@link module:impl/authenticator/secretKey}
   * @see {@link module:impl/authenticator/encodeKey}
   */
  generateSecret(len = 20) {
    if (!len) {
      return '';
    }
    const opt = this.optionsAll;
    const secret = secretKey(len, opt);
    return opt.base32Encode(secret);
  }

  /**
   * @param {string} secret - base32 encoded string
   * @return {string}
   * @see {@link module:impl/authenticator/token}
   */
  generate(secret) {
    const opt = this.optionsAll;
    return token(secret || opt.secret, opt);
  }

  /**
   * Checks validity of token.
   * Passes instance options to underlying core function
   *
   * @param {string} token
   * @param {string} secret
   * @return {boolean}
   * @see {@link module:impl/authenticator/check}
   */
  check(token, secret) {
    const opt = this.optionsAll;
    return check(token, secret || opt.secret, opt);
  }

  /**
   * Checks validity of token.
   * Returns the delta (window) which token passes.
   * Returns null otherwise.
   * Passes instance options to underlying core function
   *
   * @param {string} token
   * @param {string} secret
   * @return {number | null}
   * @see {@link module:impl/authenticator/checkDelta}
   */
  checkDelta(token, secret) {
    const opt = this.optionsAll;
    return checkDelta(token, secret || opt.secret, opt);
  }
}

Authenticator.prototype.Authenticator = Authenticator;
Authenticator.prototype.utils = {
  check,
  checkDelta,
  decodeKey,
  encodeKey,
  keyuri,
  token
};
export default Authenticator;
