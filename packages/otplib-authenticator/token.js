import { totpToken } from 'otplib-core';

/**
 * Generates the Authenticator OTP code
 *
 * @module otplib-authenticator/token
 * @param {string} secret - your secret that is used to generate the token
 * @param {object} options - additional options.
 * @return {number} OTP Code
 */
function token(secret, options) {
  const decodedSecret = options.base32Decode(secret);
  return totpToken(decodedSecret, options);
}

export default token;
