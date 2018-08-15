import { totpCheckWithWindow } from 'otplib-core';

/**
 * Checks the provided OTP token against system generated token
 * Returns the delta (window) which token passes.
 * Returns null otherwise.
 *
 * @module otplib-authenticator/checkDelta
 * @param {string} token - the OTP token to check
 * @param {string} secret - your secret that is used to generate the token
 * @param {object} options - options which was used to generate it originally
 * @return {integer | null}
 */
function checkDelta(token, secret, options) {
  const decodedSecret = options.base32Decode(secret);
  return totpCheckWithWindow(token, decodedSecret, options);
}

export default checkDelta;
