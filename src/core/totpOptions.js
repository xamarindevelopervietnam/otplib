import hotpOptions from './hotpOptions';
import totpSecret from './totpSecret';

const defaultOptions = {
  createHmacSecret: totpSecret,
  epoch: null,
  step: 30,
};

/**
 * Generates options for TOTP
 *
 * @module core/totpOptions
 * @param {number} options.digits - the output token length
 * @param {string} options.epoch - starting time since the UNIX epoch. Used to calculate the counter
 * @param {number} options.step - time step in seconds
 * @return {object}
 */
function totpOptions(options = {}) {
  let opt = {
    ...hotpOptions(),
    ...defaultOptions,
    ...options
  };

  opt.epoch = typeof opt.epoch === 'number'
    ? opt.epoch * 1000
    : new Date().getTime();

  return opt;
}

export default totpOptions;
