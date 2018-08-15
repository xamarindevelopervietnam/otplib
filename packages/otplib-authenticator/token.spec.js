import * as core from 'otplib-core';
import token from './token';

describe('token', () => {
  it('should return expected result', () => {
    const totpToken = jest
      .spyOn(core, 'totpToken')
      .mockImplementation(() => 'result');

    const options = { test: 1, base32Decode: jest.fn() };

    options.base32Decode.mockImplementation(() => 10);

    token('test', options);

    expect(options.base32Decode).toHaveBeenCalledTimes(1);
    expect(options.base32Decode).toHaveBeenCalledWith('test');

    expect(totpToken).toHaveBeenCalledTimes(1);
    expect(totpToken).toHaveBeenCalledWith(10, options);
  });
});
