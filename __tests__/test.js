// Generated with create-vectors (compile with npm run compile-create-vectors)

test('lyra hash', () => {
  const lyra2 = require('..');
  const password = new Buffer('the password');
  const salt = new Buffer('the salt');
  const expected = 'eeec8cf45a35a10ff0ca37e044cfa6b83978f3bad36905ce2d796e1631a2bcee';
  const actual = lyra2.hash(password, salt, 2, 1000, 256);

  expect(actual.toString('hex')).toBe(expected);
});
