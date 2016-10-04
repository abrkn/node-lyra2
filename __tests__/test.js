// Generated with create-vectors (compile with npm run compile-create-vectors)

test('lyra hash', () => {
  const lyra2 = require('..');
  const password = new Buffer('the password');
  const salt = new Buffer('the salt');
  const expected = 'c4bb06266131c809fa985602bb03c3fefa318284c91465ae243d0387cb909d52';
  const actual = lyra2.hash(password, salt, 2, 1000, 256);

  expect(actual.toString('hex')).toBe(expected);
});
