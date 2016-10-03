// Generated with create-vectors (compile with npm run compile-create-vectors)

test('lyra hash', () => {
  const lyra2 = require('..');
  const input = new Buffer('fest');
  const expected = 'b01f702c8aad90e13d74ea996aac42d7218523e4e07c9206d8488ba5cf17ac44';
  const actual = lyra2.hash(input, 2, 1000, 256);

  expect(actual.toString('hex')).toBe(expected);
});
