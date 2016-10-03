test('lyra hash 1', () => {
  const lyra2 = require('..');
  const input = new Buffer('test');
  const output = lyra2.hash(input, 1, 2, 3);
	console.log(typeof output, !!output, output);

  // expect(output.toString('hex')).toBe('fest');
  expect(output.toString()).toBe('fest');
});
