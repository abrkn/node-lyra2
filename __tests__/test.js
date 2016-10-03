// Generated with https://github.com/bsdphk/PHC
// $ ../bin/Lyra2 fest fest 32 2 1000
// Inputs:
// 	Password: fest
// 	Password Size: 4
// 	Salt: fest
// 	Output Size: 32
// ------------------------------------------------------------------------------------------------------------------------------------------
// Parameters:
// 	T: 2
// 	R: 1000
// 	C: 256
// 	Memory: 24576000 bits
// ------------------------------------------------------------------------------------------------------------------------------------------
// Output:
//
// 	K: 72|1c|e6|e7|78|dc|30|8c|37|f0|9a|e0|3c|18|9e|68|e7|74|b9|4|21|d9|fd|d3|4f|91|ad|fb|4c|ac|2a|5d|
// ------------------------------------------------------------------------------------------------------------------------------------------

test('lyra hash', () => {
  const lyra2 = require('..');
  const input = new Buffer('fest');
  const expected = '721ce6e778dc308c37f09ae03c189e68e774b90421d9fdd34f91adfb4cac2a5d';
  const actual = lyra2.hash(input, 2, 1000, 256);

  expect(actual.toString('hex')).toBe(expected);
});
