/**
 * This code performes breaking JWT token secret using brute-force attack.
 */
const Combinatorics = require('js-combinatorics');
const JWT = require('./jwt');

const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODY5IiwibmFtZSI6IkVsb24gTXVzayIsInNvbHV0aW9uIjoiaHR0cHM6Ly9naXRodWIuY29tL2x1a2l4L2p3dCJ9.hBPk4rtII_TNnuBOrCDQ0suuP4TzceMNDvRVWmDgN4c';

const secretExpectedLength = 5;
const alphabet = 'abcdefghijklmnoprstuvwxyz'.split('');
const baseN = Combinatorics.baseN(alphabet, secretExpectedLength);
let foundSecret = null;

console.time('Execution time');
for(let n = 0; n < alphabet.length**secretExpectedLength; n++) {
  const secret = baseN.nth(n).join('');
  if (JWT.verify(token, secret)) {
    foundSecret = secret;
    break;
  }
}
console.timeEnd('Execution time');
console.log(foundSecret);