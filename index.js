const JWT = require('./jwt');

const header = {
	alg: 'HS256',
  typ: 'JWT',
};

const payload = {
	sub: '1234567890',
  name: 'John Doe',
  iat: 1516239022,
};

const secret = 'secret string';

const token = JWT.create({ header, payload, secret: 'secret string' });
const verificationResult = JWT.verify(token, secret);
const decodedToken = JWT.decode(token);

console.log(token);
console.log(verificationResult);
console.log(decodedToken);