const sha256 = require('js-sha256');
const base64url = require('base64url');

const stringToBase64 = (str) => base64url(str);
const base64ToString = (str) => base64url.decode(str);
const hexStringToBase64 = (str) => base64url.fromBase64(Buffer.from(str, 'hex').toString('base64'));

const encodeObject = (object) => {
	return stringToBase64(JSON.stringify(object));
};

const decodeObject = (object) => {
	return JSON.parse(base64ToString(object));
};

/**
 * Creates signed token.
 */
const createToken = ({ header, payload, secret }) => {
	const encodedHeader = encodeObject(header);
	const encodedPayload = encodeObject(payload);
	
	const siganture = sha256.hmac(secret, [encodedHeader, encodedPayload].join('.'));
	const base64Signature = hexStringToBase64(siganture);

	return [encodedHeader, encodedPayload, base64Signature].join('.');
}

/**
 * Verifies token signature. Returns true if signature is correct or false otherwise.
 */
const verifyToken = (token, secret) => {
	if (token.split('.').length < 3) {
		return false;
	}

	const [encodedHeader, encodedPayload, signature] = token.split('.');
	
	const expectedSiganture = sha256.hmac(secret, [encodedHeader, encodedPayload].join('.'));
	const expectedBase64Signature = hexStringToBase64(expectedSiganture);

	return expectedBase64Signature === signature;
}

/**
 * Returns an object with decoded header and payload.
 */
const decodeToken = (token) => {
	const [encodedHeader, encodedPayload] = token.split('.');
	return {
		header: decodeObject(encodedHeader),
		payload: decodeObject(encodedPayload),
	}
}

module.exports = {
	create: createToken,
	verify: verifyToken,
	decode: decodeToken,
};