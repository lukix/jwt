const sha256 = require('js-sha256');

const stringToBase64 = (str) => Buffer.from(str).toString('base64');
const base64ToString = (str) => Buffer.from(str, 'base64').toString();
const hexStringToBase64 = (str) => Buffer.from(str, 'hex').toString('base64');
const removeBase64Padding = (str) => str.replace(new RegExp('=', 'g'), '');

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
	const encodedHeader = removeBase64Padding(encodeObject(header));
	const encodedPayload = removeBase64Padding(encodeObject(payload));
	
	const siganture = sha256.hmac(secret, [encodedHeader, encodedPayload].join('.'));
	const base64Signature = removeBase64Padding(hexStringToBase64(siganture));

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
	const expectedBase64Signature = removeBase64Padding(hexStringToBase64(expectedSiganture));

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