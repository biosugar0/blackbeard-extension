import { Context, Next } from 'hono';
import { fromBER } from 'asn1js';
import { Sequence, Integer } from 'asn1js';

interface GitHubKeysPayload {
	readonly public_keys: ReadonlyArray<{
		key: string;
		key_identifier: string;
		is_current: boolean;
	}>;
}

const GITHUB_KEYS_URI = 'https://api.github.com/meta/public_keys/copilot_api';

function padStart(data: Readonly<Uint8Array>, totalLength: number): Uint8Array {
	if (data.length === totalLength) return data;
	if (data.length > totalLength) {
		if (data.length === totalLength + 1 && data[0] === 0) {
			return data.slice(1);
		}
		throw new Error('Invalid data length for ECDSA signature component');
	}
	const result = new Uint8Array(totalLength);
	result.set(data, totalLength - data.length);
	return result;
}

function parseASN1Signature(signatureBuffer: Readonly<Uint8Array>): Uint8Array {
	const asn1 = fromBER(signatureBuffer.buffer as ArrayBuffer);
	if (asn1.offset === -1) throw new Error('Failed to parse signature');

	const [r, s] = (asn1.result as Sequence).valueBlock.value;

	return new Uint8Array([
		...padStart(new Uint8Array((r as Integer).valueBlock.valueHexView), 32),
		...padStart(new Uint8Array((s as Integer).valueBlock.valueHexView), 32),
	]);
}

type MiddlewareReturn = Promise<Response | void>;
export const verifySignature = async (c: Context, next: Next): MiddlewareReturn => {
	const signature = c.req.header('Github-Public-Key-Signature');
	const keyId = c.req.header('Github-Public-Key-Identifier');
	const tokenForUser = c.req.header('X-GitHub-Token');

	if (!signature || !keyId) {
		c.status(400);
		return c.text('Missing signature headers');
	}

	const body = await c.req.text();

	const response = await fetch(GITHUB_KEYS_URI, {
		headers: {
			'User-Agent': 'Your-App-Name/0.0.1',
			...(tokenForUser && { Authorization: `Bearer ${tokenForUser}` }),
		},
	});

	if (!response.ok) {
		c.status(500);
		return c.text('Failed to fetch public keys');
	}

	const keys: GitHubKeysPayload = await response.json();
	const publicKeyEntry = keys.public_keys.find((key) => key.key_identifier === keyId);

	if (!publicKeyEntry) {
		c.status(401);
		return c.text('No matching public key found');
	}

	try {
		const pemToArrayBuffer = (pem: Readonly<string>): ArrayBuffer => {
			const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
			const binary = atob(b64);
			return Uint8Array.from(binary, (c) => c.charCodeAt(0)).buffer;
		};

		const publicKeyBuffer = pemToArrayBuffer(publicKeyEntry.key);
		const cryptoKey = await crypto.subtle.importKey('spki', publicKeyBuffer, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);

		const signatureBuffer = Uint8Array.from(atob(signature), (c) => c.charCodeAt(0));
		const rawSignature = parseASN1Signature(signatureBuffer);
		const encoder = new TextEncoder();
		const payloadBuffer = encoder.encode(body) as Readonly<Uint8Array>;

		const isValid = await crypto.subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-256' } }, cryptoKey, rawSignature, payloadBuffer);

		if (!isValid) {
			console.error('Invalid signature');
			return c.text('Invalid signature', 401);
		}

		console.log('Signature verified');
		await next();
	} catch (error: unknown) {
		console.error('Signature verification error:', error);
		return c.text('Signature verification failed', 500);
	}
};
