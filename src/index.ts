import { Hono } from 'hono';
import { Octokit } from '@octokit/core';
import crypto from 'crypto';

const app = new Hono();

const GITHUB_KEYS_URI = 'https://api.github.com/meta/public_keys/copilot_api';

interface PublicKey {
	key: string;
	key_identifier: string;
	is_current: boolean;
}

interface GitHubPublicKeys {
	public_keys: PublicKey[];
}

async function verifySignature(payload: string, signature: string, keyId: string, tokenForUser: string | null): Promise<boolean> {
	try {
		if (!payload || !signature || !keyId) {
			throw new Error('Invalid input parameters');
		}

		const headers: HeadersInit = {
			'User-Agent': 'Blackbeard-Extension/0.0.1',
			...(tokenForUser && { Authorization: `Bearer ${tokenForUser}` }),
		};

		const response = await fetch(GITHUB_KEYS_URI, { headers });
		if (!response.ok) {
			throw new Error(`Failed to fetch public keys: ${response.statusText}`);
		}

		const keys: GitHubPublicKeys = await response.json();
		const publicKeyEntry = keys.public_keys.find((key) => key.key_identifier === keyId);
		if (!publicKeyEntry) {
			throw new Error('No matching public key found');
		}

		const pemToArrayBuffer = (pem: string): ArrayBuffer => {
			const b64 = pem
				.replace(/-----BEGIN PUBLIC KEY-----/, '')
				.replace(/-----END PUBLIC KEY-----/, '')
				.replace(/\s/g, '');
			const binary = atob(b64);
			const buffer = new Uint8Array(binary.length);
			for (let i = 0; i < binary.length; i++) {
				buffer[i] = binary.charCodeAt(i);
			}
			return buffer.buffer;
		};

		const publicKeyBuffer = pemToArrayBuffer(publicKeyEntry.key);

		const cryptoKey = await crypto.subtle.importKey('spki', publicKeyBuffer, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);

		const signatureBuffer = Uint8Array.from(atob(signature), (c) => c.charCodeAt(0));
		console.log('Raw Signature Buffer:', signatureBuffer);

		const asn1Signature = parseASN1Signature(signatureBuffer);

		const encoder = new TextEncoder();
		const payloadBuffer = encoder.encode(payload);

		const isValid = await crypto.subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-256' } }, cryptoKey, asn1Signature, payloadBuffer);

		return isValid;
	} catch (error) {
		console.error('Signature verification error:', error);
		return false;
	}
}

function parseASN1Signature(signature: Uint8Array): Uint8Array {
	if (signature[0] !== 0x30) {
		throw new Error('Invalid ASN.1 signature: Expected SEQUENCE (0x30)');
	}

	const totalLength = signature[1];
	if (totalLength + 2 !== signature.length) {
		throw new Error('Invalid ASN.1 signature length');
	}

	// R部分を解析
	const rTag = signature[2];
	if (rTag !== 0x02) {
		throw new Error('Invalid ASN.1 signature: Expected INTEGER (0x02) for R');
	}

	const rLength = signature[3];
	const rStart = 4;
	let r = signature.slice(rStart, rStart + rLength);

	// S部分を解析
	const sTag = signature[rStart + rLength];
	if (sTag !== 0x02) {
		throw new Error('Invalid ASN.1 signature: Expected INTEGER (0x02) for S');
	}

	const sLength = signature[rStart + rLength + 1];
	const sStart = rStart + rLength + 2;
	let s = signature.slice(sStart, sStart + sLength);

	// 先頭の余分なゼロを削除（符号ビットを除去）
	if (r.length > 32 && r[0] === 0x00) {
		r = r.slice(1);
	}
	if (s.length > 32 && s[0] === 0x00) {
		s = s.slice(1);
	}

	// 64バイトの結果を生成
	const result = new Uint8Array(64);
	result.set(r, 32 - r.length); // Rをゼロパディングして配置
	result.set(s, 64 - s.length); // Sをゼロパディングして配置

	return result;
}

app.post('/', async (c) => {
	// 署名とキーIDのヘッダーを取得
	const signature = c.req.header('Github-Public-Key-Signature');
	const keyId = c.req.header('Github-Public-Key-Identifier');
	const tokenForUser = c.req.header('X-GitHub-Token');

	// ヘッダーの存在確認
	if (!signature || !keyId) {
		return c.text('Missing signature headers', 400);
	}

	// リクエストボディの取得
	const body = await c.req.text(); // ストリームを読み取る

	// 署名の検証
	const isValid = await verifySignature(body, signature, keyId, tokenForUser ?? null);
	if (!isValid) {
		console.error('Invalid signature');
		return c.text('Invalid signature', 401);
	}

	if (!tokenForUser) {
		return c.text('GitHub token is required', 400);
	}

	const octokit = new Octokit({ auth: tokenForUser });
	const payload = JSON.parse(body);

	try {
		const user = await octokit.request('GET /user');
		const username = user.data.login;
		console.log('User:', username);

		const messages = payload.messages || [];
		messages.unshift(
			{
				role: 'system',
				content: 'You are a helpful assistant that replies to user messages as if you were the Blackbeard Pirate.',
			},
			{
				role: 'system',
				content: `Start every response with the user's name, which is @${username}`,
			},
		);

		const model = 'gpt-4o';
		const requestBody = {
			messages,
			model,
			stream: true,
		};

		const copilotLLMResponse = await fetch('https://api.githubcopilot.com/chat/completions', {
			method: 'POST',
			headers: {
				authorization: `Bearer ${tokenForUser}`,
				'content-type': 'application/json',
			},
			body: JSON.stringify(requestBody),
		});

		if (!copilotLLMResponse.body) {
			throw new Error('No response body from Copilot API');
		}

		return new Response(copilotLLMResponse.body, {
			headers: { 'Content-Type': 'application/json' },
		});
	} catch (error) {
		console.error('Error:', error);
		return c.text(`Error: ${(error as Error).message}`, 500);
	}
});

export default app;
