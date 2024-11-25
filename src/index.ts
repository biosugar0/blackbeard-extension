import { Hono } from 'hono';
import { Octokit } from '@octokit/core';
import { fromBER } from 'asn1js';
import { Sequence, Integer } from 'asn1js';

const app = new Hono();

// GitHubの公開鍵を取得するためのURL
const GITHUB_KEYS_URI = 'https://api.github.com/meta/public_keys/copilot_api';

interface PublicKey {
	key: string; // 公開鍵の内容（PEM形式）
	key_identifier: string; // 公開鍵の識別子
	is_current: boolean; // 現在有効な鍵かどうか
}

interface GitHubPublicKeys {
	public_keys: PublicKey[]; // 公開鍵の配列
}

// データの長さを調整するための関数
function padStart(data: Uint8Array, totalLength: number): Uint8Array {
	/*
    前提知識：
    - デジタル署名（特にECDSA署名）では、署名は2つの数値コンポーネント（rとs）から構成されます。
    - ECDSA P-256（secp256r1）では、これらの数値は32バイト（256ビット）の固定長である必要があります。
    - しかし、数値のバイナリ表現では、先頭のゼロが省略されることがあり、結果として期待する長さより短くなる場合があります。
    - また、符号を示すために余分なゼロバイトが付加され、長さが長くなることもあります。

    なぜこの操作が必要か：
    - 署名の検証では、rとsが正確に32バイトであることが求められます。
    - 長さが不足している場合は、ビッグエンディアン形式に従い、先頭にゼロを追加して32バイトに揃える必要があります。
    - 長さが超過している場合は、先頭の余分なゼロバイトを削除して32バイトにします。
    - これにより、署名の検証アルゴリズムが期待する形式にデータを整形します。
  */

	// データの長さが既に指定の長さ（32バイト）と一致している場合、そのまま返す
	if (data.length === totalLength) return data;
	// 長さが超過している場合は、先頭の余分なバイトを削除して指定の長さにする
	// 先頭の余分なゼロバイトは数値の値に影響しないため、削除して問題ありません
	// ASN.1エンコードでは、整数値が符号付きで表現されるため、値が正であっても最上位ビットが1の場合（つまり、値が2^255以上の場合）、負の数と誤解されないように先頭に余分なゼロバイトを付加します。
	if (data.length > totalLength) {
		// データが1バイト長い場合、先頭バイトがゼロであることを確認
		if (data.length === totalLength + 1) {
			if (data[0] !== 0) {
				throw new Error('Invalid signature format: leading byte must be zero when length is exceeded by 1');
			}
			return data.slice(1); // 先頭の0を除いて返す
		} else {
			throw new Error('Invalid data length for ECDSA signature component');
		}
	}

	// 長さが不足している場合は、先頭にゼロを追加して指定の長さにする
	const result = new Uint8Array(totalLength);
	result.set(data, totalLength - data.length);
	return result;
}

// 署名を検証する関数
async function verifySignature(
	payload: string, // 署名の対象となるデータ（ペイロード）
	signatureBase64: string, // Base64エンコードされた署名
	keyId: string, // 公開鍵の識別子
	tokenForUser: string | null, // ユーザーのGitHubトークン（オプション）
): Promise<boolean> {
	try {
		// 必要なパラメータが全て提供されているか確認
		if (!payload || !signatureBase64 || !keyId) {
			throw new Error('Invalid input parameters');
		}

		// GitHubの公開鍵を取得するためのヘッダーを設定
		const headers: HeadersInit = {
			'User-Agent': 'Blackbeard-Extension/0.0.1', // ユーザーエージェントを設定
			...(tokenForUser && { Authorization: `Bearer ${tokenForUser}` }), // トークンがあればAuthorizationヘッダーを追加
		};

		// GitHubから公開鍵を取得
		const response = await fetch(GITHUB_KEYS_URI, { headers });
		if (!response.ok) {
			throw new Error(`Failed to fetch public keys: ${response.statusText}`);
		}

		// 取得した公開鍵のリストをパース
		const keys: GitHubPublicKeys = await response.json();
		// 指定されたキーIDに対応する公開鍵を検索
		const publicKeyEntry = keys.public_keys.find((key) => key.key_identifier === keyId);
		if (!publicKeyEntry) {
			throw new Error('No matching public key found');
		}

		// PEM形式の公開鍵をArrayBufferに変換する関数
		const pemToArrayBuffer = (pem: string): ArrayBuffer => {
			// PEMのヘッダーとフッターを削除してBase64部分を抽出
			const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
			// Base64デコードしてバイナリデータに変換
			const binary = atob(b64);
			// バイナリデータをUint8Arrayに変換
			const buffer = new Uint8Array(binary.length);
			for (let i = 0; i < binary.length; i++) {
				buffer[i] = binary.charCodeAt(i);
			}
			return buffer.buffer; // ArrayBufferを返す
		};

		// 公開鍵をArrayBufferに変換
		// ArrayBufferはバイナリデータを扱うためのJavaScriptのオブジェクト
		const publicKeyBuffer = pemToArrayBuffer(publicKeyEntry.key);

		// 公開鍵をCryptoKeyオブジェクトにインポート
		const cryptoKey = await crypto.subtle.importKey(
			'spki', // 公開鍵の形式（SubjectPublicKeyInfo）
			publicKeyBuffer, // 公開鍵のバイナリデータ
			{ name: 'ECDSA', namedCurve: 'P-256' }, // 鍵のアルゴリズムと曲線
			false, // 鍵の抽出を禁止
			['verify'], // 使用目的（署名の検証）
		);

		// 署名をBase64デコードしてUint8Arrayに変換
		const signatureBuffer = Uint8Array.from(atob(signatureBase64), (c) => c.charCodeAt(0));

		// 署名を解析して、検証に適した形式に変換
		const rawSignature = parseASN1Signature(signatureBuffer);

		// ペイロードをUTF-8でエンコードしてUint8Arrayに変換
		const encoder = new TextEncoder();
		const payloadBuffer = encoder.encode(payload);

		// 署名を検証
		const isValid = await crypto.subtle.verify(
			{ name: 'ECDSA', hash: { name: 'SHA-256' } }, // 署名アルゴリズムとハッシュ関数
			cryptoKey, // 公開鍵
			rawSignature, // 署名（加工済み）
			payloadBuffer, // 検証対象のデータ（ペイロード）
		);

		return isValid; // 検証結果を返す（trueまたはfalse）
	} catch (error) {
		console.error('Signature verification error:', error);
		return false; // エラーが発生した場合は検証失敗とする
	}
}

// 署名を解析して、検証に適した形式に変換する関数
function parseASN1Signature(signatureBuffer: Uint8Array): Uint8Array {
	/*
    前提知識：
    - デジタル署名（特にECDSA署名）は、2つの数値コンポーネント（rとs）から構成されます。
    - これらの数値は、署名の生成と検証に使用されます。
    - 署名データは通常、ASN.1（Abstract Syntax Notation One）という標準的なデータ形式でエンコードされています。
    - ASN.1は、データをコンピュータ間でやり取りするための共通の形式を提供します。

    なぜ解析が必要か：
    - 署名データはASN.1形式でエンコードされているため、そのままでは署名の検証に使用できません。
    - まずASN.1形式からrとsの数値を取り出し、それらを適切なバイナリ形式に変換する必要があります。

    この関数の目的：
    - ASN.1形式の署名データを解析し、rとsの値を取り出します。
    - rとsを適切な長さに調整し、連結して署名検証に使用できる形式にします。
	- rとsとは、それぞれ署名の2つのコンポーネントで、それぞれ32バイトの固定長です。
  */

	// ASN.1のBERエンコーディングからデータを解析
	const asn1 = fromBER(signatureBuffer.buffer);
	if (asn1.offset === -1) {
		throw new Error('Failed to parse signature');
	}

	// 解析結果から、rとsの値を取得
	const sequence = asn1.result as Sequence;
	if (!sequence.valueBlock || sequence.valueBlock.value.length !== 2) {
		throw new Error('Invalid signature structure');
	}

	// rとsの値を整数として取得
	const rInteger = sequence.valueBlock.value[0] as Integer;
	const sInteger = sequence.valueBlock.value[1] as Integer;

	// rとsの値をバイナリデータに変換
	const rArray = new Uint8Array(rInteger.valueBlock.valueHexView);
	const sArray = new Uint8Array(sInteger.valueBlock.valueHexView);

	// rとsの長さを調整（必要に応じてゼロを追加または削除）
	const paddedR = padStart(rArray, 32);
	const paddedS = padStart(sArray, 32);

	// rとsを連結して、署名検証に使用する形式にする
	const rawSignature = new Uint8Array(64);
	rawSignature.set(paddedR, 0); // 先頭32バイトにrをセット
	rawSignature.set(paddedS, 32); // 次の32バイトにsをセット

	return rawSignature; // 加工済みの署名を返す
}

// POSTリクエストを処理するエンドポイントを定義
app.post('/', async (c) => {
	// リクエストヘッダーから署名とキーIDを取得
	const signature = c.req.header('Github-Public-Key-Signature'); // 署名
	const keyId = c.req.header('Github-Public-Key-Identifier'); // 公開鍵の識別子
	const tokenForUser = c.req.header('X-GitHub-Token'); // ユーザーのGitHubトークン

	// 署名とキーIDが存在するか確認
	if (!signature || !keyId) {
		return c.text('Missing signature headers', 400); // ヘッダーがない場合はエラーを返す
	}

	// リクエストボディを取得
	const body = await c.req.text(); // リクエストの内容をテキストとして取得

	// 署名の検証を実行
	const isValid = await verifySignature(body, signature, keyId, tokenForUser ?? null);
	if (!isValid) {
		console.error('Invalid signature');
		return c.text('Invalid signature', 401); // 署名が無効な場合はエラーを返す
	}

	// GitHubトークンが提供されているか確認
	if (!tokenForUser) {
		return c.text('GitHub token is required', 400); // トークンがない場合はエラーを返す
	}

	// GitHub APIを操作するためのクライアントを作成
	const octokit = new Octokit({ auth: tokenForUser });
	// リクエストボディをJSONとしてパース
	const payload = JSON.parse(body);

	try {
		// GitHub APIを使ってユーザー情報を取得
		const user = await octokit.request('GET /user');
		const username = user.data.login; // ユーザー名を取得
		console.log('User:', username);

		// チャットのメッセージリストを準備
		const messages = payload.messages || [];
		// システムメッセージを追加してチャットの設定を行う
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

		// 使用するモデルを指定
		const model = 'gpt-4o';
		// Copilot APIに送信するリクエストボディを作成
		const requestBody = {
			messages,
			model,
			stream: true, // ストリーミングレスポンスを要求
		};

		// GitHub CopilotのAPIにリクエストを送信
		const copilotLLMResponse = await fetch('https://api.githubcopilot.com/chat/completions', {
			method: 'POST',
			headers: {
				authorization: `Bearer ${tokenForUser}`, // ユーザーのトークンを使用
				'content-type': 'application/json',
			},
			body: JSON.stringify(requestBody), // リクエストボディをJSON形式で送信
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
