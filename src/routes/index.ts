import { Context } from 'hono';
import { Octokit } from '@octokit/core';
import OpenAI from 'openai';

const tools: OpenAI.Chat.Completions.ChatCompletionTool[] = [
	{
		type: 'function',
		function: {
			name: 'getWeather',
			description: 'Get the current weather for a city',
			parameters: {
				type: 'object',
				properties: {
					city: {
						type: 'string',
						description: 'The city to get the weather for',
					},
				},
				required: ['city'],
				additionalProperties: false,
			},
		},
	},
];

async function getWeather(city: string) {
	console.log('Getting weather for:', city);
	return `The weather in ${city} is -10°C and snowing.`;
}

/**
 * ツールを呼び出すヘルパー関数
 */
async function callTool(toolCall: OpenAI.Chat.Completions.ChatCompletionMessageToolCall): Promise<string> {
	if (toolCall.type !== 'function') {
		throw new Error('Unexpected tool_call type:' + toolCall.type);
	}

	const args = JSON.parse(toolCall.function.arguments);
	switch (toolCall.function.name) {
		case 'getWeather':
			return await getWeather(args['city']);
		default:
			throw new Error('No function found');
	}
}

/**
 * 確認用SSEイベントを送信する関数
 */
function sendConfirmationSSE(toolCall: OpenAI.Chat.Completions.ChatCompletionMessageToolCall): Response {
	const city = JSON.parse(toolCall.function.arguments).city;

	// getWeatherしか実装していないので、固定の確認メッセージを返す
	const confirmationData = {
		type: 'action',
		title: 'kurohige-sample が天気調査能力を発動しようとしています。',
		message: `${city}の天気を調べることを許可しますか？`,
		confirmation: {
			id: `${toolCall.function.name}`,
			city: `${city}`,
		},
	};

	const encoder = new TextEncoder();
	const readableStream = new ReadableStream({
		start(controller) {
			const payload = `event: copilot_confirmation\ndata: ${JSON.stringify(confirmationData)}\n\n`;
			controller.enqueue(encoder.encode(payload));
			controller.close();
		},
	});

	return new Response(readableStream, {
		headers: {
			'Content-Type': 'text/event-stream',
			'Cache-Control': 'no-cache',
			Connection: 'keep-alive',
		},
	});
}

/**
 * ChatCompletionをストリームで返すための関数
 */
async function streamCompletion(openai: OpenAI, messages: any[], username: string): Promise<Response> {
	// 海賊風に回答させるためのシステムメッセージを追加
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

	const stream = await openai.chat.completions.create({
		messages: messages,
		model: 'gpt-4o',
		stream: true,
	});

	const encoder = new TextEncoder();
	const readableStream = new ReadableStream({
		async start(controller) {
			for await (const chunk of stream) {
				if (chunk.choices?.[0]?.finish_reason) {
					const data = JSON.stringify(chunk);
					const payload = `data: ${data}\n\n`;
					controller.enqueue(encoder.encode(payload));
					console.log('Stream completed.');
					controller.close();
					break;
				}
				const data = JSON.stringify(chunk);
				const payload = `data: ${data}\n\n`;
				controller.enqueue(encoder.encode(payload));
			}
			controller.close();
		},
	});

	return new Response(readableStream, {
		headers: {
			'Content-Type': 'text/event-stream',
			'Cache-Control': 'no-cache',
			Connection: 'keep-alive',
		},
	});
}

export const handlePost = async (c: Context) => {
	const tokenForUser = c.req.header('X-GitHub-Token');
	if (!tokenForUser) {
		return c.text('GitHub token is required', 400);
	}

	const octokit = new Octokit({ auth: tokenForUser });
	const body = await c.req.json();
	const messages = body.messages || [];
	const lastMessage = messages[messages.length - 1];
	console.log('Payload:', messages);

	try {
		const user = await octokit.request('GET /user');
		const username = user.data.login;
		console.log('User:', username);

		const openai = new OpenAI({
			baseURL: 'https://api.githubcopilot.com',
			apiKey: tokenForUser,
		});

		// 1. 確認結果が返ってきた場合の処理
		let toolExecuted = false;
		if (lastMessage?.copilot_confirmations) {
			for (const confirmation of lastMessage.copilot_confirmations) {
				if (confirmation.state === 'accepted') {
					// ユーザーが承認したのでツールを実行
					const toolCall: OpenAI.Chat.Completions.ChatCompletionMessageToolCall = {
						id: confirmation.confirmation.id,
						type: 'function',
						function: {
							name: confirmation.confirmation.id,
							arguments: JSON.stringify({ city: confirmation.confirmation.city }),
						},
					};

					const toolResultContent = await callTool(toolCall);
					const toolResultMessage = `This agent has activated the ability of ${confirmation.confirmation.id} and returned the following result: ${toolResultContent}`;
					messages.push({ content: toolResultMessage, role: 'system' });
					toolExecuted = true;
				}
			}
		}

		// 2. ツールがまだ実行されていない場合、ツールを呼ぶべきか確認
		if (!toolExecuted) {
			const toolResponse = await openai.chat.completions.create({
				model: 'gpt-4o',
				messages: messages,
				tools: tools,
				tool_choice: 'auto',
				stream: false,
			});

			const toolCall = toolResponse.choices?.[0]?.message?.tool_calls?.[0];
			if (toolCall) {
				// ユーザーにツールの実行確認を促すSSEを送信
				return sendConfirmationSSE(toolCall);
			}
		}

		// 3. ツール実行後、またはツール不要時は通常のレスポンス送信
		return await streamCompletion(openai, messages, username);
	} catch (error) {
		console.error('Error:', error);
		return c.text(`Error: ${(error as Error).message}`, 500);
	}
};
