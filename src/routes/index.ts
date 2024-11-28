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
	return `The weather in ${city} is 25°C and rainy.`;
}

async function callTool(tool_call: OpenAI.Chat.Completions.ChatCompletionMessageToolCall): Promise<any> {
	if (tool_call.type !== 'function') throw new Error('Unexpected tool_call type:' + tool_call.type);
	const args = JSON.parse(tool_call.function.arguments);
	switch (tool_call.function.name) {
		case 'getWeather':
			return await getWeather(args['city']);
		default:
			throw new Error('No function found');
	}
}

export const handlePost = async (c: Context) => {
	const tokenForUser = c.req.header('X-GitHub-Token');
	if (!tokenForUser) {
		return c.text('GitHub token is required', 400);
	}

	const octokit = new Octokit({ auth: tokenForUser });
	const body = await c.req.json();
	const messages = body.messages || [];

	try {
		const user = await octokit.request('GET /user');
		const username = user.data.login;
		console.log('User:', username);

		const baseUrl = 'https://api.githubcopilot.com';
		const openai = new OpenAI({
			baseURL: baseUrl,
			apiKey: tokenForUser,
		});

		try {
			const toolResponse = await openai.chat.completions.create({
				model: 'gpt-4o',
				messages: messages,
				tools: tools,
				tool_choice: 'auto',
				stream: false,
			});
			console.log('Tool response:', JSON.stringify(toolResponse, null, 2));

			if (toolResponse.choices?.[0]?.message?.tool_calls) {
				const toolCall = toolResponse.choices[0].message.tool_calls[0];
				if (toolCall) {
					const toolResultContent = await callTool(toolCall);

					const toolMessage = {
						content: toolResultContent,
						role: 'assistant',
					};
					messages.push(toolMessage);
				}
			}
		} catch (error) {
			console.error('Error:', error);
			return c.text(`Error: ${(error as Error).message}`, 500);
		}

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
	} catch (error) {
		console.error('Error:', error);
		return c.text(`Error: ${(error as Error).message}`, 500);
	}
};
