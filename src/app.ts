import { Hono } from 'hono';
import { verifySignature } from './middlewares/verifySignature';
import { handlePost } from './routes/index';

const app = new Hono();

app.get('/', (c) => {
	return c.html(`
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>kurohige-sample</title>
  <link rel="icon" href="https://cdn.jsdelivr.net/gh/twitter/twemoji@14.0.2/assets/72x72/1f3f4-200d-2620-fe0f.png" type="image/png">
  <style>
    body {
      font-family: Arial, sans-serif;
      text-align: center;
      margin-top: 50px;
    }
    h1 {
      color: #333;
    }
  </style>
</head>
<body>
  <h1>Blackbeard is ready!</h1>
  <footer>
    <p>This is a sample app for github copilot extension agent</p>
  </footer>
</body>
</html>
  `);
});

app.post('/', verifySignature, handlePost);

export default app;
