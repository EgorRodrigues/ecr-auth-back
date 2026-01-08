import 'dotenv/config';
import { app } from './app';

const port = Number(process.env.PORT ?? 8080);
app
  .listen({
    port,
    host: '0.0.0.0',
  })
  .then(() => {
    console.log(`HTTP Server Running on http://localhost:${port}`);
  });
