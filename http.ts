import { Application } from './deps.ts';

const app = new Application();

// ctx is similar to ((req, res) => {}) cb in node 
// deno run --allow-net http.ts

app.use((ctx) => {
    ctx.response.body = "Hello World!"
})

await app.listen({ port: 8000 });