import { Application, send } from './deps.ts';
import { bold, yellow } from "https://deno.land/std@0.77.0/fmt/colors.ts"

const app = new Application();

// ctx is similar to ((req, res) => {}) cb in node 
// deno run --allow-net --allow-read http.ts

app.use( async (ctx) => {
   
   try {
       await send(ctx, ctx.request.url.pathname, {
           root: `${Deno.cwd()}/static`,
           index: "index.html"
       });
   } catch (e) {
        console.log('error', e);
   }
})

app.addEventListener("listen", ({ hostname, port}) => {
    console.log(
        bold("Start listening on ") + yellow(`${hostname}:${port}`)
    )
})

await app.listen({ hostname: "127.0.01", port: 8000 });