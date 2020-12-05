import { Application, send, Router } from './deps.ts';
import { bold, yellow } from "https://deno.land/std@0.77.0/fmt/colors.ts"

const app = new Application();
const router = new Router()

router.get('/hi', (ctx) => {
    ctx.response.body = {
        hello: {
            from: {
                the: {
                    router: "hi"
                }
            }
        }
    }
})


app.use(router.routes());
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