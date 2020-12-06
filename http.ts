import { Application, send, Router, Status } from './deps.ts';
import { bold, yellow, red, green } from "https://deno.land/std@0.77.0/fmt/colors.ts"
import { getMovies, getMovie } from "./api/movies/methods.ts";

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
}).get('/api/movies', async(ctx) => {
    console.log('movies route')
    const movies = await getMovies();
    ctx.response.body = movies;
})
.get('/api/movie/:id', async(ctx) => {
    const movies = await getMovie(ctx.params.id);
    ctx.response.body = movies;
})


// logger
app.use( async(ctx, next) => {
    await next();
    const responseTime = ctx.response.headers.get("X-Response-Time")
    console.log(`${ctx.request.method}: ${ctx.request.url}:${responseTime}`) 

})

// timer
app.use(async (ctx, next) => {
    const startTime = Date.now();
    await next()
    const endTime = Date.now();
    const difference = endTime - startTime;
    ctx.response.headers.set("X-Response-Time", `${difference}ms`)
})


// error
app.use(async(ctx, next) => {
    try {
        await next()
    } catch(e) {
        // log error
        console.error("error middleware", red(e.message), e.status);

        if (e.status === Status.NotFound) {
            // send page to front end
            await send(ctx, '404.html', {
                root: `${Deno.cwd()}/static`
            })
        } else {
            throw e
        }

    }

})

app.use(router.routes());
app.use( async (ctx) => {
   

       await send(ctx, ctx.request.url.pathname, {
           root: `${Deno.cwd()}/static`,
           index: "index.html"
       });
  
})

app.addEventListener("listen", ({ hostname, port}) => {
    console.log(
        bold("Start listening on ") + yellow(`${hostname}:${port}`)
    )
})

await app.listen({ hostname: "127.0.01", port: 8000 });