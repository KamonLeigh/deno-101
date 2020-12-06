import { Context } from "https://deno.land/x/oak@v6.3.2/mod.ts";

 
 export async function logger(ctx:Context, next: () => Promise<void>) {
    await next();
    const responseTime = ctx.response.headers.get("X-Response-Time")
    console.log(`${ctx.request.method}: ${ctx.request.url}:${responseTime}`) 

}
