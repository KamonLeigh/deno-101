import { Context } from "https://deno.land/x/oak@v6.3.2/mod.ts";
export async function timing(ctx: Context, next: () => Promise<void>) {
    const startTime = Date.now();
    await next()
    const endTime = Date.now();
    const difference = endTime - startTime;
    ctx.response.headers.set("X-Response-Time", `${difference}ms`)
}