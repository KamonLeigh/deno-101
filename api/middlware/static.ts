import { Context, send } from "https://deno.land/x/oak@v6.3.2/mod.ts";

export async function staticFiles (ctx: Context) {
        await send(ctx, ctx.request.url.pathname, {
            root: `${Deno.cwd()}/static`,
            index: "index.html"
        });
}