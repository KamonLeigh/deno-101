import { Context, Status, send } from "https://deno.land/x/oak@v6.3.2/mod.ts";
import { red } from "https://deno.land/std@0.77.0/fmt/colors.ts"



export async function error (ctx: Context, next: () => Promise<void>) {
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

}