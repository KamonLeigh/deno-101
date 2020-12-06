import { Application, send, Router, Status } from './deps.ts';
import { bold, yellow, red, green } from "https://deno.land/std@0.77.0/fmt/colors.ts"
import { logger } from './api/middlware/logger.ts';
import { timing } from './api/middlware/timing.ts';
import { error } from './api/middlware/error.ts';
import { staticFiles } from './api/middlware/static.ts'

import { router } from './api/routes.ts'



// Deno run -r = reload importss

const app = new Application();


// logger
app.use(logger);

// timer
app.use(timing);

// error
app.use(error);

app.use(router.routes());
app.use(staticFiles);

app.addEventListener("listen", ({ hostname, port}) => {
    console.log(
        bold("Start listening on ") + yellow(`${hostname}:${port}`)
    )
})

await app.listen({ hostname: "127.0.01", port: 8000 });