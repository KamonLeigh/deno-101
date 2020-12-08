//import { config } from "https://deno.land/x/dotenv@v1.0.1/mod.ts";
import "https://deno.land/x/dotenv@v1.0.1/load.ts"

import { Application, send, Router, Status } from './deps.ts';
import { bold, yellow, red, green } from "https://deno.land/std@0.77.0/fmt/colors.ts"
import { logger } from './api/middlware/logger.ts';
import { timing } from './api/middlware/timing.ts';
import { error } from './api/middlware/error.ts';
import { staticFiles } from './api/middlware/static.ts'

import { router } from './api/routes.ts'

/**
 *  Try and bundle file using the following methos
 *   deno bundle http.ts http.bundle.js
 */


//  denon run --allow-net --allow-read --allow-env  http.ts allow access to env
// denon run -A command that allows all
// console.log(config());
// const { API_KEY } = config();
// console.log(API_KEY);

console.log(Deno.env.get("API_KEY"));


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