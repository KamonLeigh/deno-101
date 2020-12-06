import {  Router } from '../deps.ts';

import { getMovies, getMovie } from "./movies/methods.ts";

export const router = new Router();

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

