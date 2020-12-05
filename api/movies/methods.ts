export async function getMovies() {
    return ({
        data: [
            {
                title: "Spiderman"
            },
            {
                title: "Batman"
            }
        ]
    })
}

export async function getMovie(id?: string) {
    if (!id) return { data: {}};
    return {
        data: 
            {
                id,
                title: "Spiderman"
            }
            
    }
}