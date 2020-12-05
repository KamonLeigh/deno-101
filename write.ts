const file = await Deno.writeTextFile("write.txt", "Writing to file");
console.log("file written to write.txt");

/*
 * deno run --allow-write write.ts 
 * 
 */