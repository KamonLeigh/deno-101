const fileNames = Deno.args
console.log("filename", fileNames)

/*
 * Denn run read.ts Hello
 * will print filename [ "Hello" ]
 * based on console.log("filename", fileName)
 */

    if (fileNames.length > 0) {
        for (const fileName of fileNames) {
            const file = await Deno.readTextFile(fileName);
            console.log("file", file);
        }
    } else {
        const file = await Deno.readTextFile('./text.txt');
        console.log("file", file);
    }

 /**
  * The above code will read file
  * Deno run --allow-read  read.ts ./text.txt
  *  -will print 'file Hello from file' for else 
  * state
  */