let customer = "Wes Bos";
let freelancer = "Byron Dunkley";
//let date "05-01-21";
let services = "Web development"

const contractTemplate = await Deno.readTextFile("./template.txt");
const contract = contractTemplate
                    .replaceAll("[customer]", customer)
                    .replaceAll("[freelancer]", freelancer)
                    //.replaceAll("[date]", date)
                    .replaceAll("[services]", services);

const file = await Deno.writeTextFile(`${customer}-contract.txt`, contract)

console.log('contract complete');

/**
 * 
 * deno run --allow-write --allow-read contract.ts
 */
