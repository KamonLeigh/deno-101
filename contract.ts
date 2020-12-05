import Ask from "https://deno.land/x/ask/mod.ts";

const ask = new Ask();

const answers = await ask.prompt([
    {
        name: "customer",
        type: "input",
        message: "Who is the customer?"
    },
    {
        name: "freelancer",
        type: "input",
        message: "Who is the freelancer?"
    },
    {
        name: "services",
        type: "input",
        message: "What are services are provided?"
    }
]);

const { customer, freelancer, services } = answers;

const contractTemplate = await Deno.readTextFile("./template.txt");
const contract = contractTemplate
                    .replaceAll("[customer]", customer)
                    .replaceAll("[freelancer]", freelancer)
                    //.replaceAll("[date]", date)
                    .replaceAll("[services]", services);

await Deno.writeTextFile(`${customer}-contract.txt`, contract)

console.log('contract complete');

/**
 * 
 * deno run --allow-write --allow-read contract.ts
 */
