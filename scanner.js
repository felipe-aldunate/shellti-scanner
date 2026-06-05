const scanWebsite = require('./scanWebsite');
const analyze = require('./analyze');

(async () => {

    const url = process.argv[2];

    if (!url) {
        console.log('Uso: node scanner.js https://empresa.cl');
        process.exit();
    }

    console.log('Escaneando...');

    const crawlerData =
        await scanWebsite(url);

    console.log('Analizando...');

    const result =
        await analyze(crawlerData);

    console.log(result);

})();
