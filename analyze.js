require('dotenv').config({ override: false });

const Groq   = require('groq-sdk');
const prompt = require('./prompt');

async function analyze(crawlerData) {
    // Leer la key en cada llamada — así toma el valor correcto de Railway
    const client = new Groq({ apiKey: process.env.GROQ_API_KEY });

    const finalPrompt = prompt.replace(
        '{{DATOS_CRAWLER}}',
        JSON.stringify(crawlerData, null, 2)
    );

    const response = await client.chat.completions.create({
        model: 'llama-3.3-70b-versatile',
        messages: [{ role: 'user', content: finalPrompt }]
    });

    return response.choices[0].message.content;
}

module.exports = analyze;
