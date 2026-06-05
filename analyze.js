require('dotenv').config();

const Groq = require('groq-sdk');

const prompt = require('./prompt');

const client = new Groq({
    apiKey: process.env.GROQ_API_KEY
});

async function analyze(crawlerData) {

    const finalPrompt = prompt.replace(
        '{{DATOS_CRAWLER}}',
        JSON.stringify(crawlerData, null, 2)
    );

    const response =
        await client.chat.completions.create({
            model: 'llama-3.3-70b-versatile',
            messages: [
                {
                    role: 'user',
                    content: finalPrompt
                }
            ]
        });

    return response.choices[0].message.content;
}

module.exports = analyze;
