const { chromium } = require('playwright');

async function scanWebsite(url) {

    const browser = await chromium.launch({
        headless: true
    });

    const page = await browser.newPage();

    await page.goto(url, {
        waitUntil: 'networkidle'
    });

    const title = await page.title();

    const links = await page.$$eval('a', links =>
        links.map(link => ({
            text: (link.innerText || '').trim(),
            href: link.href
        }))
    );

    const forms = await page.$$eval('form', forms =>
        forms.map(form => {

            const fields = [];

            form.querySelectorAll('input, textarea, select')
                .forEach(field => {

                    fields.push({
                        name: field.name || '',
                        type: field.type || field.tagName
                    });

                });

            return {
                action: form.action || '',
                fields
            };

        })
    );

    const pageText = (
        await page.textContent('body')
    ).toLowerCase();

    const scripts = await page.$$eval(
        'script',
        scripts => scripts.map(s =>
            s.src || s.innerHTML
        )
    );

    const scriptText = scripts.join(' ');

    const trackers = [];

    if (scriptText.includes('googletagmanager'))
        trackers.push('Google Tag Manager');

    if (
        scriptText.includes('gtag(') ||
        scriptText.includes('google-analytics')
    )
        trackers.push('Google Analytics');

    if (
        scriptText.includes('facebook.net') ||
        scriptText.includes('fbq(')
    )
        trackers.push('Meta Pixel');

    if (scriptText.includes('clarity'))
        trackers.push('Microsoft Clarity');

    if (scriptText.includes('hotjar'))
        trackers.push('Hotjar');

    if (scriptText.includes('linkedin'))
        trackers.push('LinkedIn Insight');

    const privacyPolicy = links.some(link =>
        link.text.toLowerCase().includes('privacidad')
    );

    const cookiePolicy = links.some(link =>
        link.text.toLowerCase().includes('cookie')
    );

    const cookieBanner =
        pageText.includes('cookie');

    const rejectButton =
        pageText.includes('rechazar') ||
        pageText.includes('reject');

    const rightsMechanism =
        pageText.includes('portabilidad') ||
        pageText.includes('rectificación') ||
        pageText.includes('eliminación') ||
        pageText.includes('supresión');

    const response = await page.goto(url);

    const headers = response.headers();

    const securityHeaders = {
        hsts: !!headers['strict-transport-security'],
        csp: !!headers['content-security-policy'],
        xFrameOptions: !!headers['x-frame-options'],
        referrerPolicy: !!headers['referrer-policy']
    };

    await browser.close();

    return {
        url,
        title,
        privacyPolicy,
        cookiePolicy,
        cookieBanner,
        rejectButton,
        rightsMechanism,
        trackers,
        forms,
        securityHeaders
    };
}

module.exports = scanWebsite;

// Solo se ejecuta si corres: node scanWebsite.js directamente
if (require.main === module) {
    (async () => {
        const result = await scanWebsite('https://shellti.com');
        console.log(JSON.stringify(result, null, 2));
    })();
}
