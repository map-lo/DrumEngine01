/** @type {import('tailwindcss').Config} */
module.exports = {
    content: [
        "./index.html",
        "./app.js",
        "./preset-browser.js",
    ],
    theme: {
        extend: {
            fontFamily: {
                sans: ['Inter', 'system-ui', 'sans-serif'],
            },
        },
    },
    plugins: [],
}
