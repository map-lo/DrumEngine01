/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./app.js",
        "./preset-browser.js",
        "./partials/**/*.hbs",
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
