import { defineConfig } from 'vite';
import handlebars from 'vite-plugin-handlebars';

export default defineConfig({
    base: './',

    plugins: [
        handlebars({
            partialDirectory: './partials',
            helpers: {
                range: (start, end) => {
                    const result = [];
                    if (start <= end) {
                        for (let i = start; i <= end; i++) {
                            result.push(i);
                        }
                    } else {
                        for (let i = start; i >= end; i--) {
                            result.push(i);
                        }
                    }
                    return result;
                },
                add: (a, b) => a + b,
                subtract: (a, b) => a - b
            }
        }),
    ],

    server: {
        fs: {
            // Allow serving files from the project root (for fonts)
            allow: ['..', '../..']
        }
    },

    build: {
        rollupOptions: {
            output: {
                // Use consistent filenames without hashes for JUCE binary embedding
                entryFileNames: 'app.js',
                assetFileNames: (assetInfo) => {
                    // CSS files go to root as styles.css
                    if (assetInfo.name && assetInfo.name.endsWith('.css')) {
                        return 'styles.css';
                    }
                    // Fonts and other assets keep their original names in assets folder
                    return 'assets/[name][extname]';
                }
            }
        }
    }
})
