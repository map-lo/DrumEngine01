import { defineConfig } from 'vite';

export default defineConfig({
    base: './',

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
