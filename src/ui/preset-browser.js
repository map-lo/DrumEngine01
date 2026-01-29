// DrumEngine01 Preset Browser UI

class PresetBrowserUI {
    constructor() {
        this.presetList = [];
        this.filteredPresets = [];
        this.selectedTags = new Set();
        this.searchTerm = '';
        this.currentPresetIndex = -1;

        this.initializeElements();
        this.attachEventListeners();

        if (window.__JUCE__ && window.__JUCE__.backend && window.__JUCE__.backend.emitEvent) {
            window.__JUCE__.backend.emitEvent('pageReady', {});
        }

        this.sendMessage('requestPresetList');
        this.sendMessage('requestUpdate');
    }

    initializeElements() {
        this.searchInput = document.getElementById('presetSearch');
        this.tagsContainer = document.getElementById('presetTags');
        this.listContainer = document.getElementById('presetList');
        this.closeButton = document.getElementById('closePresetBrowser');
    }

    attachEventListeners() {
        if (this.searchInput) {
            this.searchInput.addEventListener('input', (event) => {
                this.searchTerm = event.target.value || '';
                this.render();
            });
        }

        if (this.closeButton) {
            this.closeButton.addEventListener('click', () => {
                // Send message to parent window to close browser
                if (window.parent !== window) {
                    window.parent.postMessage({ action: 'closePresetBrowser' }, '*');
                } else {
                    this.sendMessage('closePresetBrowser');
                }
            });
        }

        // Listen for messages from parent window
        window.addEventListener('message', (event) => {
            console.log('PresetBrowserUI received message:', event.data);
            if (event.data && event.data.action) {
                switch (event.data.action) {
                    case 'updatePresetList':
                        if (event.data.presets) {
                            this.updatePresetList(event.data.presets);
                        }
                        break;
                    case 'updateState':
                        if (event.data.state) {
                            this.updateState(event.data.state);
                        }
                        break;
                }
            }
        });
    }

    sendMessage(action, data = {}) {
        const message = { action, ...data };
        if (window.__JUCE__ && window.__JUCE__.backend && window.__JUCE__.backend.emitEvent) {
            window.__JUCE__.backend.emitEvent('fromWebView', message);
        }
    }

    updatePresetList(presets) {
        console.log('PresetBrowserUI.updatePresetList called with', presets.length, 'presets');
        this.presetList = presets.map((preset, index) => ({
            index,
            displayName: preset.displayName || 'Unnamed Preset',
            instrumentType: preset.instrumentType || 'Unknown',
            category: preset.category || ''
        }));
        console.log('Mapped preset list:', this.presetList);
        this.render();
    }

    updateState(state) {
        if (typeof state.currentPresetIndex !== 'undefined') {
            this.currentPresetIndex = state.currentPresetIndex;
            this.renderPresetList();
        }
    }

    render() {
        this.renderTags();
        this.renderPresetList();
    }

    getSearchFilteredPresets() {
        const query = this.searchTerm.trim().toLowerCase();
        if (!query) {
            return this.presetList.slice();
        }
        return this.presetList.filter((preset) =>
            preset.displayName.toLowerCase().includes(query)
        );
    }

    getTagFilteredPresets() {
        const searchFiltered = this.getSearchFilteredPresets();
        if (this.selectedTags.size === 0) {
            return searchFiltered;
        }
        return searchFiltered.filter((preset) => this.selectedTags.has(preset.instrumentType));
    }

    renderTags() {
        if (!this.tagsContainer) return;

        const tagFiltered = this.getTagFilteredPresets();

        const availableTags = new Set();
        tagFiltered.forEach((preset) => availableTags.add(preset.instrumentType));

        this.selectedTags.forEach((tag) => availableTags.add(tag));

        const tags = Array.from(availableTags).filter(Boolean).sort();

        this.tagsContainer.innerHTML = '';

        if (tags.length === 0) {
            const emptyTag = document.createElement('div');
            emptyTag.className = 'text-[10px] text-black text-opacity-50';
            emptyTag.textContent = 'No tags available';
            this.tagsContainer.appendChild(emptyTag);
            return;
        }

        tags.forEach((tag) => {
            const button = document.createElement('button');
            const isActive = this.selectedTags.has(tag);
            button.className = [
                'px-2',
                'py-1',
                'text-[10px]',
                'border-2',
                'border-black',
                'uppercase',
                'tracking-widest',
                'hover:bg-black',
                'hover:text-white',
                isActive ? 'bg-black text-white' : 'bg-white text-black'
            ].join(' ');
            button.textContent = tag;
            button.addEventListener('click', () => {
                if (this.selectedTags.has(tag)) {
                    this.selectedTags.delete(tag);
                } else {
                    this.selectedTags.add(tag);
                }
                this.render();
            });
            this.tagsContainer.appendChild(button);
        });
    }

    renderPresetList() {
        if (!this.listContainer) return;

        const filtered = this.getTagFilteredPresets();
        this.filteredPresets = filtered;

        this.listContainer.innerHTML = '';

        if (filtered.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'px-2 py-2 text-black text-opacity-50';
            empty.textContent = 'No presets found';
            this.listContainer.appendChild(empty);
            return;
        }

        filtered.forEach((preset) => {
            const item = document.createElement('button');
            const isSelected = preset.index === this.currentPresetIndex;
            item.className = [
                'w-full',
                'text-left',
                'px-2',
                'py-1',
                'hover:bg-black',
                'hover:text-white',
                isSelected ? 'bg-black text-white' : 'bg-white text-black'
            ].join(' ');
            item.textContent = preset.displayName;
            item.addEventListener('click', () => {
                this.currentPresetIndex = preset.index;
                this.sendMessage('loadPresetByIndex', { index: preset.index });
                this.renderPresetList();
            });
            this.listContainer.appendChild(item);
        });
    }
}

window.updateStateFromCpp = function (stateJson) {
    try {
        const state = typeof stateJson === 'string' ? JSON.parse(stateJson) : stateJson;
        if (window.presetBrowserUI) {
            window.presetBrowserUI.updateState(state);
        }
    } catch (e) {
        console.error('Error parsing state from C++:', e);
    }
};

window.updatePresetListFromCpp = function (presetsJson) {
    try {
        const presets = typeof presetsJson === 'string' ? JSON.parse(presetsJson) : presetsJson;
        if (window.presetBrowserUI) {
            window.presetBrowserUI.updatePresetList(presets);
        }
    } catch (e) {
        console.error('Error parsing preset list from C++:', e);
    }
};

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.presetBrowserUI = new PresetBrowserUI();
    });
} else {
    window.presetBrowserUI = new PresetBrowserUI();
}
