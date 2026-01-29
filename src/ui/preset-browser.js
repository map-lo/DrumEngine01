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
                if (window.drumEngineUI) {
                    window.drumEngineUI.togglePresetBrowser();
                }
            });
        }
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
            this.updateSelection();
        }
    }

    updateSelection() {
        // Update only the selected styling without re-rendering the entire list
        if (!this.listContainer) return;

        const buttons = this.listContainer.querySelectorAll('button');
        buttons.forEach((button, index) => {
            const preset = this.filteredPresets[index];
            if (!preset) return;

            const isSelected = preset.index === this.currentPresetIndex;
            if (isSelected) {
                button.classList.add('bg-white', '!bg-opacity-30');
                button.classList.remove('bg-black');
            } else {
                button.classList.remove('bg-white', '!bg-opacity-30');
                button.classList.add('bg-black');
            }
        });
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

        // Toggle visibility of the noTagsMessage element
        const noTagsMessage = document.getElementById('noTagsMessage');
        if (noTagsMessage) {
            if (tags.length === 0) {
                noTagsMessage.classList.remove('hidden');
            } else {
                noTagsMessage.classList.add('hidden');
            }
        }

        // Remove all tag buttons (but not the noTagsMessage element)
        Array.from(this.tagsContainer.children).forEach(child => {
            if (child.id !== 'noTagsMessage') {
                this.tagsContainer.removeChild(child);
            }
        });

        if (tags.length === 0) {
            return;
        }

        tags.forEach((tag) => {
            const button = document.createElement('button');
            const isActive = this.selectedTags.has(tag);
            button.className = [
                'px-2',
                'py-1',
                'text-[10px]',
                'uppercase',
                'tracking-widest',
                'hover:bg-white',
                'hover:bg-opacity-20',
                isActive ? 'bg-white text-black' : 'bg-black text-white'
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

        // Track which button should be focused after render
        const focusedIndex = this.listContainer.querySelector('button:focus')
            ? Array.from(this.listContainer.querySelectorAll('button')).indexOf(this.listContainer.querySelector('button:focus'))
            : -1;

        this.listContainer.innerHTML = '';

        if (filtered.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'px-2 py-2 text-black text-opacity-50';
            empty.textContent = 'No presets found';
            this.listContainer.appendChild(empty);
            return;
        }

        filtered.forEach((preset, arrayIndex) => {
            const item = document.createElement('button');
            const isSelected = preset.index === this.currentPresetIndex;
            item.className = [
                'mx-1',
                'text-left',
                'break-all',
                'text-white',
                'text-[10px]',
                'tracking-wider',
                'px-0.5',
                'py-1',
                'hover:bg-white',
                'hover:bg-opacity-20',
                'hover:text-white',
                'focus:outline-none',
                'focus:ring-2',
                'focus:ring-white',
                'focus:ring-opacity-50',
                isSelected ? 'bg-white !bg-opacity-30' : 'bg-black'
            ].join(' ');

            // Make button keyboard focusable
            item.tabIndex = 0;

            // Split displayName for prefix and main name
            const displayName = preset.displayName || '';
            const lastSlash = displayName.lastIndexOf('/');
            let prefix = '';
            let mainName = displayName;
            if (lastSlash !== -1) {
                prefix = displayName.substring(0, lastSlash).replace('kits/', '');
                mainName = displayName.substring(lastSlash + 1);
            }

            // Prefix div
            const prefixDiv = document.createElement('div');
            prefixDiv.className = 'text-[8px] -mb-0.5 font-medium text-white tracking-wide text-opacity-70';
            prefixDiv.textContent = prefix;
            // Main name div (only after last slash)
            const nameDiv = document.createElement('div');
            nameDiv.textContent = mainName;

            item.appendChild(prefixDiv);
            item.appendChild(nameDiv);

            item.addEventListener('click', () => {
                this.currentPresetIndex = preset.index;
                this.sendMessage('loadPresetByIndex', { index: preset.index });
                this.updateSelection();
            });

            // Keyboard navigation for arrow keys
            item.addEventListener('keydown', (e) => {
                if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    if (arrayIndex < this.filteredPresets.length - 1) {
                        const nextPreset = this.filteredPresets[arrayIndex + 1];
                        this.currentPresetIndex = nextPreset.index;
                        this.sendMessage('loadPresetByIndex', { index: nextPreset.index });
                        this.updateSelection();
                        // Focus the next button
                        const buttons = this.listContainer.querySelectorAll('button');
                        if (buttons[arrayIndex + 1]) {
                            buttons[arrayIndex + 1].focus();
                        }
                    }
                } else if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    if (arrayIndex > 0) {
                        const prevPreset = this.filteredPresets[arrayIndex - 1];
                        this.currentPresetIndex = prevPreset.index;
                        this.sendMessage('loadPresetByIndex', { index: prevPreset.index });
                        this.updateSelection();
                        // Focus the previous button
                        const buttons = this.listContainer.querySelectorAll('button');
                        if (buttons[arrayIndex - 1]) {
                            buttons[arrayIndex - 1].focus();
                        }
                    }
                }
            });

            this.listContainer.appendChild(item);
        });

        // Restore focus if a button was focused before
        if (focusedIndex >= 0 && focusedIndex < this.listContainer.children.length) {
            setTimeout(() => {
                const buttons = this.listContainer.querySelectorAll('button');
                if (buttons[focusedIndex]) {
                    buttons[focusedIndex].focus();
                }
            }, 0);
        }
    }
}

// Initialize after DrumEngineUI is ready
if (window.drumEngineUI) {
    window.presetBrowserUI = new PresetBrowserUI();
} else {
    window.addEventListener('drumEngineUIReady', () => {
        window.presetBrowserUI = new PresetBrowserUI();
    });
}
