// DrumEngine01 WebView UI
// This JavaScript handles all UI interactions and communicates with the C++ backend

class DrumEngineUI {
    constructor() {
        this.channelStrips = [];
        this.currentPresetIndex = -1;
        this.presetList = [];

        this.initializeElements();
        this.attachEventListeners();

        // Notify C++ that page is ready - send as separate event
        console.log('DrumEngineUI: Checking for JUCE backend...');
        console.log('window.__JUCE__:', window.__JUCE__);
        console.log('window.juce:', window.juce);

        if (window.__JUCE__ && window.__JUCE__.backend && window.__JUCE__.backend.emitEvent) {
            console.log('DrumEngineUI: Emitting pageReady event');
            window.__JUCE__.backend.emitEvent('pageReady', {});
        } else {
            console.error('DrumEngineUI: JUCE backend not available!');
        }
    }

    initializeElements() {
        // Header controls
        this.presetBrowser = document.getElementById('presetBrowser');
        this.prevPresetBtn = document.getElementById('prevPresetBtn');
        this.nextPresetBtn = document.getElementById('nextPresetBtn');
        this.loadPresetBtn = document.getElementById('loadPresetBtn');
        this.outputMode = document.getElementById('outputMode');

        // Info panel elements
        this.statusMessage = document.getElementById('statusMessage');
        this.presetName = document.getElementById('presetName');
        this.instrumentType = document.getElementById('instrumentType');
        this.midiNote = document.getElementById('midiNote');
        this.layerCount = document.getElementById('layerCount');
        this.slotCount = document.getElementById('slotCount');
        this.velocityToVolume = document.getElementById('velocityToVolume');

        // Channel strips
        const strips = document.querySelectorAll('.channel-strip');
        strips.forEach((strip, index) => {
            this.channelStrips[index] = {
                element: strip,
                label: strip.querySelector('.slot-label'),
                fader: strip.querySelector('.volume-fader'),
                volumeIndicator: strip.querySelector('.volume-indicator'),
                volumeValue: strip.querySelector('.volume-value'),
                muteBtn: strip.querySelector('.mute-button'),
                soloBtn: strip.querySelector('.solo-button')
            };
        });
    }

    attachEventListeners() {
        // Preset controls
        this.presetBrowser.addEventListener('change', () => this.onPresetSelected());
        this.prevPresetBtn.addEventListener('click', () => this.sendMessage('loadPrevPreset'));
        this.nextPresetBtn.addEventListener('click', () => this.sendMessage('loadNextPreset'));
        this.loadPresetBtn.addEventListener('click', () => this.sendMessage('browseForPreset'));

        // Output mode
        this.outputMode.addEventListener('change', () => {
            this.sendMessage('setOutputMode', { mode: this.outputMode.value });
        });

        // Velocity to volume checkbox
        this.velocityToVolume.addEventListener('change', () => {
            this.sendMessage('setVelocityToVolume', { enabled: this.velocityToVolume.checked });
        });

        // Channel strip controls
        this.channelStrips.forEach((strip, index) => {
            // Volume fader (invisible range input)
            strip.fader.addEventListener('input', (e) => {
                const value = parseFloat(e.target.value) / 100.0;
                const percent = e.target.value;
                strip.volumeValue.textContent = percent + '%';
                strip.volumeIndicator.style.height = percent + '%';
                this.sendMessage('setSlotVolume', { slot: index, volume: value });
            });

            // Make volume indicator interactive (click and drag)
            const faderContainer = strip.volumeIndicator.parentElement;
            let isDragging = false;

            const updateVolumeFromPosition = (e) => {
                const rect = faderContainer.getBoundingClientRect();
                const y = e.clientY - rect.top;
                const height = rect.height;
                // Invert because bottom = 0, top = 100
                let percent = Math.round(((height - y) / height) * 100);
                percent = Math.max(0, Math.min(100, percent));

                const value = percent / 100.0;
                strip.fader.value = percent;
                strip.volumeValue.textContent = percent + '%';
                strip.volumeIndicator.style.height = percent + '%';
                this.sendMessage('setSlotVolume', { slot: index, volume: value });
            };

            faderContainer.addEventListener('mousedown', (e) => {
                isDragging = true;
                updateVolumeFromPosition(e);
                e.preventDefault();
            });

            document.addEventListener('mousemove', (e) => {
                if (isDragging) {
                    updateVolumeFromPosition(e);
                }
            });

            document.addEventListener('mouseup', () => {
                isDragging = false;
            });

            // Mute button
            strip.muteBtn.addEventListener('click', () => {
                const isMuted = strip.muteBtn.classList.contains('bg-red-600');
                this.sendMessage('setSlotMuted', { slot: index, muted: !isMuted });
            });

            // Solo button
            strip.soloBtn.addEventListener('click', () => {
                const isSoloed = strip.soloBtn.classList.contains('bg-yellow-400');
                this.sendMessage('setSlotSoloed', { slot: index, soloed: !isSoloed });
            });
        });
    }

    sendMessage(action, data = {}) {
        const message = { action, ...data };

        // Check if we're running in JUCE WebBrowserComponent
        if (window.__JUCE__ && window.__JUCE__.backend && window.__JUCE__.backend.emitEvent) {
            console.log('Sending to C++:', action, data);
            window.__JUCE__.backend.emitEvent('fromWebView', message);
        } else {
            console.log('Message to C++ (not available):', message);
        }
    }

    onPresetSelected() {
        const selectedIndex = this.presetBrowser.selectedIndex - 1; // Subtract 1 for header option
        if (selectedIndex >= 0) {
            this.sendMessage('loadPresetByIndex', { index: selectedIndex });
        }
    }

    // Called from C++ with preset list
    updatePresetList(presets) {
        this.presetList = presets;
        this.presetBrowser.innerHTML = '<option value="">-- Select Preset --</option>';

        presets.forEach((preset, index) => {
            const option = document.createElement('option');
            option.value = index;
            option.textContent = preset.displayName;
            this.presetBrowser.appendChild(option);
        });
    }

    // Called from C++ with current state
    updateState(state) {
        console.log('updateState called with:', state);

        // Update status message
        if (state.statusMessage && this.statusMessage) {
            this.statusMessage.textContent = state.statusMessage;
            // You can add color classes based on error/warning status here
        }

        // Update preset info panel
        if (state.presetInfo) {
            const info = state.presetInfo;

            if (this.presetName) {
                this.presetName.textContent = info.isPresetLoaded ? info.presetName : 'None';
            }
            if (this.instrumentType) {
                this.instrumentType.textContent = info.isPresetLoaded ? info.instrumentType : '-';
            }
            if (this.midiNote) {
                this.midiNote.textContent = info.isPresetLoaded ? info.fixedMidiNote.toString() : '-';
            }
            if (this.layerCount) {
                this.layerCount.textContent = info.layerCount.toString();
            }
            if (this.slotCount) {
                this.slotCount.textContent = info.slotCount.toString();
            }

            // Update velocity checkbox
            if (this.velocityToVolume) {
                this.velocityToVolume.checked = info.useVelocityToVolume;
            }
        }

        // Update channel strips
        if (state.slots) {
            state.slots.forEach((slot, index) => {
                if (index < this.channelStrips.length) {
                    const strip = this.channelStrips[index];

                    // Active/inactive state
                    if (slot.isActive) {
                        strip.element.classList.remove('opacity-50');
                        strip.element.classList.add('opacity-100');
                    } else {
                        strip.element.classList.add('opacity-50');
                        strip.element.classList.remove('opacity-100');
                    }

                    // Label
                    strip.label.textContent = slot.name || (index + 1);

                    // Volume
                    const volumePercent = Math.round(slot.volume * 100);
                    strip.fader.value = volumePercent;
                    strip.volumeValue.textContent = volumePercent + '%';
                    strip.volumeIndicator.style.height = volumePercent + '%';

                    // Mute button - update for new white/black styling
                    if (slot.muted) {
                        strip.muteBtn.classList.add('bg-red-600', 'text-white');
                        strip.muteBtn.classList.remove('bg-white', 'text-black');
                    } else {
                        strip.muteBtn.classList.remove('bg-red-600', 'text-white');
                        strip.muteBtn.classList.add('bg-white', 'text-black');
                    }

                    // Solo button - update for new white/yellow styling
                    if (slot.soloed) {
                        strip.soloBtn.classList.add('bg-yellow-400');
                        strip.soloBtn.classList.remove('bg-white');
                    } else {
                        strip.soloBtn.classList.remove('bg-yellow-400');
                        strip.soloBtn.classList.add('bg-white');
                    }
                }
            });
        }

        // Update output mode
        if (state.outputMode && this.outputMode) {
            this.outputMode.value = state.outputMode;
        }

        // Update current preset index
        if (typeof state.currentPresetIndex !== 'undefined') {
            this.currentPresetIndex = state.currentPresetIndex;
            if (this.presetBrowser && state.currentPresetIndex >= 0) {
                this.presetBrowser.selectedIndex = state.currentPresetIndex + 1; // +1 for header option
            }
        }
    }

    updatePresetList(presets) {
        console.log('updatePresetList called with', presets.length, 'presets');

        this.presetList = presets;

        // Clear existing options except the first one
        while (this.presetBrowser.options.length > 1) {
            this.presetBrowser.remove(1);
        }

        // Add new options
        presets.forEach((preset, index) => {
            const option = document.createElement('option');
            option.value = index;
            option.textContent = preset.displayName;
            this.presetBrowser.appendChild(option);
        });
    }

    onPresetSelected() {
        const selectedIndex = this.presetBrowser.selectedIndex - 1; // Subtract 1 for header option
        if (selectedIndex >= 0) {
            this.sendMessage('loadPresetByIndex', { index: selectedIndex });
        }
    }
}

// Global function that C++ can call
window.updateStateFromCpp = function (stateJson) {
    console.log('updateStateFromCpp called');
    try {
        const state = typeof stateJson === 'string' ? JSON.parse(stateJson) : stateJson;
        if (window.drumEngineUI) {
            window.drumEngineUI.updateState(state);
        } else {
            console.error('drumEngineUI not initialized yet');
        }
    } catch (e) {
        console.error('Error parsing state from C++:', e);
    }
};

window.updatePresetListFromCpp = function (presetsJson) {
    console.log('updatePresetListFromCpp called');
    try {
        const presets = typeof presetsJson === 'string' ? JSON.parse(presetsJson) : presetsJson;
        if (window.drumEngineUI) {
            window.drumEngineUI.updatePresetList(presets);
        } else {
            console.error('drumEngineUI not initialized yet');
        }
    } catch (e) {
        console.error('Error parsing preset list from C++:', e);
    }
};

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.drumEngineUI = new DrumEngineUI();
    });
} else {
    window.drumEngineUI = new DrumEngineUI();
}
