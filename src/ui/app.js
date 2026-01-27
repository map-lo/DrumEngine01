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
        if (window.juce && window.juce.emitEvent) {
            window.juce.emitEvent('pageReady', {});
        }
    }

    initializeElements() {
        // Header controls
        this.presetBrowser = document.getElementById('presetBrowser');
        this.prevPresetBtn = document.getElementById('prevPresetBtn');
        this.nextPresetBtn = document.getElementById('nextPresetBtn');
        this.loadPresetBtn = document.getElementById('loadPresetBtn');
        this.outputMode = document.getElementById('outputMode');

        // Info panel
        this.status = document.getElementById('status');
        this.velocityToggle = document.getElementById('velocityToggle');
        this.presetInfo = document.getElementById('presetInfo');

        // Channel strips
        const strips = document.querySelectorAll('.channel-strip');
        strips.forEach((strip, index) => {
            this.channelStrips[index] = {
                element: strip,
                label: strip.querySelector('.slot-label'),
                fader: strip.querySelector('.volume-fader'),
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

        // Velocity toggle
        this.velocityToggle.addEventListener('click', () => {
            const isActive = this.velocityToggle.classList.contains('active');
            this.sendMessage('setVelocityToVolume', { enabled: !isActive });
        });

        // Channel strip controls
        this.channelStrips.forEach((strip, index) => {
            // Volume fader
            strip.fader.addEventListener('input', (e) => {
                const value = parseFloat(e.target.value) / 100.0;
                strip.volumeValue.textContent = e.target.value + '%';
                this.sendMessage('setSlotVolume', { slot: index, volume: value });
            });

            // Mute button
            strip.muteBtn.addEventListener('click', () => {
                const isMuted = strip.muteBtn.classList.contains('active');
                this.sendMessage('setSlotMuted', { slot: index, muted: !isMuted });
            });

            // Solo button
            strip.soloBtn.addEventListener('click', () => {
                const isSoloed = strip.soloBtn.classList.contains('active');
                this.sendMessage('setSlotSoloed', { slot: index, soloed: !isSoloed });
            });
        });
    }

    sendMessage(action, data = {}) {
        const message = { action, ...data };

        // Check if we're running in JUCE WebBrowserComponent
        if (window.juce && window.juce.emitEvent) {
            window.juce.emitEvent('fromWebView', message);
        } else {
            console.log('Message to C++:', message);
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
        // Update status
        if (state.statusMessage) {
            this.status.textContent = state.statusMessage;
            this.status.className = 'status';
            if (state.statusIsError) {
                this.status.classList.add('error');
            } else if (state.statusIsWarning) {
                this.status.classList.add('warning');
            }
        }

        // Update preset info
        if (state.presetInfo) {
            const info = state.presetInfo;

            if (info.isPresetLoaded) {
                let infoText = `Preset: ${info.presetName}\n`;
                infoText += `Type: ${info.instrumentType}\n`;
                infoText += `Fixed MIDI Note: ${info.fixedMidiNote}\n`;
                infoText += `Slots: ${info.slotCount}\n`;
                infoText += `Velocity Layers: ${info.layerCount}\n`;
                infoText += `Vel->Vol: ${info.useVelocityToVolume ? 'On' : 'Off'}\n`;

                if (info.slotNames && info.slotNames.length > 0) {
                    infoText += '\nMic Slots:\n';
                    info.slotNames.forEach((name, i) => {
                        infoText += `  ${i + 1}: ${name}\n`;
                    });
                }

                this.presetInfo.textContent = infoText;

                // Update velocity toggle
                this.velocityToggle.textContent = info.useVelocityToVolume ? 'ON' : 'OFF';
                if (info.useVelocityToVolume) {
                    this.velocityToggle.classList.add('active');
                } else {
                    this.velocityToggle.classList.remove('active');
                }
            } else {
                this.presetInfo.textContent = 'No preset loaded\n\nClick \'Load Preset...\' or select from dropdown to load a JSON preset file';
            }
        }

        // Update channel strips
        if (state.slots) {
            state.slots.forEach((slot, index) => {
                if (index < this.channelStrips.length) {
                    const strip = this.channelStrips[index];

                    // Active state
                    if (slot.isActive) {
                        strip.element.classList.add('active');
                    } else {
                        strip.element.classList.remove('active');
                    }

                    // Label
                    strip.label.textContent = slot.name || (index + 1);

                    // Volume
                    const volumePercent = Math.round(slot.volume * 100);
                    strip.fader.value = volumePercent;
                    strip.volumeValue.textContent = volumePercent + '%';

                    // Mute
                    if (slot.muted) {
                        strip.muteBtn.classList.add('active');
                    } else {
                        strip.muteBtn.classList.remove('active');
                    }

                    // Solo
                    if (slot.soloed) {
                        strip.soloBtn.classList.add('active');
                    } else {
                        strip.soloBtn.classList.remove('active');
                    }
                }
            });
        }

        // Update output mode
        if (state.outputMode) {
            this.outputMode.value = state.outputMode;
        }

        // Update preset browser selection
        if (state.currentPresetIndex !== undefined && state.currentPresetIndex >= 0) {
            this.presetBrowser.selectedIndex = state.currentPresetIndex + 1;
        }
    }
}

// Global function that C++ can call
window.updateStateFromCpp = function (stateJson) {
    try {
        const state = typeof stateJson === 'string' ? JSON.parse(stateJson) : stateJson;
        if (window.drumEngineUI) {
            window.drumEngineUI.updateState(state);
        }
    } catch (e) {
        console.error('Error parsing state from C++:', e);
    }
};

window.updatePresetListFromCpp = function (presetsJson) {
    try {
        const presets = typeof presetsJson === 'string' ? JSON.parse(presetsJson) : presetsJson;
        if (window.drumEngineUI) {
            window.drumEngineUI.updatePresetList(presets);
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
