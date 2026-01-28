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

    // Convert fader position (0-100) to decibels using logarithmic curve
    // Similar to professional analog mixing console faders:
    // - 100% = +10 dB
    // - 75% = 0 dB (unity gain)
    // - 65% = -6 dB
    // - 50% = -12 dB
    // - 0% = -∞ dB
    faderPositionToDb(position) {
        if (position <= 0) return -80; // Effective -∞

        // Analog-style logarithmic curve
        // Maps 0-100% fader position to -80dB to +10dB
        // Unity gain (0dB) at 75% position
        const minDb = -80;
        const maxDb = 10;
        const unityPosition = 75; // 0dB at 75%

        if (position >= unityPosition) {
            // Above unity: linear scale from 0dB to +10dB
            const ratio = (position - unityPosition) / (100 - unityPosition);
            return ratio * maxDb;
        } else {
            // Below unity: logarithmic scale from -80dB to 0dB
            const ratio = position / unityPosition;
            // Use exponential curve: dB = minDb * (1 - ratio^4)
            return minDb * Math.pow(1 - ratio, 3);
        }
    }

    // Convert decibels to linear gain
    dbToLinear(db) {
        if (db <= -80) return 0;
        return Math.pow(10, db / 20);
    }

    // Convert fader position to linear gain (for sending to backend)
    faderPositionToLinear(position) {
        const db = this.faderPositionToDb(position);
        return this.dbToLinear(db);
    }

    // Format dB value for display
    formatDb(db) {
        if (db <= -80) return '-∞';
        return (db >= 0 ? '+' : '') + db.toFixed(1);
    }

    // Update preset quality indicator based on available samples
    updatePresetQualityIndicator(sampleMap) {
        if (!this.presetQualityIndicator || !sampleMap) return;

        // Reset all indicators to inactive (lower opacity)
        const allIndicators = this.presetQualityIndicator.querySelectorAll('div');
        allIndicators.forEach(indicator => {
            indicator.classList.remove('opacity-100');
            indicator.classList.add('opacity-20');
        });

        // Activate indicators based on sampleMap
        // sampleMap should be an object like: { "velocity-1": [1, 2, 3], "velocity-2": [1, 2, 3, 4, 5], ... }
        // where the array contains the RR indices that have samples
        for (const [velocityClass, rrIndices] of Object.entries(sampleMap)) {
            rrIndices.forEach(rrIndex => {
                const selector = `.${velocityClass}.rr-${rrIndex}`;
                const indicator = this.presetQualityIndicator.querySelector(selector);
                if (indicator) {
                    indicator.classList.remove('opacity-20');
                    indicator.classList.add('opacity-100');
                }
            });
        }
    }

    initializeElements() {
        // Header controls
        this.presetBrowser = document.getElementById('presetBrowser');
        this.prevPresetBtn = document.getElementById('prevPresetBtn');
        this.nextPresetBtn = document.getElementById('nextPresetBtn');
        this.loadPresetBtn = document.getElementById('loadPresetBtn');
        this.outputMode = document.getElementById('outputMode');

        // Preset quality indicator
        this.presetQualityIndicator = document.querySelector('.preset-quality-indicator');

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

        // Output mode checkbox
        this.outputMode.addEventListener('change', () => {
            const mode = this.outputMode.checked ? 'multiout' : 'stereo';
            this.sendMessage('setOutputMode', { mode: mode });
        });

        // Velocity to volume checkbox
        this.velocityToVolume.addEventListener('change', () => {
            this.sendMessage('setVelocityToVolume', { enabled: this.velocityToVolume.checked });
        });

        // Channel strip controls
        this.channelStrips.forEach((strip, index) => {
            // Volume fader (invisible range input)
            strip.fader.addEventListener('input', (e) => {
                const position = parseFloat(e.target.value);
                const linear = this.faderPositionToLinear(position);
                const db = this.faderPositionToDb(position);
                strip.volumeValue.textContent = this.formatDb(db) + ' dB';
                strip.volumeIndicator.style.height = position + '%';
                this.sendMessage('setSlotVolume', { slot: index, volume: linear });
            });

            // Make volume indicator interactive (click and drag)
            const faderContainer = strip.volumeIndicator.parentElement;
            let isDragging = false;

            const updateVolumeFromPosition = (e) => {
                const rect = faderContainer.getBoundingClientRect();
                const y = e.clientY - rect.top;
                const height = rect.height;
                // Invert because bottom = 0, top = 100
                let position = Math.round(((height - y) / height) * 100);
                position = Math.max(0, Math.min(100, position));

                const linear = this.faderPositionToLinear(position);
                const db = this.faderPositionToDb(position);
                strip.fader.value = position;
                strip.volumeValue.textContent = this.formatDb(db) + ' dB';
                strip.volumeIndicator.style.height = position + '%';
                this.sendMessage('setSlotVolume', { slot: index, volume: linear });
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

            // Update preset quality indicator
            if (info.sampleMap) {
                this.updatePresetQualityIndicator(info.sampleMap);
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

                    // Volume - convert from linear to fader position using inverse curve
                    const db = 20 * Math.log10(Math.max(0.00001, slot.volume));

                    // Inverse calculation to get fader position from dB
                    let position;
                    if (db >= 0) {
                        // Above unity
                        position = 75 + (db / 10) * 25;
                    } else if (db <= -80) {
                        position = 0;
                    } else {
                        // Below unity: solve for position from our exponential curve
                        // db = -80 * (1 - (position/75))^3
                        position = 75 * (1 - Math.pow(-db / 80, 1 / 3));
                    }
                    position = Math.round(Math.max(0, Math.min(100, position)));

                    strip.fader.value = position;
                    strip.volumeValue.textContent = this.formatDb(db) + ' dB';
                    strip.volumeIndicator.style.height = position + '%';

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

        // Update output mode checkbox
        if (state.outputMode && this.outputMode) {
            this.outputMode.checked = (state.outputMode === 'multiout');
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
    // Handle hit notification from C++ (real-time sample trigger visualization)
    onHit(velocityLayer, rrIndex) {
        if (!this.presetQualityIndicator) return;

        const selector = `.velocity-${velocityLayer}.rr-${rrIndex}`;
        const indicator = this.presetQualityIndicator.querySelector(selector);

        if (indicator) {
            // Flash the indicator by temporarily changing background to white
            indicator.classList.add('hit-flash');

            // Remove the flash class after animation completes
            setTimeout(() => {
                indicator.classList.remove('hit-flash');
            }, 200); // Match the CSS transition duration
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
        window.ui = window.drumEngineUI; // Alias for easier access from C++
    });
} else {
    window.drumEngineUI = new DrumEngineUI();
    window.ui = window.drumEngineUI; // Alias for easier access from C++
}

// Listen for hit events from C++
if (window.__JUCE__ && window.__JUCE__.backend) {
    window.__JUCE__.backend.addEventListener('hit', (event) => {
        if (window.ui && event && event.velocityLayer && event.rrIndex) {
            window.ui.onHit(event.velocityLayer, event.rrIndex);
        }
    });
}
