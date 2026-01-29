// DrumEngine01 WebView UI
// This JavaScript handles all UI interactions and communicates with the C++ backend

class DrumEngineUI {
    constructor() {
        this.channelStrips = [];
        this.currentPresetIndex = -1;
        this.presetList = [];
        this.dawOctaveOffset = -2; // Default to Yamaha convention, will be updated from backend

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
        if (Math.abs(db) < 0.05) return '0.0'; // Show 0.0 with no sign
        return (db > 0 ? '+' : '') + db.toFixed(1);
    }

    // MIDI note utilities
    noteNameToMidiNumber(noteName) {
        if (!noteName || noteName === '-' || noteName === '') return null;

        const noteMap = {
            'C': 0, 'C#': 1, 'DB': 1, 'CS': 1,
            'D': 2, 'D#': 3, 'EB': 3, 'DS': 3,
            'E': 4,
            'F': 5, 'F#': 6, 'GB': 6, 'FS': 6,
            'G': 7, 'G#': 8, 'AB': 8, 'GS': 8,
            'A': 9, 'A#': 10, 'BB': 10, 'AS': 10,
            'B': 11
        };

        const upper = noteName.toUpperCase().trim();

        // Empty or just special chars
        if (!upper || upper.length === 0) return null;

        // Find where octave number starts
        let octaveStart = -1;
        for (let i = 0; i < upper.length; i++) {
            if ((upper[i] >= '0' && upper[i] <= '9') || upper[i] === '-') {
                octaveStart = i;
                break;
            }
        }

        // No octave found
        if (octaveStart === -1) return null;

        // No note name found
        if (octaveStart === 0) return null;

        const noteStr = upper.substring(0, octaveStart);
        const octaveStr = upper.substring(octaveStart);

        const noteValue = noteMap[noteStr];
        if (noteValue === undefined) return null;

        const octave = parseInt(octaveStr);
        if (isNaN(octave)) return null;

        // Convert using DAW-specific offset (provided by backend)
        // offset -2: Yamaha (Ableton/Logic), offset -1: Roland (others)
        const midiNote = (octave - this.dawOctaveOffset) * 12 + noteValue;

        return (midiNote >= 0 && midiNote <= 127) ? midiNote : null;
    }

    midiNumberToNoteName(noteNumber) {
        if (noteNumber < 0 || noteNumber > 127) return 'Invalid';

        const noteNames = ['C', 'C#', 'D', 'D#', 'E', 'F', 'F#', 'G', 'G#', 'A', 'A#', 'B'];
        // Use DAW-specific offset from backend
        const octave = Math.floor(noteNumber / 12) + this.dawOctaveOffset;
        const note = noteNumber % 12;

        return noteNames[note] + octave;
    }

    handleMidiNoteChange() {
        // Null checks for DOM elements
        if (!this.midiNoteInput) return;

        // Sanitize input: remove any invalid characters, only allow alphanumeric, #, and -
        let input = this.midiNoteInput.value.trim();
        input = input.replace(/[^A-Za-z0-9#\-]/g, '');

        // Empty input - don't do anything
        if (!input || input === '' || input === '-') {
            // Restore previous value if available
            if (this.midiNote && this.midiNote.textContent !== '-') {
                const currentNote = parseInt(this.midiNote.textContent);
                if (!isNaN(currentNote)) {
                    this.midiNoteInput.value = this.midiNumberToNoteName(currentNote);
                }
            }
            return;
        }

        // Try to parse as note name (e.g., "C1", "D#2")
        let midiNote = this.noteNameToMidiNumber(input);

        // If that didn't work, try parsing as a number
        if (midiNote === null) {
            const num = parseInt(input);
            if (!isNaN(num) && num >= 0 && num <= 127) {
                midiNote = num;
            }
        }

        if (midiNote !== null) {
            this.sendMessage('setFixedMidiNote', { note: midiNote });

            // Update display to show canonical note name
            const noteName = this.midiNumberToNoteName(midiNote);
            this.midiNoteInput.value = noteName;

            // Update the display note number if element exists
            if (this.midiNote) {
                this.midiNote.textContent = midiNote.toString();
            }
        } else {
            // Invalid input - restore previous value
            if (this.midiNote && this.midiNote.textContent !== '-') {
                const currentNote = parseInt(this.midiNote.textContent);
                if (!isNaN(currentNote)) {
                    this.midiNoteInput.value = this.midiNumberToNoteName(currentNote);
                } else {
                    this.midiNoteInput.value = '-';
                }
            } else {
                this.midiNoteInput.value = '-';
            }
        }
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
        this.pluginTitle = document.getElementById('pluginTitle');
        this.presetInfo = document.getElementById('presetInfo');
        this.presetDisplay = document.getElementById('presetDisplay');

        // Preset quality indicator
        this.presetQualityIndicator = document.querySelector('.preset-quality-indicator');

        // Info panel elements
        this.statusMessage = document.getElementById('statusMessage');
        this.presetName = document.getElementById('presetName');
        this.instrumentType = document.getElementById('instrumentType');
        this.midiNote = document.getElementById('midiNote');
        this.midiNoteInput = document.getElementById('midiNoteInput');
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
            this.sendMessage('setOutputMode', { mode: this.outputMode.checked ? 'multiout' : 'stereo' });
        });

        // Velocity to volume checkbox
        this.velocityToVolume.addEventListener('change', () => {
            this.sendMessage('setVelocityToVolume', { enabled: this.velocityToVolume.checked });
        });

        // MIDI note lock checkbox
        this.midiNoteLock = document.getElementById('midiNoteLock');
        if (this.midiNoteLock) {
            this.midiNoteLock.addEventListener('change', () => {
                this.sendMessage('setMidiNoteLocked', { locked: this.midiNoteLock.checked });
            });
        }

        // Pitch shift control
        this.pitchSliderContainer = document.getElementById('pitchSliderContainer');
        this.pitchValue = document.getElementById('pitchValue');
        this.pitchIndicator = document.getElementById('pitchIndicator');
        this.pitchShiftValue = 0.0; // Current pitch value in semitones

        if (this.pitchSliderContainer) {
            let isDragging = false;

            const updatePitchFromPosition = (clientX) => {
                const rect = this.pitchSliderContainer.getBoundingClientRect();
                const x = clientX - rect.left;
                const percentage = Math.max(0, Math.min(100, (x / rect.width) * 100));

                // Map 0-100% to -6 to +6 semitones
                const semitones = (percentage / 100) * 12 - 6;
                // Round to 0.1 step
                const rounded = Math.round(semitones * 10) / 10;

                this.pitchShiftValue = rounded;
                this.sendMessage('setPitchShift', { semitones: rounded });

                if (this.pitchValue) {
                    const sign = rounded === 0 ? '' : (rounded > 0 ? '+' : '');
                    this.pitchValue.textContent = sign + rounded.toFixed(1) + 'st';
                }
                if (this.pitchIndicator) {
                    this.pitchIndicator.style.width = percentage + '%';
                }
            };

            this.pitchSliderContainer.addEventListener('pointerdown', (e) => {
                // Alt+click to reset
                if (e.altKey) {
                    e.preventDefault();
                    this.pitchShiftValue = 0.0;
                    this.sendMessage('setPitchShift', { semitones: 0 });
                    if (this.pitchValue) {
                        this.pitchValue.textContent = '0.0st';
                    }
                    if (this.pitchIndicator) {
                        this.pitchIndicator.style.width = '50%';
                    }
                    return;
                }

                isDragging = true;
                this.pitchSliderContainer.setPointerCapture(e.pointerId);
                updatePitchFromPosition(e.clientX);
            });

            this.pitchSliderContainer.addEventListener('pointermove', (e) => {
                if (isDragging) {
                    updatePitchFromPosition(e.clientX);
                }
            });

            this.pitchSliderContainer.addEventListener('pointerup', (e) => {
                if (isDragging) {
                    isDragging = false;
                    this.pitchSliderContainer.releasePointerCapture(e.pointerId);
                }
            });

            this.pitchSliderContainer.addEventListener('pointercancel', (e) => {
                if (isDragging) {
                    isDragging = false;
                    this.pitchSliderContainer.releasePointerCapture(e.pointerId);
                }
            });

            // Double-click to reset pitch to 0
            this.pitchSliderContainer.addEventListener('dblclick', (e) => {
                e.preventDefault();
                this.pitchShiftValue = 0.0;
                this.sendMessage('setPitchShift', { semitones: 0 });
                if (this.pitchValue) {
                    this.pitchValue.textContent = '0.0st';
                }
                if (this.pitchIndicator) {
                    this.pitchIndicator.style.width = '50%';
                }
            });
        }

        // MIDI note input - handle changes (Enter key or blur)
        this.midiNoteInput.addEventListener('input', (e) => {
            // Sanitize input in real-time: only allow alphanumeric, #, and - characters
            const sanitized = e.target.value.replace(/[^A-Za-z0-9#\-]/g, '');
            if (e.target.value !== sanitized) {
                e.target.value = sanitized;
            }
        });

        this.midiNoteInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                this.handleMidiNoteChange();
                this.midiNoteInput.blur(); // Remove focus after enter
            }
            // Allow Escape to cancel and restore previous value
            if (e.key === 'Escape') {
                e.preventDefault();
                if (this.midiNote && this.midiNote.textContent !== '-') {
                    const currentNote = parseInt(this.midiNote.textContent);
                    if (!isNaN(currentNote)) {
                        this.midiNoteInput.value = this.midiNumberToNoteName(currentNote);
                    }
                }
                this.midiNoteInput.blur();
            }
        });

        this.midiNoteInput.addEventListener('blur', () => {
            this.handleMidiNoteChange();
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

            // Alt+click to reset fader to 0.0 dB (unity)
            strip.fader.addEventListener('pointerdown', (e) => {
                if (e.altKey) {
                    e.preventDefault();
                    const unityPosition = 75;
                    strip.fader.value = unityPosition;
                    strip.volumeValue.textContent = this.formatDb(0) + ' dB';
                    strip.volumeIndicator.style.height = unityPosition + '%';
                    const linear = this.faderPositionToLinear(unityPosition);
                    this.sendMessage('setSlotVolume', { slot: index, volume: linear });
                }
            });

            // Double-click to reset fader to 0.0 dB (unity)
            strip.fader.addEventListener('dblclick', (e) => {
                // 0.0 dB is at 75% position
                const unityPosition = 75;
                strip.fader.value = unityPosition;
                strip.volumeValue.textContent = this.formatDb(0) + ' dB';
                strip.volumeIndicator.style.height = unityPosition + '%';
                const linear = this.faderPositionToLinear(unityPosition);
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

            // Toggle between plugin title and preset info display
            if (this.pluginTitle && this.presetInfo) {
                if (info.isPresetLoaded) {
                    this.pluginTitle.classList.add('hidden');
                    this.presetInfo.classList.remove('hidden');
                } else {
                    this.pluginTitle.classList.remove('hidden');
                    this.presetInfo.classList.add('hidden');
                }
            }

            if (this.presetDisplay) {
                this.presetDisplay.textContent = info.isPresetLoaded
                    ? `[${info.instrumentType}] ${info.presetName}`
                    : '[Empty]';
            }
            if (this.presetName) {
                this.presetName.textContent = info.isPresetLoaded ? info.presetName : 'None';
            }
            if (this.instrumentType) {
                this.instrumentType.textContent = info.isPresetLoaded ? info.instrumentType : '-';
            }
            if (this.midiNote) {
                this.midiNote.textContent = info.isPresetLoaded ? info.fixedMidiNote.toString() : '-';
            }
            if (this.midiNoteInput) {
                this.midiNoteInput.value = info.isPresetLoaded ? this.midiNumberToNoteName(info.fixedMidiNote) : '-';
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

            // Update MIDI note lock checkbox
            if (this.midiNoteLock) {
                this.midiNoteLock.checked = info.midiNoteLocked || false;
            }

            // Update DAW octave offset if provided
            if (info.dawOctaveOffset !== undefined) {
                this.dawOctaveOffset = info.dawOctaveOffset;
            }

            // Update pitch shift
            if (info.pitchShift !== undefined) {
                this.pitchShiftValue = info.pitchShift;
                if (this.pitchValue) {
                    const sign = info.pitchShift === 0 ? '' : (info.pitchShift > 0 ? '+' : '');
                    this.pitchValue.textContent = sign + info.pitchShift.toFixed(1) + 'st';
                }
                if (this.pitchIndicator) {
                    // Map -6 to +6 range to 0% to 100% (0 semitones = 50%)
                    const percentage = ((info.pitchShift + 6) / 12) * 100;
                    this.pitchIndicator.style.width = percentage + '%';
                }
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
                        strip.muteBtn.classList.remove('text-black');
                    } else {
                        strip.muteBtn.classList.remove('bg-red-600', 'text-white');
                        strip.muteBtn.classList.add('text-black');
                    }

                    // Solo button - update for new white/yellow styling
                    if (slot.soloed) {
                        strip.soloBtn.classList.add('bg-yellow-400');
                        strip.soloBtn.classList.remove();
                    } else {
                        strip.soloBtn.classList.remove('bg-yellow-400');
                        strip.soloBtn.classList.add();
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
