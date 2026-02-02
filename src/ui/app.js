// Import CSS for Vite to process
import './styles.css';

// Import Alpine.js
import Alpine from 'alpinejs';

// Make Alpine available globally
window.Alpine = Alpine;

// Main DrumEngine Alpine Component
window.drumEngineApp = function () {
    return {
        // Debug mode - set to false to disable console logging
        debugMode: false,

        // UI State
        editor: false,
        isPresetBrowserOpen: false,

        // Data
        presetList: [],
        currentPresetIndex: -1,
        dawOctaveOffset: -2,

        // Preset Info
        presetInfo: {
            isPresetLoaded: false,
            presetName: 'None',
            instrumentType: '-',
            fixedMidiNote: 0,
            layerCount: 0,
            slotCount: 0,
            useVelocityToVolume: false,
            midiNoteLocked: false,
            pitchShift: 0,
            sampleMap: {}
        },

        // Mixer State
        slots: Array(8).fill(null).map((_, i) => ({
            name: (i + 1).toString(),
            volume: 1.0,
            muted: false,
            soloed: false,
            isActive: false
        })),

        statusMessage: '',
        outputMode: 'stereo',
        resamplingMode: 'lanczos3',
        version: '0.0.0',
        buildNumber: '0',
        buildTimestamp: '',

        // Volume drag state
        volumeDragIndex: -1,

        // Pitch drag state
        isPitchDragging: false,

        // MIDI note input
        midiNoteInput: '-',

        // Computed
        get pitchEnabled() {
            return this.resamplingMode !== 'off';
        },

        // Initialize
        init() {

            // Set up global functions for C++ to call
            window.updateStateFromCpp = (stateJson) => {
                try {
                    const state = typeof stateJson === 'string' ? JSON.parse(stateJson) : stateJson;
                    this.updateState(state);
                } catch (e) {
                    console.error('Error parsing state from C++:', e);
                }
            };

            window.updatePresetListFromCpp = (presetsJson) => {
                try {
                    const presets = typeof presetsJson === 'string' ? JSON.parse(presetsJson) : presetsJson;
                    this.updatePresetList(presets);
                } catch (e) {
                    console.error('Error parsing preset list from C++:', e);
                }
            };

            // Alias for backwards compatibility
            window.ui = this;
            window.drumEngineUI = this;

            // Set up hit event listener
            if (window.__JUCE__ && window.__JUCE__.backend) {
                window.__JUCE__.backend.addEventListener('hit', (event) => {
                    if (event && event.velocityLayer && event.rrIndex) {
                        this.onHit(event.velocityLayer, event.rrIndex);
                    }
                });
            }

            // Notify C++ that page is ready
            if (window.__JUCE__ && window.__JUCE__.backend && window.__JUCE__.backend.emitEvent) {
                window.__JUCE__.backend.emitEvent('pageReady', {});
            }

            // Set up volume drag handlers
            document.addEventListener('mousemove', (e) => {
                if (this.volumeDragIndex >= 0) {
                    this.handleVolumeDrag(e);
                }
            });

            document.addEventListener('mouseup', () => {
                this.volumeDragIndex = -1;
            });

            // Set up pitch drag handlers
            document.addEventListener('pointermove', (e) => {
                if (this.isPitchDragging) {
                    this.handlePitchMove(e);
                }
            });

            document.addEventListener('pointerup', () => {
                this.isPitchDragging = false;
            });

            document.addEventListener('pointercancel', () => {
                this.isPitchDragging = false;
            });
        },

        // Computed property for preset display
        get presetDisplay() {
            if (!this.presetInfo.isPresetLoaded) return '[Empty]';
            return `[${this.presetInfo.instrumentType}] ${this.presetInfo.presetName}`;
        },

        // Volume utilities
        faderPositionToDb(position) {
            if (position <= 0) return -80;

            const minDb = -80;
            const maxDb = 10;
            const unityPosition = 75;

            if (position >= unityPosition) {
                const ratio = (position - unityPosition) / (100 - unityPosition);
                return ratio * maxDb;
            } else {
                const ratio = position / unityPosition;
                return minDb * Math.pow(1 - ratio, 3);
            }
        },

        dbToLinear(db) {
            if (db <= -80) return 0;
            return Math.pow(10, db / 20);
        },

        faderPositionToLinear(position) {
            const db = this.faderPositionToDb(position);
            return this.dbToLinear(db);
        },

        formatDb(db) {
            if (db <= -80) return '-∞';
            if (Math.abs(db) < 0.05) return '0.0';
            return (db > 0 ? '+' : '') + db.toFixed(1);
        },

        linearToFaderPosition(volume) {
            const db = 20 * Math.log10(Math.max(0.00001, volume));

            let position;
            if (db >= 0) {
                position = 75 + (db / 10) * 25;
            } else if (db <= -80) {
                position = 0;
            } else {
                position = 75 * (1 - Math.pow(-db / 80, 1 / 3));
            }
            return Math.round(Math.max(0, Math.min(100, position)));
        },

        // Slot methods
        getSlotFaderPosition(index) {
            return this.linearToFaderPosition(this.slots[index].volume);
        },

        getSlotVolumeDisplay(index) {
            const db = 20 * Math.log10(Math.max(0.00001, this.slots[index].volume));
            return this.formatDb(db) + ' dB';
        },

        setSlotVolume(event, index) {
            const position = parseFloat(event.target.value);
            const linear = this.faderPositionToLinear(position);
            // Create new slot object to trigger reactivity
            this.slots[index] = { ...this.slots[index], volume: linear };
            this.sendMessage('setSlotVolume', { slot: index, volume: linear });
        },

        resetSlotVolume(index) {
            const unityPosition = 75;
            const linear = this.faderPositionToLinear(unityPosition);
            // Create new slot object to trigger reactivity
            this.slots[index] = { ...this.slots[index], volume: linear };
            this.sendMessage('setSlotVolume', { slot: index, volume: linear });
        },

        toggleSlotMute(index) {
            // Create new slot object to trigger reactivity
            this.slots[index] = { ...this.slots[index], muted: !this.slots[index].muted };
            this.sendMessage('setSlotMuted', { slot: index, muted: this.slots[index].muted });
        },

        toggleSlotSolo(index) {
            // Create new slot object to trigger reactivity
            this.slots[index] = { ...this.slots[index], soloed: !this.slots[index].soloed };
            this.sendMessage('setSlotSoloed', { slot: index, soloed: this.slots[index].soloed });
        },

        startVolumeDrag(event, index) {
            this.volumeDragIndex = index;
            this.handleVolumeDrag(event);
            event.preventDefault();
        },

        handleVolumeDrag(event) {
            if (this.volumeDragIndex < 0) return;

            const strips = document.querySelectorAll('.channel-strip');
            const strip = strips[this.volumeDragIndex];
            if (!strip) return;

            // Find the fader container
            const container = strip.querySelector('.fader-container');
            if (!container) return;

            const rect = container.getBoundingClientRect();
            const y = event.clientY - rect.top;
            const height = rect.height;
            let position = Math.round(((height - y) / height) * 100);
            position = Math.max(0, Math.min(100, position));

            const linear = this.faderPositionToLinear(position);
            this.slots[this.volumeDragIndex] = { ...this.slots[this.volumeDragIndex], volume: linear };
            this.sendMessage('setSlotVolume', { slot: this.volumeDragIndex, volume: linear });
        },

        // Sample map check
        hasSample(velocityLayer, rrIndex) {
            const key = `velocity-${velocityLayer}`;
            const sampleMap = this.presetInfo.sampleMap || {};
            return sampleMap[key] && sampleMap[key].includes(rrIndex);
        },

        // Preset browser
        togglePresetBrowser() {
            this.isPresetBrowserOpen = !this.isPresetBrowserOpen;

            if (this.isPresetBrowserOpen) {
                this.sendMessage('openPresetBrowser');
            } else {
                this.sendMessage('closePresetBrowser');
            }
        },

        // Update methods
        updatePresetList(presets) {
            this.presetList = presets.map((preset, index) => ({
                index,
                displayName: preset.displayName || 'Unnamed Preset',
                instrumentType: preset.instrumentType || 'Unknown',
                category: preset.category || ''
            }));
        },

        updateState(state) {
            if (state.statusMessage) {
                this.statusMessage = state.statusMessage;
            }

            if (state.presetInfo) {
                this.presetInfo = { ...this.presetInfo, ...state.presetInfo };

                // Update MIDI note input display
                if (this.presetInfo.isPresetLoaded && this.presetInfo.fixedMidiNote >= 0) {
                    this.midiNoteInput = this.midiNumberToNoteName(this.presetInfo.fixedMidiNote);
                } else {
                    this.midiNoteInput = '-';
                }

                // Update DAW octave offset if provided
                if (state.presetInfo.dawOctaveOffset !== undefined) {
                    this.dawOctaveOffset = state.presetInfo.dawOctaveOffset;
                }
            }

            if (state.slots) {
                state.slots.forEach((slot, index) => {
                    if (index < this.slots.length) {
                        this.slots[index] = { ...this.slots[index], ...slot };
                    }
                });
            }

            if (state.outputMode) {
                this.outputMode = state.outputMode;
            }

            if (state.resamplingMode) {
                this.resamplingMode = state.resamplingMode;
            }

            if (state.version) {
                this.version = state.version;
            }

            if (typeof state.buildNumber !== 'undefined') {
                this.buildNumber = state.buildNumber;
            }

            if (Object.prototype.hasOwnProperty.call(state, 'buildTimestamp')) {
                this.buildTimestamp = state.buildTimestamp;
            }

            if (typeof state.currentPresetIndex !== 'undefined') {
                this.currentPresetIndex = state.currentPresetIndex;
            }
        },

        // Hit visualization
        onHit(velocityLayer, rrIndex) {
            // Find the indicator element using CSS classes
            const selector = `.velocity-${velocityLayer}.rr-${rrIndex}`;
            const indicator = document.querySelector(selector);

            if (indicator) {
                // Flash the indicator by temporarily changing background to white
                indicator.classList.add('hit-flash');

                // Remove the flash class after animation completes
                setTimeout(() => {
                    indicator.classList.remove('hit-flash');
                }, 200); // Match the CSS transition duration
            }
        },

        // Pitch shift methods
        formatPitchShift(semitones) {
            const sign = semitones === 0 ? '' : (semitones > 0 ? '+' : '');
            return sign + semitones.toFixed(1) + 'st';
        },

        handlePitchDrag(event) {
            if (!this.pitchEnabled) return;
            if (event.altKey) {
                this.resetPitch();
                return;
            }

            this.isPitchDragging = true;
            this.handlePitchMove(event);
            event.preventDefault();
        },

        handlePitchMove(event) {
            if (!this.isPitchDragging || !this.pitchEnabled) return;

            // Find the pitch fader container
            const container = document.querySelector('.pitch-indicator')?.parentElement;
            if (!container) return;

            const rect = container.getBoundingClientRect();
            const x = event.clientX - rect.left;
            const percentage = Math.max(0, Math.min(100, (x / rect.width) * 100));

            // Map 0-100% to -6 to +6 semitones
            const semitones = (percentage / 100) * 12 - 6;
            const rounded = Math.round(semitones * 10) / 10;

            this.presetInfo.pitchShift = rounded;
            this.sendMessage('setPitchShift', { semitones: rounded });
        },

        resetPitch() {
            this.presetInfo.pitchShift = 0.0;
            this.sendMessage('setPitchShift', { semitones: 0 });
        },

        setResamplingMode(mode) {
            this.resamplingMode = mode;
            this.sendMessage('setResamplingMode', { mode });

            if (mode === 'off') {
                this.resetPitch();
            }
        },

        // MIDI note methods
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
            if (!upper || upper.length === 0) return null;

            let octaveStart = -1;
            for (let i = 0; i < upper.length; i++) {
                if ((upper[i] >= '0' && upper[i] <= '9') || upper[i] === '-') {
                    octaveStart = i;
                    break;
                }
            }

            if (octaveStart === -1 || octaveStart === 0) return null;

            const noteStr = upper.substring(0, octaveStart);
            const octaveStr = upper.substring(octaveStart);

            const noteValue = noteMap[noteStr];
            if (noteValue === undefined) return null;

            const octave = parseInt(octaveStr);
            if (isNaN(octave)) return null;

            const midiNote = (octave - this.dawOctaveOffset) * 12 + noteValue;
            return (midiNote >= 0 && midiNote <= 127) ? midiNote : null;
        },

        midiNumberToNoteName(noteNumber) {
            if (noteNumber < 0 || noteNumber > 127) return 'Invalid';

            const noteNames = ['C', 'C#', 'D', 'D#', 'E', 'F', 'F#', 'G', 'G#', 'A', 'A#', 'B'];
            const octave = Math.floor(noteNumber / 12) + this.dawOctaveOffset;
            const note = noteNumber % 12;

            return noteNames[note] + octave;
        },

        sanitizeMidiNoteInput(event) {
            const sanitized = event.target.value.replace(/[^A-Za-z0-9#\-]/g, '');
            if (event.target.value !== sanitized) {
                event.target.value = sanitized;
                this.midiNoteInput = sanitized;
            }
        },

        handleMidiNoteChange() {
            let input = this.midiNoteInput.trim();
            input = input.replace(/[^A-Za-z0-9#\-]/g, '');

            if (!input || input === '' || input === '-') {
                this.resetMidiNoteInput();
                return;
            }

            let midiNote = this.noteNameToMidiNumber(input);

            if (midiNote === null) {
                const num = parseInt(input);
                if (!isNaN(num) && num >= 0 && num <= 127) {
                    midiNote = num;
                }
            }

            if (midiNote !== null) {
                this.sendMessage('setFixedMidiNote', { note: midiNote });
                this.midiNoteInput = this.midiNumberToNoteName(midiNote);
                this.presetInfo.fixedMidiNote = midiNote;
            } else {
                this.resetMidiNoteInput();
            }
        },

        resetMidiNoteInput() {
            if (this.presetInfo.isPresetLoaded && this.presetInfo.fixedMidiNote >= 0) {
                this.midiNoteInput = this.midiNumberToNoteName(this.presetInfo.fixedMidiNote);
            } else {
                this.midiNoteInput = '-';
            }
        },

        // Send message to C++
        sendMessage(action, data = {}) {
            const message = { action, ...data };

            if (window.__JUCE__ && window.__JUCE__.backend && window.__JUCE__.backend.emitEvent) {
                if (this.debugMode) console.log('Sending to C++:', action, data);
                window.__JUCE__.backend.emitEvent('fromWebView', message);
            } else if (this.debugMode) {
                console.log('Message to C++ (not available):', message);
            }
        }
    };
};

// Preset Browser Component
window.presetBrowser = function () {
    return {
        searchTerm: '',
        selectedTags: new Set(),

        init() {
            // Request initial data from root component
            this.sendToRoot('requestPresetList');
            this.sendToRoot('requestUpdate');
        },

        sendToRoot(action, data = {}) {
            const message = { action, ...data };
            if (window.__JUCE__ && window.__JUCE__.backend && window.__JUCE__.backend.emitEvent) {
                window.__JUCE__.backend.emitEvent('fromWebView', message);
            }
        },

        getRoot() {
            // Access the root Alpine component via window reference
            return window.drumEngineUI || window.ui;
        },

        get filteredPresets() {
            const root = this.getRoot();
            if (!root || !root.presetList) return [];
            let filtered = root.presetList;

            // Apply search filter
            if (this.searchTerm.trim()) {
                const query = this.searchTerm.trim().toLowerCase();
                filtered = filtered.filter(preset =>
                    preset.displayName.toLowerCase().includes(query)
                );
            }

            // Apply tag filter
            if (this.selectedTags.size > 0) {
                filtered = filtered.filter(preset =>
                    this.selectedTags.has(preset.instrumentType)
                );
            }

            return filtered;
        },

        get availableTags() {
            const tags = new Set();
            this.filteredPresets.forEach(preset => {
                if (preset.instrumentType) {
                    tags.add(preset.instrumentType);
                }
            });
            this.selectedTags.forEach(tag => tags.add(tag));
            return Array.from(tags).sort();
        },

        toggleTag(tag) {
            if (this.selectedTags.has(tag)) {
                this.selectedTags.delete(tag);
            } else {
                this.selectedTags.add(tag);
            }
            // Force reactivity
            this.selectedTags = new Set(this.selectedTags);
        },

        loadPreset(index) {
            const root = this.getRoot();
            if (root) {
                root.currentPresetIndex = index;
                this.sendToRoot('loadPresetByIndex', { index });
            }
        },

        navigateDown(currentIndex) {
            if (currentIndex < this.filteredPresets.length - 1) {
                const nextPreset = this.filteredPresets[currentIndex + 1];
                this.loadPreset(nextPreset.index);
                // Focus the next button element
                this.$nextTick(() => {
                    const buttons = document.querySelectorAll('[aria-label="Preset list"] button');
                    if (buttons[currentIndex + 1]) {
                        buttons[currentIndex + 1].focus();
                    }
                });
            }
        },

        navigateUp(currentIndex) {
            if (currentIndex > 0) {
                const prevPreset = this.filteredPresets[currentIndex - 1];
                this.loadPreset(prevPreset.index);
                // Focus the previous button element
                this.$nextTick(() => {
                    const buttons = document.querySelectorAll('[aria-label="Preset list"] button');
                    if (buttons[currentIndex - 1]) {
                        buttons[currentIndex - 1].focus();
                    }
                });
            }
        },

        getPresetPrefix(displayName) {
            const lastSlash = displayName.lastIndexOf('/');
            if (lastSlash !== -1) {
                return displayName.substring(0, lastSlash).replace('kits/', '');
            }
            return '';
        },

        getPresetName(displayName) {
            const lastSlash = displayName.lastIndexOf('/');
            if (lastSlash !== -1) {
                return displayName.substring(lastSlash + 1);
            }
            return displayName;
        }
    };
};

// Start Alpine
Alpine.start();
