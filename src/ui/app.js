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
        isScanningPresets: false,
        presetBrowserTags: [],
        presetBrowserSearchTerm: '',

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
            phaseInverted: false,
            pitchShift: 0,
            sampleMap: {},
            freq: 0,
            freqConfidence: 0
        },

        // Auto-pitch mode
        autoPitchMode: false,
        targetFrequencyHz: 60.0,

        // Output volume (dB)
        outputVolumeDb: -6.0,

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
        volumeDragStartY: 0,
        volumeDragStartPosition: 0,
        volumeDragFineActive: false,

        // Generic horizontal slider state (pitch, Hz, output volume)
        sliders: {
            pitch: { isDragging: false, startX: 0, startPercent: 0, fineActive: false },
            hz: { isDragging: false, startX: 0, startPercent: 0, fineActive: false },
            outputVolume: { isDragging: false, startX: 0, startPercent: 0, fineActive: false }
        },

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
                if (this.sliders.pitch.isDragging) {
                    this.handlePitchMove(e);
                }
            });

            document.addEventListener('pointermove', (e) => {
                if (this.sliders.hz.isDragging) {
                    this.handleHzMove(e);
                }
            });

            document.addEventListener('pointermove', (e) => {
                if (this.sliders.outputVolume.isDragging) {
                    this.handleOutputVolumeMove(e);
                }
            });

            document.addEventListener('pointerup', () => {
                this.sliders.pitch.isDragging = false;
                this.sliders.hz.isDragging = false;
                this.sliders.outputVolume.isDragging = false;
            });

            document.addEventListener('pointercancel', () => {
                this.sliders.pitch.isDragging = false;
                this.sliders.hz.isDragging = false;
                this.sliders.outputVolume.isDragging = false;
            });
        },

        // Generic horizontal slider helper methods
        createSliderHandler(sliderKey, config) {
            return {
                start: (event) => {
                    if (config.canDrag && !config.canDrag()) return;
                    if (event.altKey && config.onReset) {
                        config.onReset();
                        return;
                    }

                    const slider = this.sliders[sliderKey];
                    slider.isDragging = true;
                    slider.startX = event.clientX;
                    slider.startPercent = config.getCurrentPercent();
                    slider.fineActive = false;
                    this.moveSlider(sliderKey, event, config);
                    event.preventDefault();
                },

                move: (event) => this.moveSlider(sliderKey, event, config),

                isActive: () => this.sliders[sliderKey].isDragging
            };
        },

        moveSlider(sliderKey, event, config) {
            const slider = this.sliders[sliderKey];
            if (!slider.isDragging || (config.canDrag && !config.canDrag())) return;

            const container = document.querySelector(config.indicator)?.parentElement;
            if (!container) return;

            const rect = container.getBoundingClientRect();
            const x = event.clientX - rect.left;
            let percentage;

            if (event.metaKey) {
                // Fine control mode (Cmd+drag)
                if (!slider.fineActive) {
                    slider.startX = event.clientX;
                    slider.startPercent = config.getCurrentPercent();
                    slider.fineActive = true;
                }
                const delta = (event.clientX - slider.startX) / rect.width;
                percentage = slider.startPercent + (delta * 100) / 4;
            } else {
                slider.fineActive = false;
                percentage = (x / rect.width) * 100;
            }

            percentage = Math.max(0, Math.min(100, percentage));
            config.onUpdate(percentage);
        },

        // Computed property for preset display
        get presetDisplay() {
            if (!this.presetInfo.isPresetLoaded) return '[Empty]';
            return `[${this.presetInfo.instrumentType}] ${this.presetInfo.presetName}`;
        },

        getDefaultSlotNamesForInstrument(instrumentType) {
            const normalized = (instrumentType || '').trim().toLowerCase();

            if (normalized === 'snare') {
                return ['top', 'bottom', 'oh', 'room1', 'room2', 'extra1', 'extra2', 'extra3'];
            }

            if (normalized === 'kick') {
                return ['in', 'out', 'sub', 'room1', 'room2', 'extra1', 'extra2', 'extra3'];
            }

            return ['spot1', 'spot2', 'oh', 'room1', 'room2', 'extra1', 'extra2', 'extra3'];
        },

        getSlotDisplayName(slot, index) {
            const provided = (slot && typeof slot.name === 'string') ? slot.name.trim() : '';
            if (provided.length > 0) return provided;

            const defaults = this.getDefaultSlotNamesForInstrument(this.presetInfo.instrumentType);
            if (index >= 0 && index < defaults.length) return defaults[index];

            return (index + 1).toString();
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
                return minDb * Math.pow(1 - ratio, 2);
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

        outputVolumeDbToPercent(db) {
            const clampedDb = Math.max(-80, Math.min(0, db));
            const linear = this.dbToLinear(clampedDb);
            const position = this.linearToFaderPosition(linear);
            return Math.max(0, Math.min(100, (position / 75) * 100));
        },

        percentToOutputVolumeDb(percent) {
            const clamped = Math.max(0, Math.min(100, percent));
            const position = (clamped / 100) * 75;
            return Math.min(0, this.faderPositionToDb(position));
        },

        outputVolumePercent() {
            return this.outputVolumeDbToPercent(this.outputVolumeDb);
        },

        linearToFaderPosition(volume) {
            if (volume <= 0) return 0;

            const minDb = -80;
            const maxDb = 10;
            const unityPosition = 75;

            const db = 20 * Math.log10(volume);
            const clampedDb = Math.max(minDb, Math.min(maxDb, db));

            let position;
            if (clampedDb >= 0) {
                position = unityPosition + (clampedDb / maxDb) * (100 - unityPosition);
            } else {
                const ratio = 1 - Math.pow(clampedDb / minDb, 1 / 2);
                position = unityPosition * ratio;
            }

            return Math.max(0, Math.min(100, position));
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

        auditionSlot(index) {
            if (!this.presetInfo.isPresetLoaded) return;
            this.sendMessage('auditionSlot', { slot: index, velocity: 100 });
        },

        startVolumeDrag(event, index) {
            this.volumeDragIndex = index;
            this.volumeDragStartY = event.clientY;
            this.volumeDragStartPosition = this.linearToFaderPosition(this.slots[index].volume);
            this.volumeDragFineActive = false;
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
            let position;
            if (event.metaKey) {
                if (!this.volumeDragFineActive) {
                    this.volumeDragStartY = event.clientY;
                    this.volumeDragStartPosition = this.linearToFaderPosition(this.slots[this.volumeDragIndex].volume);
                    this.volumeDragFineActive = true;
                }
                const delta = (this.volumeDragStartY - event.clientY) / height;
                position = this.volumeDragStartPosition + (delta * 100) / 4;
            } else {
                this.volumeDragFineActive = false;
                position = ((height - y) / height) * 100;
            }
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

        auditionVelocityLayer(layerIndex) {
            if (!this.presetInfo.isPresetLoaded) return;
            this.sendMessage('auditionVelocityLayer', { layer: layerIndex });
        },

        auditionIndicatorCell(layerIndex, rrIndex) {
            if (!this.presetInfo.isPresetLoaded) return;
            this.sendMessage('auditionIndicatorCell', { layer: layerIndex, rr: rrIndex });
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

        getFilteredPresetList() {
            let filtered = this.presetList || [];

            const query = (this.presetBrowserSearchTerm || '').trim().toLowerCase();
            if (query) {
                filtered = filtered.filter(preset =>
                    preset.displayName.toLowerCase().includes(query)
                );
            }

            const selectedTags = new Set(this.presetBrowserTags || []);
            if (selectedTags.size > 0) {
                filtered = filtered.filter(preset => {
                    const tags = Array.isArray(preset.tags) ? preset.tags : [];
                    return Array.from(selectedTags).every(tag => tags.includes(tag));
                });
            }

            return filtered;
        },

        loadNextPreset() {
            const filtered = this.getFilteredPresetList();
            if (filtered.length === 0) return;

            const currentIndex = this.currentPresetIndex;
            const filteredIndex = filtered.findIndex(preset => preset.index === currentIndex);
            const nextIndex = filteredIndex >= 0
                ? Math.min(filteredIndex + 1, filtered.length - 1)
                : 0;

            const nextPreset = filtered[nextIndex];
            if (nextPreset) {
                this.currentPresetIndex = nextPreset.index;
                this.sendMessage('loadPresetByIndex', { index: nextPreset.index });
            }
        },

        loadPrevPreset() {
            const filtered = this.getFilteredPresetList();
            if (filtered.length === 0) return;

            const currentIndex = this.currentPresetIndex;
            const filteredIndex = filtered.findIndex(preset => preset.index === currentIndex);
            const prevIndex = filteredIndex >= 0
                ? Math.max(filteredIndex - 1, 0)
                : filtered.length - 1;

            const prevPreset = filtered[prevIndex];
            if (prevPreset) {
                this.currentPresetIndex = prevPreset.index;
                this.sendMessage('loadPresetByIndex', { index: prevPreset.index });
            }
        },

        // Update methods
        updatePresetList(presets) {
            this.presetList = presets.map((preset, index) => ({
                index,
                displayName: preset.displayName || 'Unnamed Preset',
                instrumentType: preset.instrumentType || 'Unknown',
                category: preset.category || '',
                tags: Array.isArray(preset.tags) ? preset.tags : []
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

            if (typeof state.outputVolumeDb !== 'undefined') {
                this.outputVolumeDb = state.outputVolumeDb;
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

            if (typeof state.isScanningPresets !== 'undefined') {
                this.isScanningPresets = state.isScanningPresets;
            }

            if (typeof state.autoPitchMode !== 'undefined') {
                this.autoPitchMode = state.autoPitchMode;
            }

            if (typeof state.targetFrequencyHz !== 'undefined') {
                this.targetFrequencyHz = state.targetFrequencyHz;
            }

            if (typeof state.isPresetBrowserOpen !== 'undefined') {
                this.isPresetBrowserOpen = state.isPresetBrowserOpen;
            }

            if (Array.isArray(state.presetBrowserTags)) {
                this.presetBrowserTags = state.presetBrowserTags;
            }

            if (typeof state.presetBrowserSearchTerm === 'string') {
                this.presetBrowserSearchTerm = state.presetBrowserSearchTerm;
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
            const handler = this.createSliderHandler('pitch', {
                canDrag: () => this.pitchEnabled,
                onReset: () => this.resetPitch(),
                indicator: '.pitch-indicator',
                getCurrentPercent: () => ((this.presetInfo.pitchShift + 6) / 12) * 100,
                onUpdate: (percentage) => {
                    const semitones = (percentage / 100) * 12 - 6;
                    const rounded = Math.round(semitones * 10) / 10;
                    this.presetInfo.pitchShift = rounded;
                    this.sendMessage('setPitchShift', { semitones: rounded });
                }
            });
            handler.start(event);
        },

        handlePitchMove(event) {
            const handler = this.createSliderHandler('pitch', {
                canDrag: () => this.pitchEnabled,
                indicator: '.pitch-indicator',
                getCurrentPercent: () => ((this.presetInfo.pitchShift + 6) / 12) * 100,
                onUpdate: (percentage) => {
                    const semitones = (percentage / 100) * 12 - 6;
                    const rounded = Math.round(semitones * 10) / 10;
                    this.presetInfo.pitchShift = rounded;
                    this.sendMessage('setPitchShift', { semitones: rounded });
                }
            });
            handler.move(event);
        },

        resetPitch() {
            this.presetInfo.pitchShift = 0.0;
            this.sendMessage('setPitchShift', { semitones: 0 });
        },

        // Auto-pitch methods
        toggleAutoPitchMode() {
            this.autoPitchMode = !this.autoPitchMode;

            // When disabling auto-pitch, immediately reset pitch to 0 in UI to avoid flash
            if (!this.autoPitchMode) {
                this.presetInfo.pitchShift = 0.0;
            }

            this.sendMessage('setAutoPitchMode', { enabled: this.autoPitchMode });
        },

        formatHz(hz) {
            return hz.toFixed(1) + ' Hz';
        },

        get hzSliderEnabled() {
            const enabled = this.pitchEnabled && this.presetInfo.freq > 0;
            console.log('hzSliderEnabled check:', {
                pitchEnabled: this.pitchEnabled,
                freq: this.presetInfo.freq,
                freqConfidence: this.presetInfo.freqConfidence,
                enabled
            });
            return enabled;
        },

        handleHzDrag(event) {
            const handler = this.createSliderHandler('hz', {
                canDrag: () => this.hzSliderEnabled,
                onReset: () => this.resetTargetFrequency(),
                indicator: '.hz-indicator',
                getCurrentPercent: () => this.getHzSliderPosition(),
                onUpdate: (percentage) => {
                    const hz = 20 + (percentage / 100) * 480;
                    const rounded = Math.round(hz * 10) / 10;
                    this.targetFrequencyHz = rounded;
                    this.sendMessage('setTargetFrequency', { hz: rounded });
                }
            });
            handler.start(event);
        },

        handleHzMove(event) {
            const handler = this.createSliderHandler('hz', {
                canDrag: () => this.hzSliderEnabled,
                indicator: '.hz-indicator',
                getCurrentPercent: () => this.getHzSliderPosition(),
                onUpdate: (percentage) => {
                    const hz = 20 + (percentage / 100) * 480;
                    const rounded = Math.round(hz * 10) / 10;
                    this.targetFrequencyHz = rounded;
                    this.sendMessage('setTargetFrequency', { hz: rounded });
                }
            });
            handler.move(event);
        },

        resetTargetFrequency() {
            this.targetFrequencyHz = 60.0;
            this.sendMessage('setTargetFrequency', { hz: 60.0 });
        },

        getHzSliderPosition() {
            // Map 20-500 Hz to 0-100%
            const hz = Math.max(20, Math.min(500, this.targetFrequencyHz));
            return ((hz - 20) / 480) * 100;
        },

        // Output volume methods
        handleOutputVolumeDrag(event) {
            const handler = this.createSliderHandler('outputVolume', {
                onReset: () => this.resetOutputVolume(),
                indicator: '.output-volume-indicator',
                getCurrentPercent: () => this.outputVolumePercent(),
                onUpdate: (percentage) => {
                    const db = this.percentToOutputVolumeDb(percentage);
                    this.outputVolumeDb = db;
                    this.sendMessage('setOutputVolume', { db });
                }
            });
            handler.start(event);
        },

        handleOutputVolumeMove(event) {
            const handler = this.createSliderHandler('outputVolume', {
                indicator: '.output-volume-indicator',
                getCurrentPercent: () => this.outputVolumePercent(),
                onUpdate: (percentage) => {
                    const db = this.percentToOutputVolumeDb(percentage);
                    this.outputVolumeDb = db;
                    this.sendMessage('setOutputVolume', { db });
                }
            });
            handler.move(event);
        },

        resetOutputVolume() {
            this.outputVolumeDb = -6.0;
            this.sendMessage('setOutputVolume', { db: -6.0 });
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
        viewMode: 'list',
        currentFolderPath: [],
        _filteredPresetsCache: null,
        _groupedPresetListCache: null,
        presetButtonCache: {
            list: null,
            buttons: [],
            elementIndex: new WeakMap(),
            byPresetIndex: new Map()
        },

        init() {
            // Request initial data from root component
            this.sendToRoot('requestPresetList');
            this.sendToRoot('requestUpdate');

            this._onPresetBrowserKeydown = event => {
                const key = event?.key;
                if (key !== 'ArrowDown' && key !== 'ArrowUp') return;

                const target = event?.target;
                const tagName = target?.tagName?.toLowerCase();
                if (tagName === 'input' || tagName === 'textarea' || target?.isContentEditable) return;

                const root = this.getRoot();
                if (!root || !root.isPresetBrowserOpen) return;

                event.preventDefault();
                this.navigateRelative(key === 'ArrowDown' ? 1 : -1);
            };

            window.addEventListener('keydown', this._onPresetBrowserKeydown);

            const root = this.getRoot();
            if (root && typeof root.presetBrowserSearchTerm === 'string') {
                this.searchTerm = root.presetBrowserSearchTerm;
            }

            this.$watch(() => this.getRoot()?.presetBrowserSearchTerm, value => {
                if (typeof value === 'string' && value !== this.searchTerm) {
                    this.searchTerm = value;
                }
            });

            this.$watch('searchTerm', value => {
                const owner = this.getRoot();
                if (!owner) return;
                owner.presetBrowserSearchTerm = value;
                this.sendToRoot('setPresetBrowserSearchTerm', { term: value });
                this.$nextTick(() => this.refreshPresetButtonCache());
            });

            this.$watch(() => this.getRoot()?.isPresetBrowserOpen, value => {
                if (value) {
                    this.syncFolderToCurrentPreset();
                    this.$nextTick(() => {
                        this.refreshPresetButtonCache();
                        this.scrollToCurrentPreset();
                    });
                }
            });

            this.$watch(() => this.getRoot()?.currentPresetIndex, () => {
                if (this.getRoot()?.isPresetBrowserOpen) {
                    this.syncFolderToCurrentPreset();
                    this.$nextTick(() => this.scrollToCurrentPreset());
                }
            });

            this.$watch(() => this.getRoot()?.presetList?.length, () => {
                this.syncFolderToCurrentPreset();
                this.$nextTick(() => {
                    this.refreshPresetButtonCache();
                    this.scrollToCurrentPreset();
                });
            });

            this.$watch(() => this.viewMode, () => {
                this.$nextTick(() => this.refreshPresetButtonCache());
            });

            this.$watch(() => this.currentFolderPath.join('||'), () => {
                this.$nextTick(() => this.refreshPresetButtonCache());
            });

            this.syncFolderToCurrentPreset();
            this.$nextTick(() => {
                this.refreshPresetButtonCache();
                this.scrollToCurrentPreset();
            });
        },

        sendToRoot(action, data = {}) {
            const message = { action, ...data };
            if (window.__JUCE__ && window.__JUCE__.backend && window.__JUCE__.backend.emitEvent) {
                window.__JUCE__.backend.emitEvent('fromWebView', message);
            }
        },

        refreshPresets() {
            this.sendToRoot('refreshPresetList');
        },

        toggleViewMode() {
            this.viewMode = this.viewMode === 'list' ? 'folders' : 'list';
            if (this.viewMode === 'folders') {
                this.syncFolderToCurrentPreset();
                this.$nextTick(() => {
                    this.refreshPresetButtonCache();
                    this.scrollToCurrentPreset();
                });
            }
        },

        getRoot() {
            // Access the root Alpine component via window reference
            return window.drumEngineUI || window.ui;
        },

        get filteredPresets() {
            const root = this.getRoot();
            if (!root || !Array.isArray(root.presetList)) return [];
            const presetList = root.presetList;
            const query = this.searchTerm.trim().toLowerCase();
            const tagsKey = (root.presetBrowserTags || []).slice().sort().join('||');
            const cached = this._filteredPresetsCache;
            if (cached && cached.source === presetList && cached.query === query && cached.tagsKey === tagsKey) {
                return cached.value;
            }

            let filtered = presetList;
            const selectedTags = new Set(root.presetBrowserTags || []);

            // Apply search filter
            if (query) {
                filtered = filtered.filter(preset =>
                    preset.displayName.toLowerCase().includes(query)
                );
            }

            // Apply tag filter
            if (selectedTags.size > 0) {
                filtered = filtered.filter(preset => {
                    const tags = Array.isArray(preset.tags) ? preset.tags : [];
                    return Array.from(selectedTags).every(tag => tags.includes(tag));
                });
            }

            this._filteredPresetsCache = {
                source: presetList,
                query,
                tagsKey,
                value: filtered
            };

            return filtered;
        },

        get availableTags() {
            const instrumentTags = new Set();
            const otherTags = new Set();

            this.filteredPresets.forEach(preset => {
                if (preset.instrumentType) {
                    instrumentTags.add(preset.instrumentType);
                }
                const presetTags = Array.isArray(preset.tags) ? preset.tags : [];
                presetTags.forEach(tag => {
                    if (!instrumentTags.has(tag)) {
                        otherTags.add(tag);
                    }
                });
            });

            const root = this.getRoot();
            const selectedTags = root ? new Set(root.presetBrowserTags || []) : new Set();
            selectedTags.forEach(tag => {
                if (instrumentTags.has(tag)) return;
                otherTags.add(tag);
            });

            const preferredOrder = ['kick', 'snare', 'tom', 'hihat', 'crash', 'ride', 'cymbal'];
            const allTags = [...instrumentTags, ...otherTags];
            const normalizedMap = new Map();
            allTags.forEach(tag => {
                const key = String(tag).toLowerCase();
                if (!normalizedMap.has(key)) {
                    normalizedMap.set(key, tag);
                }
            });

            const promoted = preferredOrder
                .map(key => normalizedMap.get(key))
                .filter(tag => tag !== undefined);

            const promotedSet = new Set(promoted);
            const remaining = allTags.filter(tag => !promotedSet.has(tag)).sort();

            return [...promoted, ...remaining];
        },

        get currentPresetList() {
            if (this.viewMode === 'folders') {
                return this.folderView.presets;
            }
            return this.filteredPresets;
        },

        get groupedPresetList() {
            const list = this.filteredPresets;
            const cached = this._groupedPresetListCache;
            if (cached && cached.source === list) {
                return cached.value;
            }
            const groups = [];
            let currentGroup = null;

            list.forEach(preset => {
                const category = preset.category || '';
                if (!currentGroup || currentGroup.category !== category) {
                    currentGroup = { category, presets: [] };
                    groups.push(currentGroup);
                }
                currentGroup.presets.push(preset);
            });

            this._groupedPresetListCache = { source: list, value: groups };

            return groups;
        },

        get folderView() {
            const presets = this.filteredPresets;
            const path = this.currentFolderPath;
            const folders = new Set();
            const presetsInFolder = [];

            presets.forEach(preset => {
                const segments = (preset.category || '')
                    .split('/')
                    .map(segment => segment.trim())
                    .filter(Boolean);

                if (path.length > segments.length) return;

                for (let i = 0; i < path.length; i++) {
                    if (segments[i] !== path[i]) return;
                }

                if (segments.length === path.length) {
                    presetsInFolder.push(preset);
                } else {
                    folders.add(segments[path.length]);
                }
            });

            return {
                folders: Array.from(folders).filter(Boolean).sort(),
                presets: presetsInFolder
            };
        },

        toggleTag(tag) {
            const root = this.getRoot();
            if (!root) return;

            const selectedTags = new Set(root.presetBrowserTags || []);
            if (selectedTags.has(tag)) {
                selectedTags.delete(tag);
            } else {
                selectedTags.add(tag);
            }

            root.presetBrowserTags = Array.from(selectedTags);
            this.sendToRoot('setPresetBrowserTags', { tags: root.presetBrowserTags });
            this.$nextTick(() => this.refreshPresetButtonCache());
        },

        enterFolder(folderName) {
            if (!folderName) return;
            this.currentFolderPath = [...this.currentFolderPath, folderName];
            this.$nextTick(() => this.refreshPresetButtonCache());
        },

        navigateUpFolder() {
            if (this.currentFolderPath.length === 0) return;
            this.currentFolderPath = this.currentFolderPath.slice(0, -1);
            this.$nextTick(() => this.refreshPresetButtonCache());
        },

        syncFolderToCurrentPreset() {
            if (this.viewMode !== 'folders') return;

            const root = this.getRoot();
            if (!root || !Array.isArray(root.presetList)) {
                this.currentFolderPath = [];
                return;
            }

            const preset = root.presetList.find(item => item.index === root.currentPresetIndex);
            if (!preset || !preset.category) {
                this.currentFolderPath = [];
                return;
            }

            const segments = preset.category
                .split('/')
                .map(segment => segment.trim())
                .filter(Boolean);
            this.currentFolderPath = segments;
        },

        optionId(index) {
            return `preset-option-${index}`;
        },

        scrollToCurrentPreset() {
            const root = this.getRoot();
            if (!root) return;

            const activeId = this.getActiveOptionId();
            if (!activeId) return;

            let item = this.presetButtonCache.byPresetIndex.get(root.currentPresetIndex);
            if (!item) {
                this.refreshPresetButtonCache();
                item = this.presetButtonCache.byPresetIndex.get(root.currentPresetIndex);
            }
            if (!item) return;

            const list = this.presetButtonCache.list || item.closest('[aria-label="Preset list"]');
            if (!list) return;

            const listRect = list.getBoundingClientRect();
            const itemRect = item.getBoundingClientRect();
            const isInView = itemRect.top >= listRect.top && itemRect.bottom <= listRect.bottom;
            if (isInView) return;

            item.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'nearest' });
        },

        getActiveOptionId() {
            const root = this.getRoot();
            if (!root) return '';
            const activeIndex = root.currentPresetIndex;
            if (typeof activeIndex !== 'number' || activeIndex < 0) return '';
            return this.optionId(activeIndex);
        },

        loadPreset(index) {
            const root = this.getRoot();
            if (root) {
                root.currentPresetIndex = index;
                this.sendToRoot('loadPresetByIndex', { index });
            }
        },

        refreshPresetButtonCache() {
            const list = document.querySelector('[aria-label="Preset list"]');
            const buttons = list ? Array.from(list.querySelectorAll('[data-preset-item="true"]')) : [];
            const elementIndex = new WeakMap();
            const byPresetIndex = new Map();

            buttons.forEach((button, index) => {
                elementIndex.set(button, index);
                const presetIndex = Number(button?.dataset?.presetIndex);
                if (!Number.isNaN(presetIndex)) {
                    byPresetIndex.set(presetIndex, button);
                }
            });

            this.presetButtonCache = { list, buttons, elementIndex, byPresetIndex };
        },

        getPresetButtons() {
            return this.presetButtonCache.buttons || [];
        },

        navigateRelative(direction) {
            let buttons = this.getPresetButtons();
            if (!buttons.length) {
                this.refreshPresetButtonCache();
                buttons = this.getPresetButtons();
            }

            if (!buttons.length) return;

            const root = this.getRoot();
            const currentPresetIndex = root?.currentPresetIndex;
            const byPresetIndex = this.presetButtonCache.byPresetIndex || new Map();
            const currentButton = byPresetIndex.get(Number(currentPresetIndex));
            const currentIndex = currentButton
                ? buttons.indexOf(currentButton)
                : -1;

            const startIndex = currentIndex >= 0
                ? currentIndex
                : (direction > 0 ? -1 : buttons.length);

            const nextIndex = startIndex + direction;
            if (nextIndex < 0 || nextIndex >= buttons.length) return;

            const next = buttons[nextIndex];
            const nextPresetIndex = Number(next?.dataset?.presetIndex);
            if (!Number.isNaN(nextPresetIndex)) {
                this.loadPreset(nextPresetIndex);
            }
        },

        navigateDown() {
            this.navigateRelative(1);
        },

        navigateUp() {
            this.navigateRelative(-1);
        },

        getPresetName(displayName) {
            return displayName;
        }
    };
};

// Start Alpine
Alpine.start();
