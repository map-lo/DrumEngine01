#pragma once

#include "ResamplingMode.h"
#include "RuntimePreset.h"
#include "Voice.h"
#include <deque>
#include <array>
#include <atomic>
#include <functional>
#include <map>

namespace DrumEngine
{

    // Main drum engine
    class Engine
    {
    public:
        Engine();
        ~Engine();

        // Lifecycle
        void prepareToPlay(double sampleRate, int samplesPerBlock);
        void reset();

        // Preset loading (call from non-audio thread)
        juce::Result loadPresetAsync(const juce::File &presetFile);
        juce::Result loadPresetFromJson(const juce::String &jsonText, const juce::String &rootFolder);

        struct PresetInfo
        {
            bool isValid = false;
            juce::String instrumentType;
            int fixedMidiNote = 38;
            int slotCount = 0;
            int layerCount = 0;
            juce::StringArray slotNames;
            std::array<bool, 8> activeSlots = {}; // Which slots have samples
            float fundamentalFrequency = 0.0f;    // Hz, 0 = not detected
            float freqConfidence = 0.0f;          // 0-1, detection confidence
        };

        PresetInfo getCurrentPresetInfo() const;

        // Audio processing
        void processBlock(juce::AudioBuffer<float> &buffer, juce::MidiBuffer &midiMessages, bool multiOutEnabled = false);
        int getFadeLengthSamples() const { return fadeLenSamples; }

        // Slot controls
        void setSlotGain(int slotIndex, float gain);
        void setSlotMuted(int slotIndex, bool muted);
        void setSlotSoloed(int slotIndex, bool soloed);
        float getEffectiveSlotGain(int slotIndex) const;

        // Velocity to volume control
        void setUseVelocityToVolume(bool enabled);
        bool getUseVelocityToVolume() const;

        // MIDI note override
        void setFixedMidiNote(int note);
        int getFixedMidiNote() const;

        // UI audition (preview) helpers
        void triggerPreview(int velocity, int slotIndex = -1);
        void triggerPreviewLayer(int layerIndex, int slotIndex = -1);
        void triggerPreviewExact(int layerIndex, int rrIndex, int velocity, int slotIndex = -1);

        // Pitch shift (semitones, -6 to +6)
        void setPitchShift(float semitones);
        float getPitchShift() const { return pitchShiftSemitones.load(); }

        // Resampling mode
        void setResamplingMode(ResamplingMode mode);
        ResamplingMode getResamplingMode() const { return resamplingMode.load(); }

        // Latency reporting (aggregated)
        void setLatencyContribution(const juce::String &name, int samples);
        void removeLatencyContribution(const juce::String &name);
        int getLatencySamples() const;
        int getResamplingLatencySamples() const;

        double getCurrentSampleRate() const { return currentSampleRate; }

        // Access to active preset (thread-safe, read-only)
        const RuntimePreset *getActivePreset() const { return activePreset.load(); }

        // Hit notification callback (velocity layer index 0-9, RR index 0-4)
        using HitCallback = std::function<void(int velocityLayer, int rrIndex)>;
        void setHitCallback(HitCallback callback) { hitCallback = std::move(callback); }

    private:
        static constexpr int kMaxHitGroups = 3;
        static constexpr int kMaxVelocityLayers = 10;

        double currentSampleRate = 44100.0;
        int fadeLenSamples = 32;

        // Preset (thread-safe swapping)
        std::atomic<RuntimePreset *> activePreset{nullptr};
        std::unique_ptr<RuntimePreset> presetStorage;

        // Track schema for preset info
        mutable juce::CriticalSection schemaLock;
        PresetSchema currentSchema;

        // Slot controls (gain, mute, solo per slot)
        std::array<float, 8> slotGains = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
        std::array<bool, 8> slotMuted = {};
        std::array<bool, 8> slotSoloed = {};
        bool anySoloed = false;

        // Pitch shift
        std::atomic<float> pitchShiftSemitones{0.0f};

        // Resampling
        std::atomic<ResamplingMode> resamplingMode{ResamplingMode::CatmullRom};

        // Latency contributions
        mutable juce::CriticalSection latencyLock;
        std::map<juce::String, int> latencyContributions;

        // Voice management
        VoicePool voicePool;
        std::deque<HitGroup> activeHitGroups;

        // Output resampling buffer
        juce::AudioBuffer<float> sourceBuffer;

        // RR counters per velocity layer
        std::array<int, kMaxVelocityLayers> rrCounters = {};

        // Hit notification
        HitCallback hitCallback;

        // Internal methods
        void handleNoteOn(int note, int velocity);
        void render(juce::AudioBuffer<float> &buffer, int startSample, int numSamples, bool multiOutEnabled);

        void triggerPreviewByLayerIndex(int layerIndex, int velocity, int slotIndex, bool advanceRr);
        void triggerPreviewByExactRr(int layerIndex, int rrIndex, int velocity, int slotIndex);
    };

} // namespace DrumEngine
