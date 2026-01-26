#pragma once

#include "RuntimePreset.h"
#include "Voice.h"
#include <deque>
#include <array>
#include <atomic>

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

        struct PresetInfo
        {
            bool isValid = false;
            juce::String instrumentType;
            int fixedMidiNote = 38;
            int slotCount = 0;
            int layerCount = 0;
            juce::StringArray slotNames;
            std::array<bool, 8> activeSlots = {}; // Which slots have samples
        };

        PresetInfo getCurrentPresetInfo() const;

        // Audio processing
        void processBlock(juce::AudioBuffer<float> &buffer, juce::MidiBuffer &midiMessages);

        // Config
        void setFadeLengthSamples(int samples) { fadeLenSamples = samples; }
        int getFadeLengthSamples() const { return fadeLenSamples; }

        // Slot controls
        void setSlotGain(int slotIndex, float gain);
        void setSlotMuted(int slotIndex, bool muted);
        void setSlotSoloed(int slotIndex, bool soloed);
        float getEffectiveSlotGain(int slotIndex) const;

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

        // Voice management
        VoicePool voicePool;
        std::deque<HitGroup> activeHitGroups;

        // RR counters per velocity layer
        std::array<int, kMaxVelocityLayers> rrCounters = {};

        // Internal methods
        void handleNoteOn(int note, int velocity);
        void render(juce::AudioBuffer<float> &buffer, int startSample, int numSamples);

        JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(Engine)
    };

} // namespace DrumEngine
