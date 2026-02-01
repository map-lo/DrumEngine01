#pragma once

#include <juce_audio_processors/juce_audio_processors.h>
#include "engine/Engine.h"

//==============================================================================
class AudioPluginAudioProcessor final : public juce::AudioProcessor
{
public:
    //==============================================================================
    AudioPluginAudioProcessor();
    ~AudioPluginAudioProcessor() override;

    //==============================================================================
    void prepareToPlay(double sampleRate, int samplesPerBlock) override;
    void releaseResources() override;

    bool isBusesLayoutSupported(const BusesLayout &layouts) const override;

    void processBlock(juce::AudioBuffer<float> &, juce::MidiBuffer &) override;
    using AudioProcessor::processBlock;

    //==============================================================================
    juce::AudioProcessorEditor *createEditor() override;
    bool hasEditor() const override;

    //==============================================================================
    const juce::String getName() const override;

    bool acceptsMidi() const override;
    bool producesMidi() const override;
    bool isMidiEffect() const override;
    double getTailLengthSeconds() const override;

    //==============================================================================
    int getNumPrograms() override;
    int getCurrentProgram() override;
    void setCurrentProgram(int index) override;
    const juce::String getProgramName(int index) override;
    void changeProgramName(int index, const juce::String &newName) override;

    //==============================================================================
    void getStateInformation(juce::MemoryBlock &destData) override;
    void setStateInformation(const void *data, int sizeInBytes) override;

    //==============================================================================
    // Preset management
    juce::Result loadPresetFromFile(const juce::File &presetFile);

    struct PresetInfo
    {
        bool isPresetLoaded = false;
        juce::String presetName;
        juce::String instrumentType;
        int fixedMidiNote = 38;
        int slotCount = 0;
        int layerCount = 0;
        juce::StringArray slotNames;
        std::array<bool, 8> activeSlots = {}; // Which slots have samples
        bool useVelocityToVolume = false;
    };

    PresetInfo getPresetInfo() const;

    // Slot control
    struct SlotState
    {
        float volume = 1.0f;
        bool muted = false;
        bool soloed = false;
    };

    void setSlotVolume(int slotIndex, float volume);
    void setSlotMuted(int slotIndex, bool muted);
    void setSlotSoloed(int slotIndex, bool soloed);
    SlotState getSlotState(int slotIndex) const;

    // Output mode
    enum class OutputMode
    {
        Stereo,  // Single stereo output (all slots mixed)
        MultiOut // 8 stereo pairs (one per slot)
    };

    void setOutputMode(OutputMode mode);
    OutputMode getOutputMode() const { return outputMode; }

    // Velocity to volume control
    void setUseVelocityToVolume(bool enabled);
    bool getUseVelocityToVolume() const;

    // MIDI note override
    void setFixedMidiNote(int note);
    int getFixedMidiNote() const;

    // Pitch shift
    void setPitchShift(float semitones);
    float getPitchShift() const { return pitchShift; }

    // Resampling mode
    void setResamplingMode(DrumEngine::ResamplingMode mode);
    DrumEngine::ResamplingMode getResamplingMode() const { return resamplingMode; }

    // MIDI note lock (prevents preset changes from overriding custom note)
    void setMidiNoteLocked(bool locked);
    bool getMidiNoteLocked() const;

    // Engine access for editor
    const DrumEngine::Engine &getEngine() const { return engine; }

    // Version information (from CMakeLists.txt)
    static juce::String getPluginVersion() { return DRUMENGINE_VERSION; }
    static int getVersionMajor() { return DRUMENGINE_VERSION_MAJOR; }
    static int getVersionMinor() { return DRUMENGINE_VERSION_MINOR; }
    static int getVersionPatch() { return DRUMENGINE_VERSION_PATCH; }

    // Hit notification for UI visualization
    class HitListener
    {
    public:
        virtual ~HitListener() = default;
        virtual void onHit(int velocityLayer, int rrIndex) = 0;
    };

    void addHitListener(HitListener *listener) { hitListeners.add(listener); }
    void removeHitListener(HitListener *listener) { hitListeners.remove(listener); }

private:
    // Common preset loading logic
    juce::Result loadPresetFromJsonInternal(const juce::String &jsonText,
                                            const juce::String &presetName,
                                            const juce::String &defaultRootFolder = {});
    void updateLatency();
    //==============================================================================
    DrumEngine::Engine engine;
    OutputMode outputMode = OutputMode::Stereo;

    // Track last loaded preset for UI
    mutable juce::CriticalSection presetInfoLock;
    PresetInfo currentPresetInfo;
    juce::String currentPresetJsonData;   // Full JSON content of preset
    juce::String currentPresetRootFolder; // Root folder path for samples
    bool stateRestored = false;           // Track if state was restored from session

    // Slot states (volume, mute, solo per slot)
    mutable juce::CriticalSection slotStateLock;
    std::array<SlotState, 8> slotStates;

    // MIDI note lock and custom note
    bool midiNoteLocked = false;
    int customMidiNote = -1; // -1 means use preset default

    // Pitch shift
    float pitchShift = 0.0f;

    // Resampling mode
    DrumEngine::ResamplingMode resamplingMode = DrumEngine::ResamplingMode::Lanczos3;

    // Hit listeners
    juce::ListenerList<HitListener> hitListeners;

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(AudioPluginAudioProcessor)
};
