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
    };

    PresetInfo getPresetInfo() const;

private:
    //==============================================================================
    DrumEngine::Engine engine;

    // Track last loaded preset for UI
    mutable juce::CriticalSection presetInfoLock;
    PresetInfo currentPresetInfo;

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(AudioPluginAudioProcessor)
};
