#pragma once

#include "PluginProcessor.h"

//==============================================================================
class AudioPluginAudioProcessorEditor final : public juce::AudioProcessorEditor,
                                              private juce::Timer
{
public:
    explicit AudioPluginAudioProcessorEditor(AudioPluginAudioProcessor &);
    ~AudioPluginAudioProcessorEditor() override;

    //==============================================================================
    void paint(juce::Graphics &) override;
    void resized() override;

private:
    void timerCallback() override;
    void loadPresetButtonClicked();
    void updateStatusDisplay();

    AudioPluginAudioProcessor &processorRef;

    // UI Components
    juce::TextButton loadPresetButton;
    juce::Label statusLabel;
    juce::Label presetInfoLabel;
    juce::Label instructionsLabel;

    // File chooser (must persist for async callback)
    std::unique_ptr<juce::FileChooser> fileChooser;

    // Status tracking
    juce::String lastLoadedPreset;
    juce::String lastStatusMessage;
    bool statusIsError = false;

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(AudioPluginAudioProcessorEditor)
};
