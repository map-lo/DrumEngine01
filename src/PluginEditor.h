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
    void updateSlotControls();
    void onSlotVolumeChanged(int slotIndex);
    void onSlotMuteClicked(int slotIndex);
    void onSlotSoloClicked(int slotIndex);

    AudioPluginAudioProcessor &processorRef;

    // UI Components
    juce::TextButton loadPresetButton;
    juce::Label statusLabel;
    juce::Label presetInfoLabel;
    juce::Label instructionsLabel;

    // Slot controls (up to 8 slots)
    struct SlotControl
    {
        juce::Label nameLabel;
        juce::Slider volumeSlider;
        juce::TextButton muteButton;
        juce::TextButton soloButton;
        bool isActive = false;
    };
    std::array<SlotControl, 8> slotControls;

    // File chooser (must persist for async callback)
    std::unique_ptr<juce::FileChooser> fileChooser;

    // Status tracking
    juce::String lastLoadedPreset;
    juce::String lastStatusMessage;
    bool statusIsError = false;

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(AudioPluginAudioProcessorEditor)
};
