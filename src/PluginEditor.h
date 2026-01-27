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
    void onOutputModeChanged();
    void onPresetSelected();
    void onVelocityToggleClicked();
    void scanPresetsFolder();
    void loadPresetByIndex(int index);

    AudioPluginAudioProcessor &processorRef;

    // UI Components
    juce::TextButton loadPresetButton;
    juce::ComboBox presetBrowser;
    juce::Label presetBrowserLabel;
    juce::Label statusLabel;
    juce::Label presetInfoLabel;
    juce::Label instructionsLabel;
    juce::ComboBox outputModeCombo;
    juce::Label outputModeLabel;
    juce::ToggleButton velocityToggle;
    juce::Label velocityToggleLabel;

    // Preset management
    struct PresetEntry
    {
        juce::String displayName;
        juce::File file;
        int indentLevel = 0;
        bool isSeparator = false;
    };
    std::vector<PresetEntry> presetList;

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
