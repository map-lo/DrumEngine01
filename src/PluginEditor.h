#pragma once

#include "PluginProcessor.h"

//==============================================================================
class MonospaceLookAndFeel : public juce::LookAndFeel_V4
{
public:
    juce::Font getComboBoxFont(juce::ComboBox &) override
    {
        return juce::Font(juce::FontOptions(juce::Font::getDefaultMonospacedFontName(), 11.0f, juce::Font::plain));
    }

    juce::Font getPopupMenuFont() override
    {
        return juce::Font(juce::FontOptions(juce::Font::getDefaultMonospacedFontName(), 11.0f, juce::Font::plain));
    }

    void getIdealPopupMenuItemSize(const juce::String &text, bool isSeparator, int standardMenuItemHeight, int &idealWidth, int &idealHeight) override
    {
        LookAndFeel_V4::getIdealPopupMenuItemSize(text, isSeparator, standardMenuItemHeight, idealWidth, idealHeight);
        idealHeight = 18; // Compact item height
    }
};

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
    void loadNextPreset();
    void loadPrevPreset();

    AudioPluginAudioProcessor &processorRef;

    // UI Components
    juce::TextButton loadPresetButton;
    juce::ComboBox presetBrowser;
    juce::TextButton prevPresetButton;
    juce::TextButton nextPresetButton;
    juce::Label presetBrowserLabel;
    juce::Label statusLabel;
    juce::Label presetInfoLabel;
    juce::Label instructionsLabel;
    juce::ComboBox outputModeCombo;
    juce::Label outputModeLabel;
    juce::TextButton velocityToggle;
    juce::Label velocityToggleLabel;

    // Preset management
    struct PresetEntry
    {
        juce::String displayName;
        juce::String category;
        juce::File file;
    };
    std::vector<PresetEntry> presetList;
    int currentPresetIndex = -1;

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

    // Custom look and feel for monospace preset browser
    MonospaceLookAndFeel monospaceLookAndFeel;

    // Status tracking
    juce::String lastLoadedPreset;
    juce::String lastStatusMessage;
    bool statusIsError = false;

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(AudioPluginAudioProcessorEditor)
};
