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

    // WebView communication handlers
    void handleMessageFromWebView(const juce::String &message);
    void sendStateUpdateToWebView();
    void sendPresetListToWebView();

    // Development helpers
    void setupWebViewForDevelopment();
    void setupWebViewForProduction();
    juce::File getUIDirectory();

    // Preset management
    void scanPresetsFolder();
    void loadPresetByIndex(int index);
    void loadNextPreset();
    void loadPrevPreset();
    void browseForPreset();

    AudioPluginAudioProcessor &processorRef;

    // WebView component
    std::unique_ptr<juce::WebBrowserComponent> webView;
    juce::String htmlContent; // Store HTML for resource provider

    // Preset management
    struct PresetEntry
    {
        juce::String displayName;
        juce::String category;
        juce::File file;
    };
    std::vector<PresetEntry> presetList;
    int currentPresetIndex = -1;

    // File chooser (must persist for async callback)
    std::unique_ptr<juce::FileChooser> fileChooser;

    // Status tracking
    juce::String lastStatusMessage;
    bool statusIsError = false;
    bool pageLoaded = false;

    // Cache last sent state to avoid unnecessary updates
    juce::String lastSentState;

#if JUCE_DEBUG
    bool useLiveReload = true; // Enable hot reload in debug builds
#else
    bool useLiveReload = false; // Use embedded resources in release
#endif

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(AudioPluginAudioProcessorEditor)
};
