#pragma once

#include "PluginProcessor.h"
#include "PresetCacheBuilder.h"

//==============================================================================
class AudioPluginAudioProcessorEditor final : public juce::AudioProcessorEditor,
                                              private juce::Timer,
                                              private AudioPluginAudioProcessor::HitListener
{
public:
    explicit AudioPluginAudioProcessorEditor(AudioPluginAudioProcessor &);
    ~AudioPluginAudioProcessorEditor() override;

    //==============================================================================
    void paint(juce::Graphics &) override;
    void resized() override;

private:
    void timerCallback() override;

    // HitListener interface
    void onHit(int velocityLayer, int rrIndex) override;

    // WebView communication handlers
    void handleMessageFromWebView(const juce::String &message);
    void sendStateUpdateToWebView();
    void sendPresetListToWebView();

    // Development helpers
    void setupWebViewForDevelopment();
    void setupWebViewForProduction();
    juce::File getUIDirectory();

    AudioPluginAudioProcessor &processorRef;

    // WebView component
    std::unique_ptr<juce::WebBrowserComponent> webView;
    juce::String htmlContent; // Store HTML for resource provider

    // Preset management
    using PresetEntry = PresetCacheBuilder::PresetEntry;
    std::vector<PresetEntry> presetList;
    int currentPresetIndex = -1;

    // Preset management
    juce::File getPresetRootFolder() const;
    juce::File getPresetCacheFile() const;
    bool loadPresetCache();
    void savePresetCache() const;
    void startPresetScanAsync();
    void scanPresetsFolder();
    void loadPresetByIndex(int index);
    void loadNextPreset();
    void loadPrevPreset();
    void browseForPreset();
    int resolvePresetIndexFromState() const;

    // File chooser (must persist for async callback)
    std::unique_ptr<juce::FileChooser> fileChooser;

    // Status tracking
    juce::String lastStatusMessage;
    bool statusIsError = false;
    bool pageLoaded = false;
    bool isScanningPresets = false;

    // Cache last sent state to avoid unnecessary updates
    juce::String lastSentState;

    static constexpr int presetCacheSchemaVersion = 1;

#if JUCE_DEBUG
    bool useLiveReload = true; // Enable hot reload in debug builds
#else
    bool useLiveReload = false; // Use embedded resources in release
#endif

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(AudioPluginAudioProcessorEditor)
};
