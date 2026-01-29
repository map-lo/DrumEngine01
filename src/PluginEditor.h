#pragma once

#include "PluginProcessor.h"

//==============================================================================
class PresetBrowserWindow;

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

    void openPresetBrowserWindow();
    void closePresetBrowserWindow();
    void togglePresetBrowserWindow();
    std::unique_ptr<juce::WebBrowserComponent> createPresetBrowserWebViewForDevelopment();
    std::unique_ptr<juce::WebBrowserComponent> createPresetBrowserWebViewForProduction();
    juce::String buildInlineHtml(const juce::String &html,
                                 const juce::String &css,
                                 const juce::String &js) const;

    // Preset management
    void scanPresetsFolder();
    void loadPresetByIndex(int index);
    void loadNextPreset();
    void loadPrevPreset();
    void browseForPreset();

    AudioPluginAudioProcessor &processorRef;

    // WebView component
    std::unique_ptr<juce::WebBrowserComponent> webView;
    juce::WebBrowserComponent *presetBrowserWebView = nullptr;
    std::unique_ptr<PresetBrowserWindow> presetBrowserWindow;
    juce::String htmlContent; // Store HTML for resource provider
    juce::String presetBrowserHtmlContent;

    // Preset management
    struct PresetEntry
    {
        juce::String displayName;
        juce::String category;
        juce::String instrumentType;
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
    bool presetBrowserPageLoaded = false;

    // Cache last sent state to avoid unnecessary updates
    juce::String lastSentState;
    juce::String lastSentStatePresetBrowser;

#if JUCE_DEBUG
    bool useLiveReload = true; // Enable hot reload in debug builds
#else
    bool useLiveReload = false; // Use embedded resources in release
#endif

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(AudioPluginAudioProcessorEditor)
};
