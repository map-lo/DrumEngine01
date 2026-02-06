#include "PluginEditor.h"
#include "PluginProcessor.h"
#include "engine/MidiNoteUtils.h"
#include "engine/DebugLog.h"
#include "BinaryData.h"
#include <thread>

// Debug logging helper (shared log file)
static void logToFile(const juce::String &message)
{
    DrumEngine::debugLog(message);
}

static juce::String resamplingModeToString(DrumEngine::ResamplingMode mode)
{
    switch (mode)
    {
    case DrumEngine::ResamplingMode::Off:
        return "off";
    case DrumEngine::ResamplingMode::CatmullRom:
        return "catmullrom";
    case DrumEngine::ResamplingMode::Lanczos3:
    default:
        return "lanczos3";
    }
}

static DrumEngine::ResamplingMode resamplingModeFromString(const juce::String &value)
{
    if (value == "off")
        return DrumEngine::ResamplingMode::Off;
    if (value == "low" || value == "normal" || value == "punch" || value == "catmullrom")
        return DrumEngine::ResamplingMode::CatmullRom;
    if (value == "ultra" || value == "smooth" || value == "lanczos3")
        return DrumEngine::ResamplingMode::Lanczos3;
    return DrumEngine::ResamplingMode::Lanczos3;
}

//==============================================================================
AudioPluginAudioProcessorEditor::AudioPluginAudioProcessorEditor(AudioPluginAudioProcessor &p)
    : AudioProcessorEditor(&p), processorRef(p)
{
    logToFile("=== DrumEngine01 Editor Constructor ===");
    logToFile("useLiveReload: " + juce::String(useLiveReload ? "true" : "false"));

    // Choose setup based on build mode
    if (useLiveReload)
        setupWebViewForDevelopment();
    else
        setupWebViewForProduction();

    // Load preset cache or scan presets folder
    if (!loadPresetCache())
        startPresetScanAsync();

    // Register for hit notifications
    processorRef.addHitListener(this);

    // Start timer to update UI
    startTimer(100); // Update every 100ms

    const bool open = processorRef.getPresetBrowserOpen();
    setSize(open ? 660 + 300 : 660, 440);
    setResizable(false, false);
}

//==============================================================================
juce::File AudioPluginAudioProcessorEditor::getUIDirectory()
{
    // For development, use hardcoded absolute path
    // This is only used in debug builds with hot reloading
    juce::File uiDir("/Users/marian/Development/JUCE-Plugins/DrumEngine01/src/ui");

    logToFile("UI Directory: " + uiDir.getFullPathName());
    logToFile("UI Directory exists: " + juce::String(uiDir.exists() ? "YES" : "NO"));

    return uiDir;
}

void AudioPluginAudioProcessorEditor::setupWebViewForDevelopment()
{
    logToFile("setupWebViewForDevelopment() called");

    // Connect to Vite dev server
    juce::String viteServerUrl = "http://localhost:5173";
    logToFile("Connecting to Vite dev server: " + viteServerUrl);

    // Create WebBrowserComponent with native integration
    webView = std::make_unique<juce::WebBrowserComponent>(
        juce::WebBrowserComponent::Options{}
            .withBackend(juce::WebBrowserComponent::Options::Backend::defaultBackend)
            .withNativeIntegrationEnabled()
            .withUserScript(
                "console.log('JUCE WebView initialized - DEVELOPMENT MODE with Vite HMR');"
                "window.juce = window.__JUCE__.backend;")
            .withEventListener("fromWebView", [this](const juce::var &message)
                               { 
                                   logToFile("C++ received fromWebView event: " + juce::JSON::toString(message));
                                   handleMessageFromWebView(juce::JSON::toString(message)); })
            .withEventListener("pageReady", [this](const juce::var &)
                               { 
                                   logToFile("C++ received pageReady event");
                                   pageLoaded = true;
                                   sendPresetListToWebView();
                                   sendStateUpdateToWebView(); }));

    addAndMakeVisible(webView.get());

    // Navigate to Vite dev server
    logToFile("Loading URL: " + viteServerUrl);
    webView->goToURL(viteServerUrl);

    logToFile("setupWebViewForDevelopment() completed - using Vite HMR");
}

void AudioPluginAudioProcessorEditor::setupWebViewForProduction()
{
    logToFile("setupWebViewForProduction() called");

    // Create WebBrowserComponent with native integration and resource provider
    webView = std::make_unique<juce::WebBrowserComponent>(
        juce::WebBrowserComponent::Options{}
            .withBackend(juce::WebBrowserComponent::Options::Backend::defaultBackend)
            .withNativeIntegrationEnabled()
            .withUserScript(
                "console.log('JUCE WebView initialized - PRODUCTION MODE with Vite bundle');"
                "window.juce = window.__JUCE__.backend;")
            .withEventListener("fromWebView", [this](const juce::var &message)
                               { 
                                   logToFile("C++ received fromWebView event: " + juce::JSON::toString(message));
                                   handleMessageFromWebView(juce::JSON::toString(message)); })
            .withEventListener("pageReady", [this](const juce::var &)
                               { 
                                   logToFile("C++ received pageReady event");
                                   pageLoaded = true;
                                   sendPresetListToWebView();
                                   sendStateUpdateToWebView(); })
            .withResourceProvider([](const juce::String &url) -> std::optional<juce::WebBrowserComponent::Resource>
                                  {
                // Helper lambda to create resource from binary data
                auto createResource = [](const char* data, size_t size, const juce::String& mimeType) {
                    std::vector<std::byte> vec;
                    vec.resize(size);
                    std::memcpy(vec.data(), data, size);
                    return juce::WebBrowserComponent::Resource { vec, mimeType.toStdString() };
                };

                // Serve index.html
                if (url == "/" || url == "/index.html")
                {
                    return createResource(BinaryData::index_html, 
                                        BinaryData::index_htmlSize, 
                                        "text/html");
                }
                
                // Serve JavaScript
                if (url.endsWith("/app.js") || url.endsWith("app.js"))
                {
                    return createResource(BinaryData::app_js, 
                                        BinaryData::app_jsSize, 
                                        "application/javascript");
                }
                
                // Serve CSS
                if (url.endsWith("/styles.css") || url.endsWith("styles.css"))
                {
                    return createResource(BinaryData::styles_css, 
                                        BinaryData::styles_cssSize, 
                                        "text/css");
                }
                
                // Serve fonts
                if (url.contains("Inter_24pt-Bold"))
                    return createResource(BinaryData::Inter_24ptBold_ttf, 
                                        BinaryData::Inter_24ptBold_ttfSize, 
                                        "font/ttf");
                                        
                if (url.contains("Inter_24pt-Medium"))
                    return createResource(BinaryData::Inter_24ptMedium_ttf, 
                                        BinaryData::Inter_24ptMedium_ttfSize, 
                                        "font/ttf");
                                        
                if (url.contains("Inter_24pt-Regular"))
                    return createResource(BinaryData::Inter_24ptRegular_ttf, 
                                        BinaryData::Inter_24ptRegular_ttfSize, 
                                        "font/ttf");
                                        
                if (url.contains("Inter_24pt-SemiBold"))
                    return createResource(BinaryData::Inter_24ptSemiBold_ttf, 
                                        BinaryData::Inter_24ptSemiBold_ttfSize, 
                                        "font/ttf");
                
                return std::nullopt; }));

    addAndMakeVisible(webView.get());

    // Navigate to the root which will trigger the resource provider
    webView->goToURL(juce::WebBrowserComponent::getResourceProviderRoot());

    logToFile("setupWebViewForProduction() completed - using Vite dist bundle");
}

AudioPluginAudioProcessorEditor::~AudioPluginAudioProcessorEditor()
{
    processorRef.removeHitListener(this);
    stopTimer();
    webView.reset();
}

//==============================================================================
void AudioPluginAudioProcessorEditor::paint(juce::Graphics &g)
{
    // WebView fills the entire area
    g.fillAll(juce::Colour(0xff252525));
}

void AudioPluginAudioProcessorEditor::resized()
{
    if (webView)
        webView->setBounds(getLocalBounds());
}

//==============================================================================
void AudioPluginAudioProcessorEditor::onHit(int velocityLayer, int rrIndex)
{
    // Send hit notification to WebView
    if (webView)
    {
        juce::DynamicObject::Ptr message = new juce::DynamicObject();
        message->setProperty("action", "hit");
        message->setProperty("velocityLayer", velocityLayer + 1); // 1-indexed for CSS classes
        message->setProperty("rrIndex", rrIndex + 1);             // 1-indexed for CSS classes

        juce::var messageVar(message.get());
        webView->emitEventIfBrowserIsVisible("hit", messageVar);
    }
}

void AudioPluginAudioProcessorEditor::timerCallback()
{
    if (pageLoaded)
        sendStateUpdateToWebView();
}

//==============================================================================
void AudioPluginAudioProcessorEditor::handleMessageFromWebView(const juce::String &message)
{
    auto json = juce::JSON::parse(message);
    if (!json.isObject())
        return;

    auto obj = json.getDynamicObject();
    if (!obj)
        return;

    juce::String action = obj->getProperty("action").toString();

    if (action == "requestPresetList")
    {
        sendPresetListToWebView();
    }
    else if (action == "refreshPresetList")
    {
        startPresetScanAsync();
    }
    else if (action == "requestUpdate")
    {
        sendStateUpdateToWebView();
    }
    else if (action == "loadPresetByIndex")
    {
        int index = obj->getProperty("index");
        loadPresetByIndex(index);
    }
    else if (action == "loadNextPreset")
    {
        loadNextPreset();
    }
    else if (action == "loadPrevPreset")
    {
        loadPrevPreset();
    }
    else if (action == "browseForPreset")
    {
        browseForPreset();
    }
    else if (action == "openPresetBrowser")
    {
        // Expand window width by 300px
        setSize(660 + 300, 440);
        processorRef.setPresetBrowserOpen(true);
    }
    else if (action == "closePresetBrowser")
    {
        // Restore original window size
        setSize(660, 440);
        processorRef.setPresetBrowserOpen(false);
    }
    else if (action == "setPresetBrowserTags")
    {
        juce::StringArray tags;
        auto tagsVar = obj->getProperty("tags");
        if (tagsVar.isArray())
        {
            if (const auto *tagsArray = tagsVar.getArray())
            {
                for (const auto &tagVar : *tagsArray)
                    tags.addIfNotAlreadyThere(tagVar.toString());
            }
        }
        processorRef.setPresetBrowserSelectedTags(tags);
    }
    else if (action == "setPresetBrowserSearchTerm")
    {
        processorRef.setPresetBrowserSearchTerm(obj->getProperty("term").toString());
    }
    else if (action == "setPresetBrowserViewMode")
    {
        processorRef.setPresetBrowserViewMode(obj->getProperty("mode").toString());
    }
    else if (action == "togglePresetFavorite")
    {
        int index = obj->getProperty("index");
        if (index >= 0 && index < static_cast<int>(presetList.size()))
        {
            auto &preset = presetList[static_cast<size_t>(index)];
            const auto presetId = getPresetIdForFile(preset.file);

            if (favoritePresetIds.contains(presetId))
                favoritePresetIds.removeString(presetId, true);
            else
                favoritePresetIds.addIfNotAlreadyThere(presetId);

            applyFavoritesToPresetList();
            savePresetMetadata();
            savePresetCache();
            sendPresetListToWebView();
        }
    }
    else if (action == "setOutputMode")
    {
        juce::String mode = obj->getProperty("mode").toString();
        auto newMode = (mode == "multiout") ? AudioPluginAudioProcessor::OutputMode::MultiOut
                                            : AudioPluginAudioProcessor::OutputMode::Stereo;
        processorRef.setOutputMode(newMode);

        if (newMode == AudioPluginAudioProcessor::OutputMode::MultiOut)
            lastStatusMessage = "Multi-Out: Mix→1-2, Slot1→3-4, Slot2→5-6, etc.";
        else
            lastStatusMessage = "Stereo: Mix output on channels 1-2";
        statusIsError = false;
    }
    else if (action == "setVelocityToVolume")
    {
        bool enabled = obj->getProperty("enabled");
        processorRef.setUseVelocityToVolume(enabled);
    }
    else if (action == "setFixedMidiNote")
    {
        int note = obj->getProperty("note");
        if (note >= 0 && note <= 127)
        {
            processorRef.setFixedMidiNote(note);
            lastStatusMessage = "MIDI note set to " + juce::String(note);
            statusIsError = false;
        }
        else
        {
            lastStatusMessage = "Invalid MIDI note: must be 0-127";
            statusIsError = true;
        }
    }
    else if (action == "setMidiNoteLocked")
    {
        bool locked = obj->getProperty("locked");
        processorRef.setMidiNoteLocked(locked);
        lastStatusMessage = locked ? "MIDI note locked" : "MIDI note unlocked";
        statusIsError = false;
    }
    else if (action == "setPhaseInverted")
    {
        bool inverted = obj->getProperty("inverted");
        processorRef.setPhaseInverted(inverted);
        lastStatusMessage = inverted ? "Phase inverted" : "Phase normal";
        statusIsError = false;
    }
    else if (action == "setPitchShift")
    {
        float semitones = obj->getProperty("semitones");
        processorRef.setPitchShift(semitones);
    }
    else if (action == "setAutoPitchMode")
    {
        bool enabled = obj->getProperty("enabled");
        processorRef.setAutoPitchMode(enabled);
    }
    else if (action == "setTargetFrequency")
    {
        float hz = obj->getProperty("hz");
        processorRef.setTargetFrequency(hz);
    }
    else if (action == "setOutputVolume")
    {
        float db = obj->getProperty("db");
        processorRef.setOutputVolumeDb(db);
    }
    else if (action == "setResamplingMode")
    {
        juce::String mode = obj->getProperty("mode").toString();
        processorRef.setResamplingMode(resamplingModeFromString(mode));
    }
    else if (action == "setSlotVolume")
    {
        int slot = obj->getProperty("slot");
        double volume = obj->getProperty("volume");
        processorRef.setSlotVolume(slot, static_cast<float>(volume));
    }
    else if (action == "setSlotMuted")
    {
        int slot = obj->getProperty("slot");
        bool muted = obj->getProperty("muted");
        processorRef.setSlotMuted(slot, muted);
    }
    else if (action == "setSlotSoloed")
    {
        int slot = obj->getProperty("slot");
        bool soloed = obj->getProperty("soloed");
        processorRef.setSlotSoloed(slot, soloed);
    }
    else if (action == "auditionSlot")
    {
        int slot = obj->getProperty("slot");
        int velocity = obj->getProperty("velocity");
        processorRef.auditionSlot(slot, velocity);
    }
    else if (action == "auditionVelocityLayer")
    {
        int layerIndex = obj->getProperty("layer");
        processorRef.auditionVelocityLayer(layerIndex - 1);
    }
    else if (action == "auditionIndicatorCell")
    {
        int layerIndex = obj->getProperty("layer");
        int rrIndex = obj->getProperty("rr");
        processorRef.auditionIndicatorCell(layerIndex - 1, rrIndex - 1);
    }
}

void AudioPluginAudioProcessorEditor::sendStateUpdateToWebView()
{
    if (!webView)
        return;

    auto info = processorRef.getPresetInfo();

    juce::DynamicObject::Ptr state = new juce::DynamicObject();

    // Status message
    if (lastStatusMessage.isNotEmpty())
    {
        state->setProperty("statusMessage", lastStatusMessage);
        state->setProperty("statusIsError", statusIsError);
    }
    else if (info.isPresetLoaded)
    {
        state->setProperty("statusMessage", "Ready - Preset Loaded");
        state->setProperty("statusIsError", false);
    }
    else
    {
        state->setProperty("statusMessage", "No Preset - Click Load Button");
        state->setProperty("statusIsError", false);
        state->setProperty("statusIsWarning", true);
    }

    // Preset info
    juce::DynamicObject::Ptr presetInfoObj = new juce::DynamicObject();
    presetInfoObj->setProperty("isPresetLoaded", info.isPresetLoaded);
    presetInfoObj->setProperty("presetName", info.presetName);
    presetInfoObj->setProperty("instrumentType", info.instrumentType);
    presetInfoObj->setProperty("fixedMidiNote", info.fixedMidiNote);
    presetInfoObj->setProperty("slotCount", info.slotCount);
    presetInfoObj->setProperty("layerCount", info.layerCount);
    presetInfoObj->setProperty("useVelocityToVolume", info.useVelocityToVolume);
    presetInfoObj->setProperty("midiNoteLocked", processorRef.getMidiNoteLocked());
    presetInfoObj->setProperty("phaseInverted", processorRef.getPhaseInverted());
    presetInfoObj->setProperty("dawOctaveOffset", DrumEngine::MidiNoteUtils::getHostOctaveOffset());
    presetInfoObj->setProperty("pitchShift", processorRef.getPitchShift());
    presetInfoObj->setProperty("freq", info.freq);
    presetInfoObj->setProperty("freqConfidence", info.freqConfidence);
    presetInfoObj->setProperty("autoPitchMode", processorRef.getAutoPitchMode());
    presetInfoObj->setProperty("targetFrequencyHz", processorRef.getTargetFrequency());
    state->setProperty("resamplingMode", resamplingModeToString(processorRef.getResamplingMode()));
    state->setProperty("outputVolumeDb", processorRef.getOutputVolumeDb());

    // Version / build metadata
    state->setProperty("version", DRUMENGINE_VERSION);
    state->setProperty("buildNumber", DRUMENGINE_BUILD_NUMBER);
    state->setProperty("buildTimestamp", DRUMENGINE_BUILD_TIMESTAMP);

    juce::Array<juce::var> slotNamesArray;
    for (const auto &name : info.slotNames)
        slotNamesArray.add(name);
    presetInfoObj->setProperty("slotNames", slotNamesArray);

    // Build sample map for preset quality indicator
    // sampleMap structure: { "velocity-1": [1, 2, 3], "velocity-2": [1, 2], ... }
    // Each velocity layer gets an array of RR indices that have samples
    if (info.isPresetLoaded)
    {
        juce::DynamicObject::Ptr sampleMapObj = new juce::DynamicObject();

        // Get the active preset from the engine
        const auto *activePresetPtr = processorRef.getEngine().getActivePreset();
        if (activePresetPtr != nullptr)
        {
            const auto &layers = activePresetPtr->getLayers();

            // Iterate through velocity layers (max 10)
            for (size_t velocityIndex = 0; velocityIndex < layers.size() && velocityIndex < 10; ++velocityIndex)
            {
                const auto &layer = layers[velocityIndex];
                juce::Array<juce::var> rrIndicesArray;

                // Check each RR sample (max 5) for the first slot that has samples
                // Find first active slot
                int firstActiveSlot = -1;
                for (int slot = 0; slot < info.slotCount; ++slot)
                {
                    if (info.activeSlots[slot])
                    {
                        firstActiveSlot = slot;
                        break;
                    }
                }

                if (firstActiveSlot >= 0)
                {
                    // Check each RR index
                    for (size_t rrIndex = 0; rrIndex < layer.samples.size() && rrIndex < 5; ++rrIndex)
                    {
                        if (rrIndex < layer.samples.size() &&
                            firstActiveSlot < layer.samples[rrIndex].size() &&
                            layer.samples[rrIndex][firstActiveSlot] != nullptr)
                        {
                            rrIndicesArray.add(static_cast<int>(rrIndex) + 1); // 1-indexed for CSS classes
                        }
                    }
                }

                // Add to sample map if there are any samples for this velocity layer
                if (rrIndicesArray.size() > 0)
                {
                    juce::String velocityKey = "velocity-" + juce::String(static_cast<int>(velocityIndex) + 1);
                    sampleMapObj->setProperty(velocityKey, rrIndicesArray);
                }
            }
        }

        presetInfoObj->setProperty("sampleMap", juce::var(sampleMapObj.get()));
    }

    state->setProperty("presetInfo", juce::var(presetInfoObj.get()));

    // Slot states
    juce::Array<juce::var> slotsArray;
    for (int i = 0; i < 8; ++i)
    {
        bool isActive = info.isPresetLoaded && i < info.slotCount && info.activeSlots[static_cast<size_t>(i)];
        auto slotState = processorRef.getSlotState(i);

        juce::DynamicObject::Ptr slotObj = new juce::DynamicObject();
        slotObj->setProperty("isActive", isActive);
        slotObj->setProperty("name", i < static_cast<int>(info.slotNames.size()) ? info.slotNames[static_cast<size_t>(i)] : juce::String(i + 1));
        slotObj->setProperty("volume", slotState.volume);
        slotObj->setProperty("muted", slotState.muted);
        slotObj->setProperty("soloed", slotState.soloed);

        slotsArray.add(juce::var(slotObj.get()));
    }
    state->setProperty("slots", slotsArray);

    // Output mode
    auto outputMode = processorRef.getOutputMode();
    state->setProperty("outputMode", outputMode == AudioPluginAudioProcessor::OutputMode::MultiOut ? "multiout" : "stereo");

    // Current preset index
    state->setProperty("currentPresetIndex", currentPresetIndex);

    // Preset scan state
    state->setProperty("isScanningPresets", isScanningPresets);

    // Preset browser UI state
    state->setProperty("isPresetBrowserOpen", processorRef.getPresetBrowserOpen());
    {
        auto tags = processorRef.getPresetBrowserSelectedTags();
        juce::Array<juce::var> tagsArray;
        for (const auto &tag : tags)
            tagsArray.add(tag);
        state->setProperty("presetBrowserTags", tagsArray);
    }
    state->setProperty("presetBrowserSearchTerm", processorRef.getPresetBrowserSearchTerm());
    state->setProperty("presetBrowserViewMode", processorRef.getPresetBrowserViewMode());

    // Convert to JSON and send to WebView
    juce::String jsonState = juce::JSON::toString(juce::var(state.get()));

    // Only send if state has changed to avoid overwriting user input
    if (jsonState != lastSentState)
    {
        lastSentState = jsonState;
        if (webView)
            webView->evaluateJavascript("window.updateStateFromCpp(" + jsonState + ");");
    }
}

void AudioPluginAudioProcessorEditor::sendPresetListToWebView()
{
    if (!webView)
        return;

    juce::Array<juce::var> presetsArray;
    for (const auto &preset : presetList)
    {
        juce::DynamicObject::Ptr presetObj = new juce::DynamicObject();
        presetObj->setProperty("displayName", preset.displayName);
        presetObj->setProperty("category", preset.category);
        presetObj->setProperty("instrumentType", preset.instrumentType);
        presetObj->setProperty("isFavorite", preset.tags.contains("favorite", true));
        if (!preset.tags.isEmpty())
        {
            juce::Array<juce::var> tagsArray;
            for (const auto &tag : preset.tags)
                tagsArray.add(tag);
            presetObj->setProperty("tags", juce::var(tagsArray));
        }
        presetsArray.add(juce::var(presetObj.get()));
    }

    juce::String jsonPresets = juce::JSON::toString(presetsArray);
    webView->evaluateJavascript("window.updatePresetListFromCpp(" + jsonPresets + ");");
}

//==============================================================================
juce::File AudioPluginAudioProcessorEditor::getPresetRootFolder() const
{
    return juce::File::getSpecialLocation(juce::File::userDocumentsDirectory)
        .getChildFile("DrumEngine01");
}

juce::File AudioPluginAudioProcessorEditor::getPresetCacheFile() const
{
    return juce::File::getSpecialLocation(juce::File::userApplicationDataDirectory)
        .getChildFile("DrumEngine01")
        .getChildFile("preset-index.json");
}

juce::File AudioPluginAudioProcessorEditor::getPresetMetadataFile() const
{
    return getPresetRootFolder().getChildFile("DrumEngine01.metadata.json");
}

juce::String AudioPluginAudioProcessorEditor::getPresetIdForFile(const juce::File &file) const
{
    return file.getRelativePathFrom(getPresetRootFolder()).replace("\\", "/");
}

void AudioPluginAudioProcessorEditor::loadPresetMetadata()
{
    favoritePresetIds.clear();

    auto metadataFile = getPresetMetadataFile();
    if (!metadataFile.existsAsFile())
        return;

    const auto jsonText = metadataFile.loadFileAsString();
    if (jsonText.isEmpty())
        return;

    juce::var json;
    const auto result = juce::JSON::parse(jsonText, json);
    if (!result.wasOk() || !json.isObject())
        return;

    auto *rootObj = json.getDynamicObject();
    if (!rootObj)
        return;

    const int schemaVersion = static_cast<int>(rootObj->getProperty("schemaVersion"));
    if (schemaVersion != presetMetadataSchemaVersion)
        return;

    const auto favoritesVar = rootObj->getProperty("favorites");
    if (!favoritesVar.isArray())
        return;

    if (const auto *favoritesArray = favoritesVar.getArray())
    {
        for (const auto &favVar : *favoritesArray)
        {
            const auto fav = favVar.toString().trim();
            if (fav.isNotEmpty())
                favoritePresetIds.addIfNotAlreadyThere(fav);
        }
    }
}

void AudioPluginAudioProcessorEditor::savePresetMetadata() const
{
    auto metadataFile = getPresetMetadataFile();
    auto metadataDir = metadataFile.getParentDirectory();
    if (!metadataDir.exists())
        metadataDir.createDirectory();

    juce::DynamicObject::Ptr rootObj = new juce::DynamicObject();
    rootObj->setProperty("schemaVersion", presetMetadataSchemaVersion);
    rootObj->setProperty("updatedAt", juce::Time::getCurrentTime().toISO8601(true));

    juce::Array<juce::var> favoritesArray;
    for (const auto &fav : favoritePresetIds)
        favoritesArray.add(fav);

    rootObj->setProperty("favorites", juce::var(favoritesArray));

    const auto jsonText = juce::JSON::toString(juce::var(rootObj.get()), true);
    metadataFile.replaceWithText(jsonText);
}

void AudioPluginAudioProcessorEditor::applyFavoritesToPresetList()
{
    const juce::String favoriteTag = "favorite";
    juce::StringArray normalizedFavorites;

    auto areStringArraysEquivalent = [](const juce::StringArray &a, const juce::StringArray &b)
    {
        if (a.size() != b.size())
            return false;
        for (const auto &item : a)
        {
            if (!b.contains(item))
                return false;
        }
        return true;
    };

    for (auto &preset : presetList)
    {
        const auto presetId = getPresetIdForFile(preset.file);
        const bool isFavorite = favoritePresetIds.contains(presetId);

        preset.tags.removeString(favoriteTag, true);
        if (isFavorite)
        {
            preset.tags.addIfNotAlreadyThere(favoriteTag);
            normalizedFavorites.addIfNotAlreadyThere(presetId);
        }
    }

    if (!areStringArraysEquivalent(favoritePresetIds, normalizedFavorites))
    {
        favoritePresetIds = normalizedFavorites;
        savePresetMetadata();
    }
}

void AudioPluginAudioProcessorEditor::startPresetScanAsync()
{
    if (isScanningPresets)
        return;

    isScanningPresets = true;
    sendStateUpdateToWebView();

    auto rootFolder = getPresetRootFolder();
    juce::Component::SafePointer<AudioPluginAudioProcessorEditor> safeThis(this);

    std::thread([safeThis, rootFolder]() mutable
                {
                    auto results = PresetCacheBuilder::buildPresetListFromRoot(rootFolder);
                    juce::MessageManager::callAsync([safeThis, results = std::move(results)]() mutable
                                                    {
                                                        if (!safeThis)
                                                            return;

                                                        safeThis->presetList = std::move(results);
                                                        safeThis->loadPresetMetadata();
                                                        safeThis->applyFavoritesToPresetList();
                                                        safeThis->currentPresetIndex = safeThis->resolvePresetIndexFromState();
                                                        safeThis->savePresetCache();
                                                        safeThis->isScanningPresets = false;
                                                        safeThis->sendPresetListToWebView();
                                                        safeThis->sendStateUpdateToWebView();
                                                    }); })
        .detach();
}

bool AudioPluginAudioProcessorEditor::loadPresetCache()
{
    presetList.clear();

    if (!getPresetRootFolder().exists())
        return false;

    const auto cacheFile = getPresetCacheFile();
    logToFile("Preset cache path: " + cacheFile.getFullPathName());
    if (!cacheFile.existsAsFile())
    {
        logToFile("Preset cache file missing");
        return false;
    }

    const auto jsonText = cacheFile.loadFileAsString();
    if (jsonText.isEmpty())
        return false;

    juce::var json;
    const auto result = juce::JSON::parse(jsonText, json);
    if (!result.wasOk() || !json.isObject())
        return false;

    auto *rootObj = json.getDynamicObject();
    if (!rootObj)
        return false;

    const int schemaVersion = static_cast<int>(rootObj->getProperty("schemaVersion"));
    if (schemaVersion != presetCacheSchemaVersion)
        return false;

    const auto presetRoot = getPresetRootFolder().getFullPathName();
    const auto cachedRoot = rootObj->getProperty("presetRoot").toString();
    if (cachedRoot != presetRoot)
        return false;

    const auto presetsVar = rootObj->getProperty("presets");
    if (!presetsVar.isArray())
        return false;

    const auto *presetsArray = presetsVar.getArray();
    if (!presetsArray)
        return false;

    for (const auto &item : *presetsArray)
    {
        if (!item.isObject())
            continue;

        auto *itemObj = item.getDynamicObject();
        if (!itemObj)
            continue;

        const auto displayName = itemObj->getProperty("displayName").toString();
        const auto category = itemObj->getProperty("category").toString();
        const auto instrumentType = itemObj->getProperty("instrumentType").toString();
        const auto filePath = itemObj->getProperty("file").toString();

        if (filePath.isEmpty())
            continue;

        juce::File presetFile(filePath);
        if (!presetFile.existsAsFile())
            continue;

        juce::StringArray tags;
        if (itemObj->hasProperty("tags"))
        {
            const auto tagsVar = itemObj->getProperty("tags");
            if (tagsVar.isArray())
            {
                if (const auto *tagsArray = tagsVar.getArray())
                {
                    for (const auto &tagVar : *tagsArray)
                        tags.addIfNotAlreadyThere(tagVar.toString());
                }
            }
        }

        presetList.push_back({displayName, category, instrumentType, presetFile, tags});
    }

    loadPresetMetadata();
    applyFavoritesToPresetList();

    currentPresetIndex = resolvePresetIndexFromState();
    return true;
}

void AudioPluginAudioProcessorEditor::savePresetCache() const
{
    auto cacheFile = getPresetCacheFile();
    auto cacheDir = cacheFile.getParentDirectory();
    if (!cacheDir.exists())
    {
        const auto created = cacheDir.createDirectory();
        logToFile("Created cache directory: " + cacheDir.getFullPathName() + " => " + juce::String(created ? "OK" : "FAILED"));
    }
    logToFile("Writing preset cache: " + cacheFile.getFullPathName());

    juce::DynamicObject::Ptr rootObj = new juce::DynamicObject();
    rootObj->setProperty("schemaVersion", presetCacheSchemaVersion);
    rootObj->setProperty("presetRoot", getPresetRootFolder().getFullPathName());
    rootObj->setProperty("generatedAt", juce::Time::getCurrentTime().toISO8601(true));

    juce::Array<juce::var> presetsArray;
    for (const auto &preset : presetList)
    {
        juce::DynamicObject::Ptr presetObj = new juce::DynamicObject();
        presetObj->setProperty("displayName", preset.displayName);
        presetObj->setProperty("category", preset.category);
        presetObj->setProperty("instrumentType", preset.instrumentType);
        presetObj->setProperty("file", preset.file.getFullPathName());

        if (!preset.tags.isEmpty())
        {
            juce::Array<juce::var> tagsArray;
            for (const auto &tag : preset.tags)
                tagsArray.add(tag);
            presetObj->setProperty("tags", juce::var(tagsArray));
        }

        presetsArray.add(juce::var(presetObj.get()));
    }

    rootObj->setProperty("presets", juce::var(presetsArray));

    juce::String jsonText = juce::JSON::toString(juce::var(rootObj.get()), true);
    const auto wrote = cacheFile.replaceWithText(jsonText);
    logToFile("Preset cache write: " + juce::String(wrote ? "OK" : "FAILED"));
}

//==============================================================================
void AudioPluginAudioProcessorEditor::scanPresetsFolder()
{
    isScanningPresets = true;
    sendStateUpdateToWebView();

    presetList = PresetCacheBuilder::buildPresetListFromRoot(getPresetRootFolder());
    loadPresetMetadata();
    applyFavoritesToPresetList();
    currentPresetIndex = resolvePresetIndexFromState();
    savePresetCache();

    isScanningPresets = false;
    sendStateUpdateToWebView();
}

void AudioPluginAudioProcessorEditor::loadPresetByIndex(int index)
{
    if (index < 0 || index >= static_cast<int>(presetList.size()))
        return;

    const auto &entry = presetList[static_cast<size_t>(index)];

    if (!entry.file.existsAsFile())
        return;

    auto result = processorRef.loadPresetFromFile(entry.file);

    if (result.wasOk())
    {
        lastStatusMessage = "✓ Loaded: " + entry.displayName;
        statusIsError = false;
        currentPresetIndex = index;
        processorRef.setLastSelectedPresetIndex(index);
    }
    else
    {
        lastStatusMessage = "✗ Failed: " + result.getErrorMessage();
        statusIsError = true;
    }

    sendStateUpdateToWebView();
}

int AudioPluginAudioProcessorEditor::resolvePresetIndexFromState() const
{
    int index = processorRef.getLastSelectedPresetIndex();
    if (index < 0 || index >= static_cast<int>(presetList.size()))
        return -1;
    return index;
}

void AudioPluginAudioProcessorEditor::loadNextPreset()
{
    if (presetList.empty())
        return;

    int nextIndex = currentPresetIndex + 1;
    if (nextIndex >= static_cast<int>(presetList.size()))
        nextIndex = 0; // Wrap around to first preset

    loadPresetByIndex(nextIndex);
}

void AudioPluginAudioProcessorEditor::loadPrevPreset()
{
    if (presetList.empty())
        return;

    int prevIndex = currentPresetIndex - 1;
    if (prevIndex < 0)
        prevIndex = static_cast<int>(presetList.size()) - 1; // Wrap around to last preset

    loadPresetByIndex(prevIndex);
}

void AudioPluginAudioProcessorEditor::browseForPreset()
{
    auto chooserFlags = juce::FileBrowserComponent::openMode | juce::FileBrowserComponent::canSelectFiles;

    fileChooser = std::make_unique<juce::FileChooser>("Select Preset JSON File",
                                                      juce::File::getSpecialLocation(juce::File::userHomeDirectory),
                                                      "*.json");

    fileChooser->launchAsync(chooserFlags, [this](const juce::FileChooser &chooser)
                             {
        auto file = chooser.getResult();
        
        if (file == juce::File{})
            return;
        
        // Attempt to load
        auto result = processorRef.loadPresetFromFile(file);
        
        if (result.wasOk())
        {
            lastStatusMessage = "✓ Preset loaded successfully!";
            statusIsError = false;
        }
        else
        {
            lastStatusMessage = "✗ Failed: " + result.getErrorMessage();
            statusIsError = true;
        }
        
        sendStateUpdateToWebView(); });
}
