#include "PluginProcessor.h"
#include "PluginEditor.h"
#include "BinaryData.h"

// Debug logging helper
static void logToFile(const juce::String &message)
{
    juce::File logFile = juce::File::getSpecialLocation(juce::File::userHomeDirectory)
                             .getChildFile("DrumEngine01_debug.log");

    juce::String timestamp = juce::Time::getCurrentTime().toString(true, true, true, true);
    juce::String logLine = timestamp + " - " + message + "\n";

    logFile.appendText(logLine);
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

    // Scan presets folder
    scanPresetsFolder();

    // Register for hit notifications
    processorRef.addHitListener(this);

    // Start timer to update UI
    startTimer(100); // Update every 100ms

    setSize(660, 440);
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

    // Load files from disk for hot reloading
    juce::File uiDir = getUIDirectory();
    juce::File indexHtml = uiDir.getChildFile("index.html");

    logToFile("Looking for index.html at: " + indexHtml.getFullPathName());
    logToFile("File exists: " + juce::String(indexHtml.existsAsFile() ? "YES" : "NO"));

    if (!indexHtml.existsAsFile())
    {
        logToFile("ERROR: UI files not found!");
        jassertfalse; // UI files not found!
        return;
    }

    // Create WebBrowserComponent with native integration
    webView = std::make_unique<juce::WebBrowserComponent>(
        juce::WebBrowserComponent::Options{}
            .withBackend(juce::WebBrowserComponent::Options::Backend::defaultBackend)
            .withNativeIntegrationEnabled()
            .withUserScript(
                "console.log('JUCE WebView initialized - DEVELOPMENT MODE');"
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

    // Navigate directly to the HTML file on disk
    juce::String fileUrl = "file://" + indexHtml.getFullPathName();
    logToFile("Loading URL: " + fileUrl);
    webView->goToURL(fileUrl);

    logToFile("setupWebViewForDevelopment() completed");
}

void AudioPluginAudioProcessorEditor::setupWebViewForProduction()
{
    // Load HTML content from binary resources
    juce::String html(BinaryData::index_html, static_cast<size_t>(BinaryData::index_htmlSize));
    juce::String css(BinaryData::styles_css, static_cast<size_t>(BinaryData::styles_cssSize));
    juce::String js(BinaryData::app_js, static_cast<size_t>(BinaryData::app_jsSize));

    // Modify JavaScript to use JUCE event listener instead of postMessage
    js = js.replace(
        "window.juce.postMessage(JSON.stringify(message));",
        "window.__JUCE__.backend.emitEvent('fromWebView', message);");

    // Create complete HTML with inline CSS and JS
    juce::String fullHtml = html;
    fullHtml = fullHtml.replace("</head>",
                                "<style>" + css + "</style></head>");
    fullHtml = fullHtml.replace("</body>",
                                "<script>" + js + "</script></body>");

    // Remove external references
    fullHtml = fullHtml.replace("<link rel=\"stylesheet\" href=\"styles.css\">", "");
    fullHtml = fullHtml.replace("<script src=\"app.js\"></script>", "");

    // Store the HTML content for the resource provider
    htmlContent = fullHtml;

    // Create WebBrowserComponent with native integration and resource provider
    webView = std::make_unique<juce::WebBrowserComponent>(
        juce::WebBrowserComponent::Options{}
            .withBackend(juce::WebBrowserComponent::Options::Backend::defaultBackend)
            .withNativeIntegrationEnabled()
            .withUserScript(
                "console.log('JUCE WebView initialized - PRODUCTION MODE');"
                "window.juce = window.__JUCE__.backend;")
            .withEventListener("fromWebView", [this](const juce::var &message)
                               { handleMessageFromWebView(juce::JSON::toString(message)); })
            .withEventListener("pageReady", [this](const juce::var &)
                               { 
                                   pageLoaded = true;
                                   sendPresetListToWebView();
                                   sendStateUpdateToWebView(); })
            .withResourceProvider([this](const juce::String &url) -> std::optional<juce::WebBrowserComponent::Resource>
                                  {
                if (url == "/" || url == "/index.html")
                {
                    std::vector<std::byte> data;
                    data.resize(this->htmlContent.length());
                    std::memcpy(data.data(), this->htmlContent.toRawUTF8(), this->htmlContent.length());
                    return juce::WebBrowserComponent::Resource { data, "text/html" };
                }
                return std::nullopt; }));

    addAndMakeVisible(webView.get());

    // Navigate to the root which will trigger the resource provider
    webView->goToURL(juce::WebBrowserComponent::getResourceProviderRoot());
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
        presetsArray.add(juce::var(presetObj.get()));
    }

    juce::String jsonPresets = juce::JSON::toString(presetsArray);
    webView->evaluateJavascript("window.updatePresetListFromCpp(" + jsonPresets + ");");
}

//==============================================================================
void AudioPluginAudioProcessorEditor::scanPresetsFolder()
{
    presetList.clear();

    // For development, use absolute path
    juce::File kitsFolder("/Users/marian/Development/JUCE-Plugins/DrumEngine01/kits");

    if (!kitsFolder.exists() || !kitsFolder.isDirectory())
        return;

    int itemId = 2;

    // Scan all JSON files recursively and flatten
    std::function<void(const juce::File &, const juce::String &)> scanFolder =
        [&](const juce::File &folder, const juce::String &categoryPath)
    {
        auto allFiles = folder.findChildFiles(juce::File::findFilesAndDirectories, false, "*");

        juce::Array<juce::File> subFolders;
        juce::Array<juce::File> jsonFiles;

        for (const auto &file : allFiles)
        {
            if (file.isDirectory() && !file.getFileName().startsWith("."))
                subFolders.add(file);
            else if (file.hasFileExtension(".json"))
                jsonFiles.add(file);
        }

        subFolders.sort();
        jsonFiles.sort();

        // Process JSON files in this folder
        for (const auto &jsonFile : jsonFiles)
        {
            juce::String displayName = jsonFile.getFileNameWithoutExtension();
            juce::String category = categoryPath.isEmpty() ? folder.getFileName() : categoryPath;

            // Add category prefix for better organization
            juce::String fullDisplayName = category + " / " + displayName;

            presetList.push_back({fullDisplayName, category, jsonFile});
            itemId++;
        }

        // Recurse into subfolders
        for (const auto &subFolder : subFolders)
        {
            juce::String newCategoryPath = categoryPath.isEmpty() ? folder.getFileName() + "/" + subFolder.getFileName() : categoryPath + "/" + subFolder.getFileName();
            scanFolder(subFolder, newCategoryPath);
        }
    };

    scanFolder(kitsFolder, "");
    currentPresetIndex = -1;
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
    }
    else
    {
        lastStatusMessage = "✗ Failed: " + result.getErrorMessage();
        statusIsError = true;
    }

    sendStateUpdateToWebView();
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
