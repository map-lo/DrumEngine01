#include "PluginProcessor.h"
#include "engine/DebugLog.h"
#include "PluginEditor.h"

//==============================================================================
AudioPluginAudioProcessor::AudioPluginAudioProcessor()
    : AudioProcessor(BusesProperties()
#if !JucePlugin_IsMidiEffect
#if !JucePlugin_IsSynth
                         .withInput("Input", juce::AudioChannelSet::stereo(), true)
#endif
                         .withOutput("Main (Mix)", juce::AudioChannelSet::stereo(), true)
                         .withOutput("Mic 1", juce::AudioChannelSet::stereo(), true)
                         .withOutput("Mic 2", juce::AudioChannelSet::stereo(), true)
                         .withOutput("Mic 3", juce::AudioChannelSet::stereo(), true)
                         .withOutput("Mic 4", juce::AudioChannelSet::stereo(), true)
                         .withOutput("Mic 5", juce::AudioChannelSet::stereo(), true)
                         .withOutput("Mic 6", juce::AudioChannelSet::stereo(), true)
                         .withOutput("Mic 7", juce::AudioChannelSet::stereo(), true)
                         .withOutput("Mic 8", juce::AudioChannelSet::stereo(), true)
#endif
      )
{
    // Set up hit notification callback
    engine.setHitCallback([this](int velocityLayer, int rrIndex)
                          { hitListeners.call([velocityLayer, rrIndex](HitListener &l)
                                              { l.onHit(velocityLayer, rrIndex); }); });
}

AudioPluginAudioProcessor::~AudioPluginAudioProcessor()
{
}

//==============================================================================
const juce::String AudioPluginAudioProcessor::getName() const
{
    return JucePlugin_Name;
}

bool AudioPluginAudioProcessor::acceptsMidi() const
{
#if JucePlugin_WantsMidiInput
    return true;
#else
    return false;
#endif
}

bool AudioPluginAudioProcessor::producesMidi() const
{
#if JucePlugin_ProducesMidiOutput
    return true;
#else
    return false;
#endif
}

bool AudioPluginAudioProcessor::isMidiEffect() const
{
#if JucePlugin_IsMidiEffect
    return true;
#else
    return false;
#endif
}

double AudioPluginAudioProcessor::getTailLengthSeconds() const
{
    return 0.0;
}

int AudioPluginAudioProcessor::getNumPrograms()
{
    return 1; // NB: some hosts don't cope very well if you tell them there are 0 programs,
              // so this should be at least 1, even if you're not really implementing programs.
}

int AudioPluginAudioProcessor::getCurrentProgram()
{
    return 0;
}

void AudioPluginAudioProcessor::setCurrentProgram(int index)
{
    juce::ignoreUnused(index);
}

const juce::String AudioPluginAudioProcessor::getProgramName(int index)
{
    juce::ignoreUnused(index);
    return {};
}

void AudioPluginAudioProcessor::changeProgramName(int index, const juce::String &newName)
{
    juce::ignoreUnused(index, newName);
}

//==============================================================================
void AudioPluginAudioProcessor::prepareToPlay(double sampleRate, int samplesPerBlock)
{
    // Initialize the drum engine
    engine.prepareToPlay(sampleRate, samplesPerBlock);
    engine.setResamplingMode(resamplingMode);
    updateLatency();

    // Only load default preset if no state was restored (i.e., new instance, not loading from session)
    if (!stateRestored)
    {
        // Load a test preset from user Documents directory
        juce::File presetFile = juce::File::getSpecialLocation(juce::File::userDocumentsDirectory)
                                    .getChildFile("DrumEngine01")
                                    .getChildFile("factory")
                                    .getChildFile("ThatSound DarrenKing")
                                    .getChildFile("Snare")
                                    .getChildFile("BITE.json");
        if (presetFile.existsAsFile())
        {
            loadPresetFromFile(presetFile);
        }
    }
}

void AudioPluginAudioProcessor::releaseResources()
{
    // When playback stops, you can use this as an opportunity to free up any
    // spare memory, etc.
    engine.reset();
}

bool AudioPluginAudioProcessor::isBusesLayoutSupported(const BusesLayout &layouts) const
{
#if JucePlugin_IsMidiEffect
    juce::ignoreUnused(layouts);
    return true;
#else
    // Main output must be stereo
    if (layouts.getMainOutputChannelSet() != juce::AudioChannelSet::stereo())
        return false;

    // All additional outputs (if enabled) must be stereo
    for (int i = 1; i < layouts.outputBuses.size(); ++i)
    {
        if (!layouts.getChannelSet(false, i).isDisabled() &&
            layouts.getChannelSet(false, i) != juce::AudioChannelSet::stereo())
            return false;
    }

#if !JucePlugin_IsSynth
    // Input (if present) should match main output
    if (layouts.getMainOutputChannelSet() != layouts.getMainInputChannelSet())
        return false;
#endif

    return true;
#endif
}

void AudioPluginAudioProcessor::processBlock(juce::AudioBuffer<float> &buffer,
                                             juce::MidiBuffer &midiMessages)
{
    juce::ScopedNoDenormals noDenormals;

    auto totalNumOutputChannels = getTotalNumOutputChannels();
    if (totalNumOutputChannels < 2)
        return;

    // Clear the buffer first
    buffer.clear();

    bool multiOutEnabled = (outputMode == OutputMode::MultiOut);

    // The buffer parameter contains all bus channels laid out sequentially
    // Bus 0 (main): channels 0-1
    // Bus 1 (Mic 1): channels 2-3
    // Bus 2 (Mic 2): channels 4-5, etc.

    // So we can just process directly into the buffer!
    engine.processBlock(buffer, midiMessages, multiOutEnabled);

    // Apply output volume to main bus (channels 1-2 only)
    const float outputGain = juce::Decibels::decibelsToGain(outputVolumeDb);
    auto numSamples = buffer.getNumSamples();
    buffer.applyGain(0, 0, numSamples, outputGain);
    if (buffer.getNumChannels() > 1)
        buffer.applyGain(1, 0, numSamples, outputGain);
}

//==============================================================================
bool AudioPluginAudioProcessor::hasEditor() const
{
    return true; // (change this to false if you choose to not supply an editor)
}

juce::AudioProcessorEditor *AudioPluginAudioProcessor::createEditor()
{
    return new AudioPluginAudioProcessorEditor(*this);
}

//==============================================================================
void AudioPluginAudioProcessor::getStateInformation(juce::MemoryBlock &destData)
{
    // Create XML to store state
    juce::XmlElement xml("DrumEngine01State");

    // Save preset JSON data and root folder
    {
        juce::ScopedLock lock(presetInfoLock);
        if (!currentPresetJsonData.isEmpty())
        {
            // Use child element with CDATA for large JSON content to avoid XML attribute size limits
            auto *presetElement = xml.createNewChildElement("PresetData");
            presetElement->setAttribute("name", currentPresetInfo.presetName);
            presetElement->setAttribute("rootFolder", currentPresetRootFolder);
            presetElement->addTextElement(currentPresetJsonData);
        }
    }

    // Save output mode
    xml.setAttribute("outputMode", static_cast<int>(outputMode));

    // Save output volume (dB)
    xml.setAttribute("outputVolumeDb", outputVolumeDb);

    // Save resampling mode
    xml.setAttribute("resamplingMode", static_cast<int>(resamplingMode));

    // Save velocity to volume setting
    xml.setAttribute("useVelocityToVolume", getUseVelocityToVolume());

    // Save MIDI note lock state and custom note
    xml.setAttribute("midiNoteLocked", midiNoteLocked);
    if (customMidiNote >= 0)
    {
        xml.setAttribute("customMidiNote", customMidiNote);
    }

    // Save pitch shift
    xml.setAttribute("pitchShift", pitchShift);

    // Save UI state (preset browser)
    {
        juce::ScopedLock lock(uiStateLock);
        auto *uiElement = xml.createNewChildElement("PresetBrowserState");
        uiElement->setAttribute("open", presetBrowserOpen);
        uiElement->setAttribute("selectedPresetIndex", lastSelectedPresetIndex);
        uiElement->setAttribute("searchTerm", presetBrowserSearchTerm);

        auto *tagsElement = uiElement->createNewChildElement("Tags");
        for (const auto &tag : presetBrowserSelectedTags)
        {
            auto *tagElement = tagsElement->createNewChildElement("Tag");
            tagElement->setAttribute("value", tag);
        }
    }

    // Save slot states
    auto *slotsXml = xml.createNewChildElement("SlotStates");
    for (int i = 0; i < 8; ++i)
    {
        auto state = getSlotState(i);
        auto *slotXml = slotsXml->createNewChildElement("Slot");
        slotXml->setAttribute("index", i);
        slotXml->setAttribute("volume", state.volume);
        slotXml->setAttribute("muted", state.muted);
        slotXml->setAttribute("soloed", state.soloed);
    }

    // Convert to binary
    copyXmlToBinary(xml, destData);
}

void AudioPluginAudioProcessor::setStateInformation(const void *data, int sizeInBytes)
{
    // Parse XML from binary
    std::unique_ptr<juce::XmlElement> xml(getXmlFromBinary(data, sizeInBytes));

    if (xml == nullptr || !xml->hasTagName("DrumEngine01State"))
        return;

    // Debug logging
    DrumEngine::debugLog("setStateInformation called");
    if (xml->hasAttribute("presetName"))
        DrumEngine::debugLog("Preset name: " + xml->getStringAttribute("presetName"));

    // Restore output mode
    if (xml->hasAttribute("outputMode"))
    {
        int modeValue = xml->getIntAttribute("outputMode", 0);
        outputMode = static_cast<OutputMode>(modeValue);
    }

    // Restore output volume (dB)
    if (xml->hasAttribute("outputVolumeDb"))
    {
        float db = static_cast<float>(xml->getDoubleAttribute("outputVolumeDb", -6.0));
        setOutputVolumeDb(db);
    }

    // Restore resampling mode
    if (xml->hasAttribute("resamplingMode"))
    {
        int modeValue = xml->getIntAttribute("resamplingMode", static_cast<int>(DrumEngine::ResamplingMode::CatmullRom));
        DrumEngine::ResamplingMode modeToSet = DrumEngine::ResamplingMode::CatmullRom;

        switch (modeValue)
        {
        case 0:
            modeToSet = DrumEngine::ResamplingMode::Off;
            break;
        case 1:
            modeToSet = DrumEngine::ResamplingMode::CatmullRom;
            break;
        case 2:
            modeToSet = DrumEngine::ResamplingMode::Lanczos3;
            break;
        default:
            modeToSet = DrumEngine::ResamplingMode::CatmullRom;
            break;
        }

        setResamplingMode(modeToSet);
    }

    // Restore slot states first (before loading preset)
    if (auto *slotsXml = xml->getChildByName("SlotStates"))
    {
        for (auto *slotXml : slotsXml->getChildIterator())
        {
            if (slotXml->hasTagName("Slot"))
            {
                int index = slotXml->getIntAttribute("index", -1);
                if (index >= 0 && index < 8)
                {
                    float volume = static_cast<float>(slotXml->getDoubleAttribute("volume", 1.0));
                    bool muted = slotXml->getBoolAttribute("muted", false);
                    bool soloed = slotXml->getBoolAttribute("soloed", false);

                    setSlotVolume(index, volume);
                    setSlotMuted(index, muted);
                    setSlotSoloed(index, soloed);
                }
            }
        }
    }

    // Restore preset from JSON data stored in child element
    if (auto *presetElement = xml->getChildByName("PresetData"))
    {
        DrumEngine::debugLog("Found PresetData element");
        juce::String presetJson = presetElement->getAllSubText();
        juce::String rootFolder = presetElement->getStringAttribute("rootFolder");
        juce::String presetName = presetElement->getStringAttribute("name", "Unknown");

        DrumEngine::debugLog("JSON length: " + juce::String(presetJson.length()));
        DrumEngine::debugLog("Root folder: " + rootFolder);
        DrumEngine::debugLog("First 500 chars of JSON:\n" + presetJson.substring(0, 500));

        if (!presetJson.isEmpty())
        {
            DrumEngine::debugLog("Calling loadPresetFromJsonInternal...");
            auto result = loadPresetFromJsonInternal(presetJson, presetName, rootFolder);

            DrumEngine::debugLog("Result: " + juce::String(result.wasOk() ? "OK" : result.getErrorMessage()));

            if (result.wasOk())
            {
                // Restore MIDI note lock state and custom note
                midiNoteLocked = xml->getBoolAttribute("midiNoteLocked", false);
                if (xml->hasAttribute("customMidiNote"))
                {
                    customMidiNote = xml->getIntAttribute("customMidiNote", -1);
                    // If we have a locked custom note, apply it now (overriding preset default)
                    if (midiNoteLocked && customMidiNote >= 0 && customMidiNote <= 127)
                    {
                        setFixedMidiNote(customMidiNote);
                        DrumEngine::debugLog("Restored locked custom MIDI note: " + juce::String(customMidiNote));
                    }
                }

                // Restore pitch shift
                if (xml->hasAttribute("pitchShift"))
                {
                    float pitch = static_cast<float>(xml->getDoubleAttribute("pitchShift", 0.0));
                    setPitchShift(pitch);
                    DrumEngine::debugLog("Restored pitch shift: " + juce::String(pitch));
                }

                // Debug: log active slots
                juce::String activeSlotsLine("Active slots: ");
                for (int i = 0; i < 8; ++i)
                    activeSlotsLine += (currentPresetInfo.activeSlots[i] ? "1" : "0");
                DrumEngine::debugLog(activeSlotsLine);

                // Mark that state was successfully restored
                stateRestored = true;

                // Debug logging - reuse the same debug stream
                DrumEngine::debugLog("Successfully restored preset: " + presetName);
            }
            else
            {
                DrumEngine::debugLog("Failed to restore preset");
            }
        }
        else
        {
            DrumEngine::debugLog("presetJson is empty");
        }
    }
    else
    {
        DrumEngine::debugLog("No PresetData element found");
    }

    // Restore velocity to volume setting (after preset is loaded)
    if (xml->hasAttribute("useVelocityToVolume"))
    {
        bool velToVol = xml->getBoolAttribute("useVelocityToVolume", false);
        setUseVelocityToVolume(velToVol);
    }

    // Restore UI state (preset browser)
    if (auto *uiElement = xml->getChildByName("PresetBrowserState"))
    {
        juce::ScopedLock lock(uiStateLock);
        presetBrowserOpen = uiElement->getBoolAttribute("open", false);
        lastSelectedPresetIndex = uiElement->getIntAttribute("selectedPresetIndex", -1);
        presetBrowserSearchTerm = uiElement->getStringAttribute("searchTerm");

        presetBrowserSelectedTags.clear();
        if (auto *tagsElement = uiElement->getChildByName("Tags"))
        {
            for (auto *tagElement : tagsElement->getChildIterator())
            {
                if (tagElement->hasTagName("Tag"))
                {
                    const auto value = tagElement->getStringAttribute("value");
                    if (value.isNotEmpty())
                        presetBrowserSelectedTags.addIfNotAlreadyThere(value);
                }
            }
        }
    }
}

//==============================================================================
juce::Result AudioPluginAudioProcessor::loadPresetFromJsonInternal(const juce::String &jsonText,
                                                                   const juce::String &presetName,
                                                                   const juce::String &defaultRootFolder)
{
    if (jsonText.isEmpty())
        return juce::Result::fail("Preset JSON is empty");

    // Extract root folder from JSON to pass to engine
    juce::var json;
    auto parseResult = juce::JSON::parse(jsonText, json);
    juce::String rootFolderFromJson;
    if (parseResult.wasOk() && json.isObject())
    {
        auto *obj = json.getDynamicObject();
        if (obj)
            rootFolderFromJson = obj->getProperty("rootFolder").toString();
    }

    if (rootFolderFromJson.isEmpty() && !defaultRootFolder.isEmpty())
        rootFolderFromJson = defaultRootFolder;

    // Load preset in engine
    auto result = engine.loadPresetFromJson(jsonText, rootFolderFromJson);

    if (result.wasOk())
    {
        juce::String cleanedPresetName = presetName;
        if (cleanedPresetName.endsWithIgnoreCase(".preset"))
            cleanedPresetName = cleanedPresetName.upToLastOccurrenceOf(".preset", false, true);

        // Update preset info for UI
        juce::ScopedLock lock(presetInfoLock);

        auto info = engine.getCurrentPresetInfo();
        currentPresetInfo.isPresetLoaded = info.isValid;
        currentPresetInfo.presetName = cleanedPresetName;
        currentPresetInfo.instrumentType = info.instrumentType;
        currentPresetInfo.fixedMidiNote = info.fixedMidiNote;
        currentPresetInfo.slotCount = info.slotCount;
        currentPresetInfo.layerCount = info.layerCount;
        currentPresetInfo.slotNames = info.slotNames;
        currentPresetInfo.activeSlots = info.activeSlots;
        currentPresetInfo.useVelocityToVolume = engine.getUseVelocityToVolume();

        // Store preset JSON data
        currentPresetJsonData = jsonText;
        currentPresetRootFolder = rootFolderFromJson;

        // Apply slot states to engine
        for (int i = 0; i < 8; ++i)
        {
            auto slotState = getSlotState(i);
            engine.setSlotGain(i, slotState.volume);
            engine.setSlotMuted(i, slotState.muted);
            engine.setSlotSoloed(i, slotState.soloed);
        }

        // If MIDI note is locked, reapply the custom note (don't let preset override it)
        if (midiNoteLocked && customMidiNote >= 0 && customMidiNote <= 127)
        {
            engine.setFixedMidiNote(customMidiNote);
            currentPresetInfo.fixedMidiNote = customMidiNote;
        }

        // Reset pitch shift when loading preset
        setPitchShift(0.0f);
    }

    return result;
}

juce::Result AudioPluginAudioProcessor::loadPresetFromFile(const juce::File &presetFile)
{
    // Read the JSON content
    juce::String jsonText = presetFile.loadFileAsString();
    if (jsonText.isEmpty())
        return juce::Result::fail("Preset file is empty or cannot be read");

    juce::String presetName = presetFile.getFileNameWithoutExtension();
    if (presetFile.getFileName().equalsIgnoreCase("preset.json"))
        presetName = presetFile.getParentDirectory().getFileName();

    return loadPresetFromJsonInternal(jsonText,
                                      presetName,
                                      presetFile.getParentDirectory().getFullPathName());
}

AudioPluginAudioProcessor::PresetInfo AudioPluginAudioProcessor::getPresetInfo() const
{
    juce::ScopedLock lock(presetInfoLock);
    return currentPresetInfo;
}

void AudioPluginAudioProcessor::setSlotVolume(int slotIndex, float volume)
{
    if (slotIndex >= 0 && slotIndex < 8)
    {
        {
            juce::ScopedLock lock(slotStateLock);
            slotStates[slotIndex].volume = volume;
        }
        engine.setSlotGain(slotIndex, volume);
    }
}

void AudioPluginAudioProcessor::setSlotMuted(int slotIndex, bool muted)
{
    if (slotIndex >= 0 && slotIndex < 8)
    {
        {
            juce::ScopedLock lock(slotStateLock);
            slotStates[slotIndex].muted = muted;
        }
        engine.setSlotMuted(slotIndex, muted);
    }
}

void AudioPluginAudioProcessor::setSlotSoloed(int slotIndex, bool soloed)
{
    if (slotIndex >= 0 && slotIndex < 8)
    {
        {
            juce::ScopedLock lock(slotStateLock);
            slotStates[slotIndex].soloed = soloed;
        }
        engine.setSlotSoloed(slotIndex, soloed);
    }
}

AudioPluginAudioProcessor::SlotState AudioPluginAudioProcessor::getSlotState(int slotIndex) const
{
    if (slotIndex >= 0 && slotIndex < 8)
    {
        juce::ScopedLock lock(slotStateLock);
        return slotStates[slotIndex];
    }
    return SlotState();
}

void AudioPluginAudioProcessor::auditionSlot(int slotIndex, int velocity)
{
    if (slotIndex < 0 || slotIndex >= 8)
        return;

    const int clampedVelocity = juce::jlimit(1, 127, velocity);
    engine.triggerPreview(clampedVelocity, slotIndex);
}

void AudioPluginAudioProcessor::auditionVelocityLayer(int layerIndex)
{
    engine.triggerPreviewLayer(layerIndex, -1);
}

void AudioPluginAudioProcessor::auditionIndicatorCell(int layerIndex, int rrIndex)
{
    auto *preset = engine.getActivePreset();
    if (!preset)
        return;

    const auto &layers = preset->getLayers();
    if (layerIndex < 0 || layerIndex >= static_cast<int>(layers.size()))
        return;

    const auto &layer = layers[layerIndex];
    const int velocity = (layer.lo + layer.hi) / 2;

    engine.triggerPreviewExact(layerIndex, rrIndex, velocity, -1);
}
void AudioPluginAudioProcessor::setOutputMode(OutputMode mode)
{
    if (outputMode == mode)
        return;

    outputMode = mode;

    // That's it! All buses are always enabled.
    // In Stereo mode, we just don't write to individual outputs (channels 2-17 stay silent).
    // In Multi-Out mode, voices write to both mix and individual outputs.
}

void AudioPluginAudioProcessor::setUseVelocityToVolume(bool enabled)
{
    engine.setUseVelocityToVolume(enabled);

    // Update preset info
    juce::ScopedLock lock(presetInfoLock);
    currentPresetInfo.useVelocityToVolume = enabled;
}

bool AudioPluginAudioProcessor::getUseVelocityToVolume() const
{
    return engine.getUseVelocityToVolume();
}

void AudioPluginAudioProcessor::setFixedMidiNote(int note)
{
    if (note >= 0 && note <= 127)
    {
        customMidiNote = note;
        engine.setFixedMidiNote(note);

        // Update preset info
        juce::ScopedLock lock(presetInfoLock);
        currentPresetInfo.fixedMidiNote = note;
    }
}

int AudioPluginAudioProcessor::getFixedMidiNote() const
{
    return engine.getFixedMidiNote();
}

void AudioPluginAudioProcessor::setMidiNoteLocked(bool locked)
{
    midiNoteLocked = locked;

    // If locking and we don't have a custom note yet, capture the current preset's note
    if (locked && customMidiNote < 0)
    {
        int currentNote = engine.getFixedMidiNote();
        if (currentNote >= 0 && currentNote <= 127)
        {
            customMidiNote = currentNote;
        }
    }
}

bool AudioPluginAudioProcessor::getMidiNoteLocked() const
{
    return midiNoteLocked;
}

void AudioPluginAudioProcessor::setPresetBrowserOpen(bool open)
{
    juce::ScopedLock lock(uiStateLock);
    presetBrowserOpen = open;
}

bool AudioPluginAudioProcessor::getPresetBrowserOpen() const
{
    juce::ScopedLock lock(uiStateLock);
    return presetBrowserOpen;
}

void AudioPluginAudioProcessor::setPresetBrowserSelectedTags(const juce::StringArray &tags)
{
    juce::ScopedLock lock(uiStateLock);
    presetBrowserSelectedTags = tags;
    presetBrowserSelectedTags.removeEmptyStrings();
    presetBrowserSelectedTags.removeDuplicates(true);
}

void AudioPluginAudioProcessor::setPresetBrowserSearchTerm(const juce::String &term)
{
    juce::ScopedLock lock(uiStateLock);
    presetBrowserSearchTerm = term;
}

juce::StringArray AudioPluginAudioProcessor::getPresetBrowserSelectedTags() const
{
    juce::ScopedLock lock(uiStateLock);
    return presetBrowserSelectedTags;
}

juce::String AudioPluginAudioProcessor::getPresetBrowserSearchTerm() const
{
    juce::ScopedLock lock(uiStateLock);
    return presetBrowserSearchTerm;
}

void AudioPluginAudioProcessor::setLastSelectedPresetIndex(int index)
{
    juce::ScopedLock lock(uiStateLock);
    lastSelectedPresetIndex = index;
}

int AudioPluginAudioProcessor::getLastSelectedPresetIndex() const
{
    juce::ScopedLock lock(uiStateLock);
    return lastSelectedPresetIndex;
}

void AudioPluginAudioProcessor::setPitchShift(float semitones)
{
    if (resamplingMode == DrumEngine::ResamplingMode::Off)
    {
        pitchShift = 0.0f;
        engine.setPitchShift(0.0f);
        return;
    }

    pitchShift = juce::jlimit(-6.0f, 6.0f, semitones);
    engine.setPitchShift(pitchShift);
}

void AudioPluginAudioProcessor::setOutputVolumeDb(float db)
{
    outputVolumeDb = juce::jlimit(-60.0f, 6.0f, db);
}

void AudioPluginAudioProcessor::setResamplingMode(DrumEngine::ResamplingMode mode)
{
    if (resamplingMode == mode)
        return;

    resamplingMode = mode;
    engine.setResamplingMode(mode);

    if (mode == DrumEngine::ResamplingMode::Off)
        setPitchShift(0.0f);

    updateLatency();
}

void AudioPluginAudioProcessor::updateLatency()
{
    setLatencySamples(engine.getLatencySamples());
}

//==============================================================================
// This creates new instances of the plugin..
juce::AudioProcessor *JUCE_CALLTYPE createPluginFilter()
{
    return new AudioPluginAudioProcessor();
}
