#include "PluginProcessor.h"
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
                                    .getChildFile("presets")
                                    .getChildFile("factory01")
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
    juce::File debugFile = juce::File::getSpecialLocation(juce::File::userHomeDirectory).getChildFile("DrumEngine01_Debug.txt");
    juce::FileOutputStream debugStream(debugFile, 1024);
    if (debugStream.openedOk())
    {
        debugStream << "[" << juce::Time::getCurrentTime().toString(true, true, true, true) << "] setStateInformation called\n";
        if (xml->hasAttribute("presetName"))
        {
            debugStream << "  Preset name: " << xml->getStringAttribute("presetName") << "\n";
        }
    }

    // Restore output mode
    if (xml->hasAttribute("outputMode"))
    {
        int modeValue = xml->getIntAttribute("outputMode", 0);
        outputMode = static_cast<OutputMode>(modeValue);
    }

    // Restore resampling mode (handle legacy values)
    if (xml->hasAttribute("resamplingMode"))
    {
        int modeValue = xml->getIntAttribute("resamplingMode", static_cast<int>(DrumEngine::ResamplingMode::Ultra));
        DrumEngine::ResamplingMode modeToSet = DrumEngine::ResamplingMode::Ultra;

        switch (modeValue)
        {
        case 0:
            modeToSet = DrumEngine::ResamplingMode::Off;
            break;
        case 1: // legacy LowLatency
        case 2: // legacy Normal
            modeToSet = DrumEngine::ResamplingMode::Normal;
            break;
        case 3: // legacy Ultra
        default:
            modeToSet = DrumEngine::ResamplingMode::Ultra;
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
        debugStream << "  Found PresetData element\n";
        juce::String presetJson = presetElement->getAllSubText();
        juce::String rootFolder = presetElement->getStringAttribute("rootFolder");
        juce::String presetName = presetElement->getStringAttribute("name", "Unknown");

        debugStream << "  JSON length: " << presetJson.length() << "\n";
        debugStream << "  Root folder: " << rootFolder << "\n";
        debugStream << "  First 500 chars of JSON:\n"
                    << presetJson.substring(0, 500) << "\n";

        if (!presetJson.isEmpty())
        {
            debugStream << "  Calling loadPresetFromJsonInternal...\n";
            auto result = loadPresetFromJsonInternal(presetJson, presetName, rootFolder);

            debugStream << "  Result: " << (result.wasOk() ? "OK" : result.getErrorMessage()) << "\n";

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
                        debugStream << "  Restored locked custom MIDI note: " << customMidiNote << "\n";
                    }
                }

                // Restore pitch shift
                if (xml->hasAttribute("pitchShift"))
                {
                    float pitch = static_cast<float>(xml->getDoubleAttribute("pitchShift", 0.0));
                    setPitchShift(pitch);
                    debugStream << "  Restored pitch shift: " << pitch << "\n";
                }

                // Debug: log active slots
                debugStream << "  Active slots: ";
                for (int i = 0; i < 8; ++i)
                    debugStream << (currentPresetInfo.activeSlots[i] ? "1" : "0");
                debugStream << "\n";

                // Mark that state was successfully restored
                stateRestored = true;

                // Debug logging - reuse the same debug stream
                debugStream << "  Successfully restored preset: " << presetName << "\n";
            }
            else
            {
                debugStream << "  Failed to restore preset\n";
            }
        }
        else
        {
            debugStream << "  presetJson is empty\n";
        }
    }
    else
    {
        debugStream << "  No PresetData element found\n";
    }

    // Restore velocity to volume setting (after preset is loaded)
    if (xml->hasAttribute("useVelocityToVolume"))
    {
        bool velToVol = xml->getBoolAttribute("useVelocityToVolume", false);
        setUseVelocityToVolume(velToVol);
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
        // Update preset info for UI
        juce::ScopedLock lock(presetInfoLock);

        auto info = engine.getCurrentPresetInfo();
        currentPresetInfo.isPresetLoaded = info.isValid;
        currentPresetInfo.presetName = presetName;
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

    return loadPresetFromJsonInternal(jsonText,
                                      presetFile.getFileNameWithoutExtension(),
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
