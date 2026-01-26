#include "PluginProcessor.h"
#include "PluginEditor.h"

//==============================================================================
AudioPluginAudioProcessor::AudioPluginAudioProcessor()
    : AudioProcessor(BusesProperties()
#if !JucePlugin_IsMidiEffect
#if !JucePlugin_IsSynth
                         .withInput("Input", juce::AudioChannelSet::stereo(), true)
#endif
                         .withOutput("Main", juce::AudioChannelSet::stereo(), true)
                         .withOutput("Slot 2", juce::AudioChannelSet::stereo(), false)
                         .withOutput("Slot 3", juce::AudioChannelSet::stereo(), false)
                         .withOutput("Slot 4", juce::AudioChannelSet::stereo(), false)
                         .withOutput("Slot 5", juce::AudioChannelSet::stereo(), false)
                         .withOutput("Slot 6", juce::AudioChannelSet::stereo(), false)
                         .withOutput("Slot 7", juce::AudioChannelSet::stereo(), false)
                         .withOutput("Slot 8", juce::AudioChannelSet::stereo(), false)
#endif
      )
{
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

    // Load a test preset (you can change this path or make it configurable)
    // For now, we'll try to load BITE.json if it exists
    juce::File presetFile = juce::File("/Users/marian/Development/JUCE-Plugins/DrumEngine01/kits/ThatSound DarrenKing/Snare/BITE.json");
    if (presetFile.existsAsFile())
    {
        loadPresetFromFile(presetFile);
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

    // Clear all output channels
    buffer.clear();

    if (outputMode == OutputMode::Stereo)
    {
        // Stereo mode: render all slots to main stereo output (channels 0-1)
        engine.processBlock(buffer, midiMessages, 0, -1); // -1 = all slots mixed
    }
    else // MultiOut
    {
        // Multi-out mode: render each slot to its own stereo pair
        int numOutputBuses = getBusCount(false);
        
        for (int slotIdx = 0; slotIdx < 8; ++slotIdx)
        {
            // Check if this output bus is enabled
            if (slotIdx < numOutputBuses && !getBus(false, slotIdx)->isEnabled())
                continue;

            // Calculate output channels for this slot
            int outputChannel = slotIdx * 2;
            
            // Make sure we have enough channels
            if (outputChannel + 1 >= totalNumOutputChannels)
                break;

            // Render this slot to its dedicated output pair
            engine.processBlock(buffer, midiMessages, outputChannel, slotIdx);
        }
    }
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
    // You should use this method to store your parameters in the memory block.
    // You could do that either as raw data, or use the XML or ValueTree classes
    // as intermediaries to make it easy to save and load complex data.
    juce::ignoreUnused(destData);
}

void AudioPluginAudioProcessor::setStateInformation(const void *data, int sizeInBytes)
{
    // You should use this method to restore your parameters from this memory block,
    // whose contents will have been created by the getStateInformation() call.
    juce::ignoreUnused(data, sizeInBytes);
}

//==============================================================================
juce::Result AudioPluginAudioProcessor::loadPresetFromFile(const juce::File &presetFile)
{
    auto result = engine.loadPresetAsync(presetFile);

    if (result.wasOk())
    {
        // Update preset info for UI
        juce::ScopedLock lock(presetInfoLock);

        auto info = engine.getCurrentPresetInfo();
        currentPresetInfo.isPresetLoaded = info.isValid;
        currentPresetInfo.presetName = presetFile.getFileNameWithoutExtension();
        currentPresetInfo.instrumentType = info.instrumentType;
        currentPresetInfo.fixedMidiNote = info.fixedMidiNote;
        currentPresetInfo.slotCount = info.slotCount;
        currentPresetInfo.layerCount = info.layerCount;
        currentPresetInfo.slotNames = info.slotNames;
        currentPresetInfo.activeSlots = info.activeSlots;

        // Update engine with current slot states
        for (int i = 0; i < 8; ++i)
        {
            auto slotState = getSlotState(i);
            engine.setSlotGain(i, slotState.volume);
            engine.setSlotMuted(i, slotState.muted);
            engine.setSlotSoloed(i, slotState.soloed);
        }
    }

    return result;
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

    // Enable/disable output buses based on mode
    if (mode == OutputMode::Stereo)
    {
        // Disable all buses except main
        for (int i = 1; i < getBusCount(false); ++i)
        {
            if (auto *bus = getBus(false, i))
                bus->enable(false);
        }
    }
    else // MultiOut
    {
        // Enable all 8 output buses
        for (int i = 1; i < getBusCount(false) && i < 8; ++i)
        {
            if (auto *bus = getBus(false, i))
                bus->enable(true);
        }
    }

    // Notify host of bus configuration change
    updateHostDisplay(ChangeDetails().withNonParameterStateChanged(true));
}
//==============================================================================
// This creates new instances of the plugin..
juce::AudioProcessor *JUCE_CALLTYPE createPluginFilter()
{
    return new AudioPluginAudioProcessor();
}
