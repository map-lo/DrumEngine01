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

    // That's it! All buses are always enabled.
    // In Stereo mode, we just don't write to individual outputs (channels 2-17 stay silent).
    // In Multi-Out mode, voices write to both mix and individual outputs.
}

//==============================================================================
// This creates new instances of the plugin..
juce::AudioProcessor *JUCE_CALLTYPE createPluginFilter()
{
    return new AudioPluginAudioProcessor();
}
