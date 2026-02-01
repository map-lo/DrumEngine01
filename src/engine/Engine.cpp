#include "Engine.h"

namespace DrumEngine
{

    Engine::Engine()
    {
        rrCounters.fill(0);
    }

    Engine::~Engine()
    {
        delete activePreset.load();
    }

    void Engine::prepareToPlay(double sampleRate, int samplesPerBlock)
    {
        currentSampleRate = sampleRate;

        // Initialize latency contribution for resampling mode
        setLatencyContribution("resampling", getResamplingLatencySamples());

        // Allocate voice pool (3 hitgroups * 8 slots + headroom)
        voicePool.allocate(32);

        reset();
    }

    void Engine::reset()
    {
        voicePool.reset();
        activeHitGroups.clear();
        rrCounters.fill(0);
    }

    juce::Result Engine::loadPresetAsync(const juce::File &presetFile)
    {
        // This should be called from a background thread in production
        // For now, we'll load synchronously

        DBG("Loading preset: " + presetFile.getFullPathName());

        PresetSchema schema;
        auto parseResult = PresetSchema::parseFromFile(presetFile, schema);

        if (parseResult.failed())
        {
            DBG("Failed to parse preset: " + parseResult.getErrorMessage());
            return parseResult;
        }

        auto newPreset = std::make_unique<RuntimePreset>();
        auto buildResult = newPreset->buildFromSchema(schema);

        if (buildResult.failed())
        {
            DBG("Failed to build runtime preset: " + buildResult.getErrorMessage());
            return buildResult;
        }

        // Store schema for info queries
        {
            juce::ScopedLock lock(schemaLock);
            currentSchema = schema;
        }

        // Atomically swap preset
        auto *oldPreset = activePreset.exchange(newPreset.release());
        delete oldPreset;

        // Reset RR counters
        rrCounters.fill(0);

        // Clear all solo states when loading a new preset
        slotSoloed.fill(false);
        anySoloed = false;

        DBG("Preset loaded successfully");

        return juce::Result::ok();
    }

    juce::Result Engine::loadPresetFromJson(const juce::String &jsonText, const juce::String &rootFolder)
    {
        // Create schema by parsing from temp file
        PresetSchema schema;

        // Save to temp file and parse
        juce::File tempFile = juce::File::createTempFile(".json");
        if (tempFile.replaceWithText(jsonText))
        {
            auto result = PresetSchema::parseFromFile(tempFile, schema);
            tempFile.deleteFile();

            if (result.failed())
                return result;
        }
        else
        {
            return juce::Result::fail("Failed to create temp file for preset");
        }

        // Override root folder if provided
        // (for when samples have moved or schema has relative paths)
        if (!rootFolder.isEmpty())
            schema.rootFolder = rootFolder;
        auto newPreset = std::make_unique<RuntimePreset>();
        auto buildResult = newPreset->buildFromSchema(schema);

        if (buildResult.failed())
            return buildResult;

        // Store schema
        {
            juce::ScopedLock lock(schemaLock);
            currentSchema = schema;
        }

        // Atomically swap preset
        auto *oldPreset = activePreset.exchange(newPreset.release());
        delete oldPreset;

        // Reset RR counters
        rrCounters.fill(0);

        // Clear all solo states
        slotSoloed.fill(false);
        anySoloed = false;

        return juce::Result::ok();
    }

    Engine::PresetInfo Engine::getCurrentPresetInfo() const
    {
        PresetInfo info;

        juce::ScopedLock lock(schemaLock);

        if (currentSchema.schemaVersion == 1) // Valid schema
        {
            info.isValid = true;
            info.instrumentType = currentSchema.instrumentType;
            info.fixedMidiNote = currentSchema.fixedMidiNote;
            info.slotCount = juce::jmin(8, currentSchema.slotNames.size());
            info.layerCount = static_cast<int>(currentSchema.velocityLayers.size());
            info.slotNames = currentSchema.slotNames;

            // Determine which slots are active (have samples in any velocity layer)
            auto *preset = activePreset.load();
            if (preset)
            {
                const auto &layers = preset->getLayers();
                for (int slotIdx = 0; slotIdx < info.slotCount; ++slotIdx)
                {
                    bool hasAnySample = false;
                    for (const auto &layer : layers)
                    {
                        for (const auto &rrSlots : layer.samples)
                        {
                            if (slotIdx < static_cast<int>(rrSlots.size()) && rrSlots[slotIdx])
                            {
                                hasAnySample = true;
                                break;
                            }
                        }
                        if (hasAnySample)
                            break;
                    }
                    info.activeSlots[slotIdx] = hasAnySample;
                }
            }
        }

        return info;
    }

    void Engine::setSlotGain(int slotIndex, float gain)
    {
        if (slotIndex >= 0 && slotIndex < 8)
        {
            slotGains[slotIndex] = gain;
        }
    }

    void Engine::setSlotMuted(int slotIndex, bool muted)
    {
        if (slotIndex >= 0 && slotIndex < 8)
        {
            slotMuted[slotIndex] = muted;
        }
    }

    void Engine::setSlotSoloed(int slotIndex, bool soloed)
    {
        if (slotIndex >= 0 && slotIndex < 8)
        {
            slotSoloed[slotIndex] = soloed;

            // Update anySoloed flag
            anySoloed = false;
            for (bool s : slotSoloed)
            {
                if (s)
                {
                    anySoloed = true;
                    break;
                }
            }
        }
    }

    float Engine::getEffectiveSlotGain(int slotIndex) const
    {
        if (slotIndex < 0 || slotIndex >= 8)
            return 0.0f;

        // If muted, gain is 0
        if (slotMuted[slotIndex])
            return 0.0f;

        // If any slot is soloed and this isn't one of them, gain is 0
        if (anySoloed && !slotSoloed[slotIndex])
            return 0.0f;

        // Otherwise return the slot's gain
        return slotGains[slotIndex];
    }

    void Engine::setUseVelocityToVolume(bool enabled)
    {
        auto *preset = activePreset.load();
        if (preset)
        {
            preset->setUseVelocityToVolume(enabled);
        }
    }

    bool Engine::getUseVelocityToVolume() const
    {
        auto *preset = activePreset.load();
        if (preset)
        {
            return preset->getUseVelocityToVolume();
        }
        return false;
    }

    void Engine::setFixedMidiNote(int note)
    {
        auto *preset = activePreset.load();
        if (preset && note >= 0 && note <= 127)
        {
            preset->setFixedMidiNote(note);

            // Update the cached schema as well
            juce::ScopedLock lock(schemaLock);
            currentSchema.fixedMidiNote = note;
        }
    }

    int Engine::getFixedMidiNote() const
    {
        auto *preset = activePreset.load();
        if (preset)
        {
            return preset->getFixedMidiNote();
        }
        return 38; // Default snare
    }

    void Engine::setPitchShift(float semitones)
    {
        // Clamp to -6 to +6
        if (resamplingMode.load() == ResamplingMode::Off)
        {
            pitchShiftSemitones.store(0.0f);
            return;
        }

        semitones = juce::jlimit(-6.0f, 6.0f, semitones);
        pitchShiftSemitones.store(semitones);
    }

    void Engine::setResamplingMode(ResamplingMode mode)
    {
        resamplingMode.store(mode);

        // Update latency contribution for resampling
        setLatencyContribution("resampling", getResamplingLatencySamples());

        // Disable pitch when resampling is off
        if (mode == ResamplingMode::Off)
            pitchShiftSemitones.store(0.0f);
    }

    void Engine::setLatencyContribution(const juce::String &name, int samples)
    {
        juce::ScopedLock lock(latencyLock);
        latencyContributions[name] = samples;
    }

    void Engine::removeLatencyContribution(const juce::String &name)
    {
        juce::ScopedLock lock(latencyLock);
        latencyContributions.erase(name);
    }

    int Engine::getLatencySamples() const
    {
        juce::ScopedLock lock(latencyLock);
        int total = 0;
        for (const auto &entry : latencyContributions)
            total += entry.second;
        return total;
    }

    int Engine::getResamplingLatencySamples() const
    {
        switch (resamplingMode.load())
        {
        case ResamplingMode::Normal:
            return 2;
        case ResamplingMode::Ultra:
            return 100;
        case ResamplingMode::Off:
        default:
            return 0;
        }
    }

    void Engine::processBlock(juce::AudioBuffer<float> &buffer, juce::MidiBuffer &midiMessages,
                              bool multiOutEnabled)
    {
        // Get current preset
        auto *preset = activePreset.load();
        if (!preset)
            return;

        int totalSamples = buffer.getNumSamples();
        int currentSample = 0;

        // Process MIDI events with sample-accurate timing
        for (const auto metadata : midiMessages)
        {
            int eventSample = metadata.samplePosition;
            if (eventSample < 0)
                eventSample = 0;
            if (eventSample > totalSamples)
                eventSample = totalSamples;

            if (eventSample > currentSample)
            {
                // Render up to the event
                render(buffer, currentSample, eventSample - currentSample, multiOutEnabled);
                currentSample = eventSample;
            }

            auto message = metadata.getMessage();
            if (message.isNoteOn())
            {
                handleNoteOn(message.getNoteNumber(), message.getVelocity());
            }
        }

        // Render remaining samples
        if (currentSample < totalSamples)
        {
            render(buffer, currentSample, totalSamples - currentSample, multiOutEnabled);
        }

        // Clean up inactive hit groups
        activeHitGroups.erase(
            std::remove_if(activeHitGroups.begin(), activeHitGroups.end(),
                           [](const HitGroup &hg)
                           { return !hg.isActive(); }),
            activeHitGroups.end());
    }

    void Engine::handleNoteOn(int note, int velocity)
    {
        auto *preset = activePreset.load();
        if (!preset)
            return;

        // Check if this is the fixed MIDI note
        if (note != preset->getFixedMidiNote())
            return;

        // Find velocity layer
        int layerIndex = preset->findLayerByVelocity(velocity);
        if (layerIndex < 0)
        {
            DBG("No velocity layer found for velocity: " + juce::String(velocity));
            return;
        }

        const auto &layers = preset->getLayers();
        if (layerIndex >= static_cast<int>(layers.size()))
            return;

        const auto &layer = layers[layerIndex];

        // Get RR index
        int rrIndex = rrCounters[layerIndex] % layer.rrCount;
        rrCounters[layerIndex]++;

        // Notify hit callback (if set)
        if (hitCallback)
            hitCallback(layerIndex, rrIndex);

        // Calculate gain from velocity
        float gain = preset->velocityToGain(velocity);

        // Check if we need to steal a hit group
        if (activeHitGroups.size() >= kMaxHitGroups)
        {
            // Steal oldest hit group
            auto &oldestGroup = activeHitGroups.front();
            oldestGroup.beginRelease();
            activeHitGroups.pop_front();
        }

        // Create new hit group
        HitGroup newGroup;

        // Start voices for each slot
        int slotCount = preset->getSlotCount();
        for (int slotIdx = 0; slotIdx < slotCount; ++slotIdx)
        {
            if (rrIndex >= static_cast<int>(layer.samples.size()))
                continue;

            if (slotIdx >= static_cast<int>(layer.samples[rrIndex].size()))
                continue;

            auto sample = layer.samples[rrIndex][slotIdx];
            if (!sample || !sample->isValid())
                continue;

            // Allocate voice
            auto *voice = voicePool.allocateVoice();
            if (!voice)
            {
                DBG("Failed to allocate voice");
                continue;
            }

            // Set slot index for routing
            voice->slotIndex = slotIdx;

            // Calculate playback rate from sample rate conversion + pitch shift
            float playbackRate = 1.0f;
            const auto mode = resamplingMode.load();
            if (mode != ResamplingMode::Off)
            {
                const double sampleRate = sample->getSampleRate();
                const double hostRate = currentSampleRate > 0.0 ? currentSampleRate : 44100.0;
                const float rateRatio = (sampleRate > 0.0 ? static_cast<float>(sampleRate / hostRate) : 1.0f);
                const float pitchRatio = std::pow(2.0f, pitchShiftSemitones.load() / 12.0f);
                playbackRate = rateRatio * pitchRatio;
            }

            // Start voice with just velocity gain (not slot gain)
            // Slot gain (volume/mute/solo) will be applied only to mix during render
            voice->start(sample, gain, fadeLenSamples, playbackRate, mode);
            newGroup.voices[slotIdx] = voice;
        }

        // Add to active hit groups
        activeHitGroups.push_back(newGroup);
    }

    void Engine::render(juce::AudioBuffer<float> &buffer, int startSample, int numSamples,
                        bool multiOutEnabled)
    {
        // Build slot gains array (applies to mix only)
        std::array<float, 8> slotGainsForMix;
        for (int i = 0; i < 8; ++i)
            slotGainsForMix[i] = getEffectiveSlotGain(i);

        voicePool.renderAll(buffer, startSample, numSamples, multiOutEnabled, slotGainsForMix);
    }

} // namespace DrumEngine
