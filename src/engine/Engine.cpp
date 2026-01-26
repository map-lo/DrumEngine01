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

        DBG("Preset loaded successfully");

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

    void Engine::processBlock(juce::AudioBuffer<float> &buffer, juce::MidiBuffer &midiMessages,
                              int outputChannel, int slotFilter)
    {
        // Get current preset
        auto *preset = activePreset.load();
        if (!preset)
            return;

        // Process MIDI events (only once, regardless of slot filter)
        if (slotFilter == -1 || slotFilter == 0)
        {
            for (const auto metadata : midiMessages)
            {
                auto message = metadata.getMessage();

                if (message.isNoteOn())
                {
                    handleNoteOn(message.getNoteNumber(), message.getVelocity());
                }
            }
        }

        // Render voices for the specified slot(s) to the specified output channels
        render(buffer, 0, buffer.getNumSamples(), outputChannel, slotFilter);

        // Clean up inactive hit groups (only once)
        if (slotFilter == -1 || slotFilter == 0)
        {
            activeHitGroups.erase(
                std::remove_if(activeHitGroups.begin(), activeHitGroups.end(),
                               [](const HitGroup &hg)
                               { return !hg.isActive(); }),
                activeHitGroups.end());
        }
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

            // Calculate final gain (velocity gain * slot gain)
            float slotGain = getEffectiveSlotGain(slotIdx);
            float finalGain = gain * slotGain;

            // Start voice
            voice->start(sample, finalGain, fadeLenSamples);
            newGroup.voices[slotIdx] = voice;
        }

        // Add to active hit groups
        activeHitGroups.push_back(newGroup);
    }

    void Engine::render(juce::AudioBuffer<float> &buffer, int startSample, int numSamples,
                        int outputChannel, int slotFilter)
    {
        voicePool.renderAll(buffer, startSample, numSamples, outputChannel, slotFilter);
    }

} // namespace DrumEngine
