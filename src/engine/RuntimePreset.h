#pragma once

#include "PresetSchema.h"
#include "SampleRef.h"
#include <memory>
#include <unordered_map>

namespace DrumEngine
{

    // Runtime representation of a velocity layer with resolved samples
    struct RuntimeVelocityLayer
    {
        int lo = 1;
        int hi = 127;
        int rrCount = 0;

        // samples[rrIndex][slotIndex] -> SampleRef (nullptr if slot unused)
        // Max dimensions: [5][8]
        std::vector<std::vector<std::shared_ptr<SampleRef>>> samples;

        RuntimeVelocityLayer() = default;
    };

    // Runtime preset with resolved sample references
    class RuntimePreset
    {
    public:
        RuntimePreset() = default;

        // Build from schema (loads and caches samples)
        juce::Result buildFromSchema(const PresetSchema &schema);

        // Find velocity layer index by MIDI velocity (1..127)
        int findLayerByVelocity(int velocity) const;

        // Velocity to gain conversion
        float velocityToGain(int velocity) const;

        // Accessors
        int getSlotCount() const { return slotCount; }
        int getFixedMidiNote() const { return fixedMidiNote; }
        const std::vector<RuntimeVelocityLayer> &getLayers() const { return layers; }

    private:
        int slotCount = 0;
        int fixedMidiNote = 38;
        std::vector<RuntimeVelocityLayer> layers;

        // Velocity-to-volume config
        float velToVolAmount = 100.0f;
        juce::String velToVolCurve = "linear";

        // Sample cache for deduplication
        std::unordered_map<juce::String, std::shared_ptr<SampleRef>> sampleCache;

        std::shared_ptr<SampleRef> loadOrGetCachedSample(const juce::String &absolutePath);

        JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(RuntimePreset)
    };

} // namespace DrumEngine
