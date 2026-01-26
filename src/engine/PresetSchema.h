#pragma once

#include <juce_core/juce_core.h>
#include <vector>
#include <unordered_map>

namespace DrumEngine
{

    // Velocity-to-volume mapping configuration
    struct VelToVol
    {
        float amount = 100.0f;             // 0..100
        juce::String curveName = "linear"; // "linear", "soft", etc.

        VelToVol() = default;
    };

    // One velocity layer from JSON
    struct VelocityLayer
    {
        int index = 0; // informational (from JSON)
        int lo = 1;    // 1..127
        int hi = 127;  // 1..127

        // Key: slot index as STRING ("1", "2", ...)
        // Value: array of relative wav paths
        std::unordered_map<juce::String, juce::StringArray> wavsBySlot;

        VelocityLayer() = default;
    };

    // Top-level preset schema
    struct PresetSchema
    {
        int schemaVersion = 0;
        juce::String instrumentType;
        juce::StringArray slotNames;
        juce::String rootFolder;
        std::vector<VelocityLayer> velocityLayers;
        VelToVol velToVol;
        int fixedMidiNote = 38; // default to snare; can be overridden by JSON

        PresetSchema() = default;

        // Parse from JSON file
        static juce::Result parseFromFile(const juce::File &file, PresetSchema &outSchema);

        // Validate the schema
        juce::Result validate() const;

    private:
        static juce::Result parseJSON(const juce::var &json, PresetSchema &outSchema);
        static juce::Result parseVelocityLayer(const juce::var &layerJson, VelocityLayer &outLayer);
        static juce::Result parseVelToVol(const juce::var &velToVolJson, VelToVol &outVelToVol);
    };

} // namespace DrumEngine
