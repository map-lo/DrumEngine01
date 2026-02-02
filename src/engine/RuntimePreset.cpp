#include "RuntimePreset.h"
#include <algorithm>

namespace DrumEngine
{
    static juce::File resolveSamplePath(const juce::String &rootFolder, const juce::String &path)
    {
        juce::File file = juce::File::isAbsolutePath(path)
                              ? juce::File(path)
                              : juce::File(rootFolder).getChildFile(path);

        return file.getCanonicalFile();
    }

    // Helper function to log to file
    static void logToFile(const juce::String &message)
    {
        static juce::File logFile = juce::File::getSpecialLocation(juce::File::userHomeDirectory)
                                        .getChildFile("DrumEngine01_Debug.txt");

        juce::String timeStamp = juce::Time::getCurrentTime().toString(true, true, true, true);
        juce::String fullMessage = timeStamp + " - " + message + "\n";

        logFile.appendText(fullMessage);
    }

    juce::Result RuntimePreset::buildFromSchema(const PresetSchema &schema)
    {
        // Clear existing state
        layers.clear();
        sampleCache.clear();
        sourceSampleRate = 0.0;

        slotCount = juce::jmin(8, schema.slotNames.size());
        fixedMidiNote = schema.fixedMidiNote;
        velToVolAmount = schema.velToVol.amount;
        velToVolCurve = schema.velToVol.curveName;
        useVelocityToVolume = schema.useVelocityToVolume;

        logToFile("=== RuntimePreset::buildFromSchema ===");
        logToFile("useVelocityToVolume: " + juce::String(useVelocityToVolume ? "TRUE" : "FALSE"));
        logToFile("velToVolAmount: " + juce::String(velToVolAmount));
        logToFile("velToVolCurve: " + velToVolCurve);

        // Sort velocity layers by lo (ascending)
        DBG("useVelocityToVolume: " + juce::String(useVelocityToVolume ? "TRUE" : "FALSE"));
        DBG("velToVolAmount: " + juce::String(velToVolAmount));
        DBG("velToVolCurve: " + velToVolCurve);

        // Sort velocity layers by lo (ascending)
        auto sortedLayers = schema.velocityLayers;
        std::sort(sortedLayers.begin(), sortedLayers.end(),
                  [](const VelocityLayer &a, const VelocityLayer &b)
                  { return a.lo < b.lo; });

        // Build runtime layers
        for (const auto &schemaLayer : sortedLayers)
        {
            RuntimeVelocityLayer runtimeLayer;
            runtimeLayer.lo = schemaLayer.lo;
            runtimeLayer.hi = schemaLayer.hi;

            // Determine RR count
            int rrCount = 0;
            for (int slotIdx = 1; slotIdx <= slotCount; ++slotIdx)
            {
                juce::String slotKey = juce::String(slotIdx);
                auto it = schemaLayer.wavsBySlot.find(slotKey);
                if (it != schemaLayer.wavsBySlot.end())
                {
                    int wavCount = it->second.size();
                    if (wavCount > rrCount)
                        rrCount = wavCount;
                }
            }

            runtimeLayer.rrCount = rrCount;

            // Initialize samples array: [rrCount][slotCount]
            runtimeLayer.samples.resize(rrCount);
            for (int rr = 0; rr < rrCount; ++rr)
            {
                runtimeLayer.samples[rr].resize(slotCount, nullptr);
            }

            // Load samples for each slot
            for (int slotIdx = 1; slotIdx <= slotCount; ++slotIdx)
            {
                juce::String slotKey = juce::String(slotIdx);
                auto it = schemaLayer.wavsBySlot.find(slotKey);

                if (it == schemaLayer.wavsBySlot.end() || it->second.isEmpty())
                    continue; // Slot unused

                const auto &wavPaths = it->second;

                for (int rr = 0; rr < juce::jmin(rrCount, wavPaths.size()); ++rr)
                {
                    juce::String relativePath = wavPaths[rr];
                    juce::String absolutePath = resolveSamplePath(schema.rootFolder, relativePath).getFullPathName();

                    auto sample = loadOrGetCachedSample(absolutePath);
                    if (!sample || !sample->isValid())
                    {
                        DBG("Warning: Failed to load sample: " + absolutePath);
                        continue;
                    }

                    if (sourceSampleRate <= 0.0)
                        sourceSampleRate = sample->getSampleRate();

                    // Store in samples[rr][slotIdx-1] (convert to 0-based)
                    runtimeLayer.samples[rr][slotIdx - 1] = sample;
                }
            }

            layers.push_back(std::move(runtimeLayer));
        }

        if (layers.empty())
            return juce::Result::fail("No valid velocity layers loaded");

        return juce::Result::ok();
    }

    int RuntimePreset::findLayerByVelocity(int velocity) const
    {
        for (size_t i = 0; i < layers.size(); ++i)
        {
            if (velocity >= layers[i].lo && velocity <= layers[i].hi)
                return static_cast<int>(i);
        }
        return -1; // No matching layer
    }

    float RuntimePreset::velocityToGain(int velocity) const
    {
        // If velocity to volume is disabled, always return full gain
        if (!useVelocityToVolume)
        {
            logToFile("Velocity to volume DISABLED - returning 1.0");
            return 1.0f;
        }

        logToFile("Velocity to volume ENABLED - velocity: " + juce::String(velocity));

        float vel01 = juce::jlimit(0.0f, 1.0f, (velocity - 1) / 126.0f);

        // Apply curve
        float shaped = vel01;
        if (velToVolCurve == "soft")
        {
            // Soft curve: more gain at lower velocities
            shaped = std::pow(vel01, 0.5f);
        }
        else
        {
            // Linear (default)
            shaped = vel01;
        }

        // Apply amount (0..100 -> 0..1)
        float amount01 = velToVolAmount / 100.0f;
        float finalGain = juce::jlimit(0.0f, 1.0f, shaped * amount01 + (1.0f - amount01));

        logToFile("Final gain: " + juce::String(finalGain) + " (vel01=" + juce::String(vel01) + ", amount=" + juce::String(velToVolAmount) + ")");

        return finalGain;
    }

    std::shared_ptr<SampleRef> RuntimePreset::loadOrGetCachedSample(const juce::String &absolutePath)
    {
        // Check cache
        auto it = sampleCache.find(absolutePath);
        if (it != sampleCache.end())
            return it->second;

        // Load new sample
        auto sample = std::make_shared<SampleRef>();
        auto result = sample->loadFromFile(juce::File(absolutePath));

        if (result.failed())
        {
            DBG("Failed to load sample: " + result.getErrorMessage());
            return nullptr;
        }

        // Cache it
        sampleCache[absolutePath] = sample;
        return sample;
    }

} // namespace DrumEngine
