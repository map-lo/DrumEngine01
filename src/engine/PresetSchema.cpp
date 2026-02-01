#include "PresetSchema.h"
#include "MidiNoteUtils.h"

namespace DrumEngine
{

    juce::Result PresetSchema::parseFromFile(const juce::File &file, PresetSchema &outSchema)
    {
        if (!file.existsAsFile())
            return juce::Result::fail("Preset file does not exist: " + file.getFullPathName());

        juce::String jsonText = file.loadFileAsString();
        if (jsonText.isEmpty())
            return juce::Result::fail("Preset file is empty: " + file.getFullPathName());

        juce::var json;
        auto parseResult = juce::JSON::parse(jsonText, json);
        if (parseResult.failed())
            return juce::Result::fail("Failed to parse JSON: " + parseResult.getErrorMessage());

        auto result = parseJSON(json, outSchema);
        if (result.failed())
            return result;

        // Auto-resolve rootFolder to parent directory if empty
        if (outSchema.rootFolder.isEmpty())
        {
            outSchema.rootFolder = file.getParentDirectory().getFullPathName();
        }

        return juce::Result::ok();
    }

    juce::Result PresetSchema::parseJSON(const juce::var &json, PresetSchema &outSchema)
    {
        if (!json.isObject())
            return juce::Result::fail("Root JSON must be an object");

        auto *obj = json.getDynamicObject();
        if (!obj)
            return juce::Result::fail("Invalid JSON object");

        // Schema version (required)
        outSchema.schemaVersion = obj->getProperty("schemaVersion");
        if (outSchema.schemaVersion != 1)
            return juce::Result::fail("Unsupported schemaVersion. Expected: 1, Got: " + juce::String(outSchema.schemaVersion));

        // Instrument type (optional)
        outSchema.instrumentType = obj->getProperty("instrumentType").toString();

        // Slot names (required)
        auto slotNamesVar = obj->getProperty("slotNames");
        if (!slotNamesVar.isArray())
            return juce::Result::fail("slotNames must be an array");

        auto *slotNamesArray = slotNamesVar.getArray();
        if (!slotNamesArray || slotNamesArray->size() == 0)
            return juce::Result::fail("slotNames array is empty");

        for (auto &slotName : *slotNamesArray)
            outSchema.slotNames.add(slotName.toString());

        // Root folder (optional - will be auto-resolved to parent directory if empty)
        outSchema.rootFolder = obj->getProperty("rootFolder").toString();

        // Velocity layers (required)
        auto velocityLayersVar = obj->getProperty("velocityLayers");
        if (!velocityLayersVar.isArray())
            return juce::Result::fail("velocityLayers must be an array");

        auto *velocityLayersArray = velocityLayersVar.getArray();
        if (!velocityLayersArray || velocityLayersArray->size() == 0)
            return juce::Result::fail("velocityLayers array is empty");

        for (auto &layerVar : *velocityLayersArray)
        {
            VelocityLayer layer;
            auto result = parseVelocityLayer(layerVar, layer);
            if (result.failed())
                return result;
            outSchema.velocityLayers.push_back(layer);
        }

        // velToVol (optional)
        if (obj->hasProperty("velToVol"))
        {
            auto result = parseVelToVol(obj->getProperty("velToVol"), outSchema.velToVol);
            if (result.failed())
                return result;
        }

        // fixedMidiNote (optional, defaults based on instrumentType)
        if (obj->hasProperty("fixedMidiNote"))
        {
            outSchema.fixedMidiNote = obj->getProperty("fixedMidiNote");
            if (outSchema.fixedMidiNote < 0 || outSchema.fixedMidiNote > 127)
                return juce::Result::fail("fixedMidiNote must be 0..127");
        }
        else
        {
            // Use default MIDI note based on instrument type
            outSchema.fixedMidiNote = MidiNoteUtils::getDefaultMidiNoteForInstrument(outSchema.instrumentType);
        }

        // useVelocityToVolume (optional, default is false)
        if (obj->hasProperty("useVelocityToVolume"))
        {
            outSchema.useVelocityToVolume = obj->getProperty("useVelocityToVolume");
        }

        // Validate the schema
        return outSchema.validate();
    }

    juce::Result PresetSchema::parseVelocityLayer(const juce::var &layerJson, VelocityLayer &outLayer)
    {
        if (!layerJson.isObject())
            return juce::Result::fail("Velocity layer must be an object");

        auto *obj = layerJson.getDynamicObject();
        if (!obj)
            return juce::Result::fail("Invalid velocity layer object");

        // Index (informational)
        outLayer.index = obj->getProperty("index");

        // lo and hi (required)
        outLayer.lo = obj->getProperty("lo");
        outLayer.hi = obj->getProperty("hi");

        if (outLayer.lo < 1 || outLayer.lo > 127)
            return juce::Result::fail("Velocity layer lo must be 1..127");
        if (outLayer.hi < 1 || outLayer.hi > 127)
            return juce::Result::fail("Velocity layer hi must be 1..127");
        if (outLayer.lo > outLayer.hi)
            return juce::Result::fail("Velocity layer lo must be <= hi");

        // wavsBySlot (required)
        auto wavsBySlotVar = obj->getProperty("wavsBySlot");
        if (!wavsBySlotVar.isObject())
            return juce::Result::fail("wavsBySlot must be an object");

        auto *wavsBySlotObj = wavsBySlotVar.getDynamicObject();
        if (!wavsBySlotObj)
            return juce::Result::fail("Invalid wavsBySlot object");

        for (auto &prop : wavsBySlotObj->getProperties())
        {
            juce::String slotKey = prop.name.toString();

            if (!prop.value.isArray())
                return juce::Result::fail("wavsBySlot[" + slotKey + "] must be an array");

            auto *wavArray = prop.value.getArray();
            if (!wavArray)
                continue;

            juce::StringArray wavPaths;
            for (auto &wavVar : *wavArray)
                wavPaths.add(wavVar.toString());

            outLayer.wavsBySlot[slotKey] = wavPaths;
        }

        return juce::Result::ok();
    }

    juce::Result PresetSchema::parseVelToVol(const juce::var &velToVolJson, VelToVol &outVelToVol)
    {
        if (!velToVolJson.isObject())
            return juce::Result::fail("velToVol must be an object");

        auto *obj = velToVolJson.getDynamicObject();
        if (!obj)
            return juce::Result::fail("Invalid velToVol object");

        // Amount (optional, default 100)
        if (obj->hasProperty("amount"))
        {
            outVelToVol.amount = obj->getProperty("amount");
            outVelToVol.amount = juce::jlimit(0.0f, 100.0f, outVelToVol.amount);
        }

        // Curve name - support both formats:
        // 1. Simple: "curveName": "soft"
        // 2. Nested: "curve": { "type": "builtin", "name": "soft" }
        if (obj->hasProperty("curveName"))
        {
            outVelToVol.curveName = obj->getProperty("curveName").toString();
        }
        else if (obj->hasProperty("curve"))
        {
            auto curveVar = obj->getProperty("curve");
            if (curveVar.isObject())
            {
                auto *curveObj = curveVar.getDynamicObject();
                if (curveObj && curveObj->hasProperty("name"))
                    outVelToVol.curveName = curveObj->getProperty("name").toString();
            }
        }

        return juce::Result::ok();
    }

    juce::Result PresetSchema::validate() const
    {
        // Check slot count
        int slotCount = slotNames.size();
        if (slotCount < 1 || slotCount > 8)
            return juce::Result::fail("Slot count must be 1..8, got: " + juce::String(slotCount));

        // Check velocity layer count
        if (velocityLayers.size() < 1 || velocityLayers.size() > 10)
            return juce::Result::fail("Velocity layer count must be 1..10, got: " + juce::String(velocityLayers.size()));

        // Validate each velocity layer
        for (size_t i = 0; i < velocityLayers.size(); ++i)
        {
            const auto &layer = velocityLayers[i];

            // Determine RR count for this layer
            int rrCount = 0;
            for (int slotIdx = 1; slotIdx <= slotCount; ++slotIdx)
            {
                juce::String slotKey = juce::String(slotIdx);
                auto it = layer.wavsBySlot.find(slotKey);
                if (it != layer.wavsBySlot.end())
                {
                    int wavCount = it->second.size();
                    if (wavCount > 0)
                    {
                        if (rrCount == 0)
                            rrCount = wavCount;
                        else if (wavCount != rrCount)
                        {
                            return juce::Result::fail(
                                "Velocity layer " + juce::String((int)i) + " has mismatched RR counts: " +
                                "expected " + juce::String(rrCount) + ", got " + juce::String(wavCount) +
                                " for slot " + slotKey);
                        }
                    }
                }
            }

            if (rrCount == 0)
                return juce::Result::fail("Velocity layer " + juce::String((int)i) + " has no samples");
        }

        return juce::Result::ok();
    }

} // namespace DrumEngine
