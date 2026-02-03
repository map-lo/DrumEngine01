#pragma once

#include <JuceHeader.h>

class PresetCacheBuilder
{
public:
    struct PresetEntry
    {
        juce::String displayName;
        juce::String category;
        juce::String instrumentType;
        juce::File file;
        juce::StringArray tags;
    };

    static juce::StringArray buildPresetTags(const juce::String &category,
                                             const juce::String &instrumentType);
    static std::vector<PresetEntry> buildPresetListFromRoot(const juce::File &rootFolder);
};
