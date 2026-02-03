#include "PresetCacheBuilder.h"

juce::StringArray PresetCacheBuilder::buildPresetTags(const juce::String &displayName,
                                                      const juce::String &category,
                                                      const juce::String &instrumentType)
{
    juce::StringArray tags;
    auto normalizeToken = [](juce::String value)
    {
        return value.trim().toLowerCase().removeCharacters(" \t\r\n");
    };

    const auto instrumentTypeLower = normalizeToken(instrumentType);
    const auto pluralInstrumentTypeLower = instrumentTypeLower.isEmpty() || instrumentTypeLower.endsWith("s")
                                               ? instrumentTypeLower
                                               : instrumentTypeLower + "s";
    const auto drumEngineLower = normalizeToken("drumengine01");

    juce::StringArray displayTokens;
    displayTokens.addTokens(displayName, " /_-.", "\"'()[]{}:");
    displayTokens.trim();
    displayTokens.removeEmptyStrings();
    displayTokens.removeDuplicates(true);

    juce::StringArray displayTokensNormalized;
    for (const auto &token : displayTokens)
    {
        const auto normalized = normalizeToken(token);
        if (normalized.isNotEmpty())
            displayTokensNormalized.addIfNotAlreadyThere(normalized);
    }

    auto tagCategory = category;
    const auto lastSlashIndex = tagCategory.lastIndexOfChar('/');
    if (lastSlashIndex >= 0)
        tagCategory = tagCategory.substring(0, lastSlashIndex);
    else
        tagCategory = "";

    juce::String tagSource = tagCategory + " " + instrumentType;
    juce::StringArray tokens;
    tokens.addTokens(tagSource, " /_-.", "\"'()[]{}:");
    tokens.trim();
    tokens.removeEmptyStrings();
    tokens.removeDuplicates(true);

    for (const auto &token : tokens)
    {
        const auto tokenLower = normalizeToken(token);
        if (displayTokensNormalized.contains(tokenLower, false))
            continue;
        if (!instrumentTypeLower.isEmpty() && tokenLower == instrumentTypeLower)
            continue;
        if (!pluralInstrumentTypeLower.isEmpty() && tokenLower == pluralInstrumentTypeLower)
            continue;
        if (tokenLower == drumEngineLower)
            continue;
        tags.addIfNotAlreadyThere(token);
    }

    return tags;
}

std::vector<PresetCacheBuilder::PresetEntry>
PresetCacheBuilder::buildPresetListFromRoot(const juce::File &rootFolder)
{
    std::vector<PresetEntry> results;

    if (!rootFolder.exists() || !rootFolder.isDirectory())
        return results;

    std::function<void(const juce::File &, const juce::String &)> scanFolder =
        [&](const juce::File &folder, const juce::String &categoryPath)
    {
        auto allFiles = folder.findChildFiles(juce::File::findFilesAndDirectories, false, "*");

        juce::Array<juce::File> subFolders;
        juce::Array<juce::File> presetFolders;

        for (const auto &file : allFiles)
        {
            if (file.isDirectory())
            {
                if (file.getFileName().startsWith("."))
                    continue; // Skip hidden folders

                if (file.getFileName().endsWithIgnoreCase(".preset"))
                    presetFolders.add(file);
                else
                    subFolders.add(file);
            }
        }

        subFolders.sort();
        presetFolders.sort();

        for (const auto &presetFolder : presetFolders)
        {
            juce::File jsonFile = presetFolder.getChildFile("preset.json");
            if (!jsonFile.existsAsFile())
                continue;

            juce::String presetName = presetFolder.getFileNameWithoutExtension();
            juce::String category = categoryPath.isEmpty() ? folder.getFileName() : categoryPath;
            if (category.startsWithIgnoreCase("DrumEngine01/"))
                category = category.fromFirstOccurrenceOf("DrumEngine01/", false, false);
            else if (category.startsWithIgnoreCase("DrumEngine01"))
                category = category.fromFirstOccurrenceOf("DrumEngine01", false, false).trimCharactersAtStart("/");
            category = category.trimCharactersAtStart("/");

            juce::String displayName = presetName;

            juce::String instrumentType = "Unknown";
            auto jsonText = jsonFile.loadFileAsString();
            if (!jsonText.isEmpty())
            {
                juce::var json;
                auto result = juce::JSON::parse(jsonText, json);
                if (result.wasOk() && json.isObject())
                {
                    if (auto *obj = json.getDynamicObject())
                    {
                        if (obj->hasProperty("instrumentType"))
                            instrumentType = obj->getProperty("instrumentType").toString();
                        else if (obj->hasProperty("instrument_type"))
                            instrumentType = obj->getProperty("instrument_type").toString();
                    }
                }
            }

            auto tags = buildPresetTags(displayName, category, instrumentType);
            results.push_back({displayName, category, instrumentType, jsonFile, tags});
        }

        for (const auto &subFolder : subFolders)
        {
            juce::String newCategoryPath = categoryPath.isEmpty() ? folder.getFileName() + "/" + subFolder.getFileName() : categoryPath + "/" + subFolder.getFileName();
            scanFolder(subFolder, newCategoryPath);
        }
    };

    scanFolder(rootFolder, "");
    return results;
}
