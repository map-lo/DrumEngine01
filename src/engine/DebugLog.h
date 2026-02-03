#pragma once

#include <juce_core/juce_core.h>

namespace DrumEngine
{
    inline void debugLog(const juce::String &message)
    {
#if JUCE_DEBUG
        const auto now = juce::Time::getCurrentTime();
        const auto dateString = now.formatted("%Y-%m-%d");
        juce::File logFile = juce::File::getSpecialLocation(juce::File::userHomeDirectory)
                                 .getChildFile("DrumEngine01." + dateString + ".log");

        const juce::String timestamp = now.toString(true, true, true, true);
        logFile.appendText(timestamp + " - " + message + "\n");
#else
        juce::ignoreUnused(message);
#endif
    }
}
