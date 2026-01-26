#pragma once

#include <juce_audio_formats/juce_audio_formats.h>
#include <memory>

namespace DrumEngine
{

    // Represents a single audio sample file with memory-mapped streaming
    class SampleRef
    {
    public:
        SampleRef() = default;
        ~SampleRef();

        // Load from file (prefer memory-mapped reader)
        juce::Result loadFromFile(const juce::File &file);

        // Get audio data for a single frame
        void getFrame(juce::int64 frameIndex, float &outLeft, float &outRight) const;

        // Accessors
        int getNumChannels() const { return numChannels; }
        juce::int64 getTotalFrames() const { return totalFrames; }
        double getSampleRate() const { return sampleRate; }
        juce::String getFilePath() const { return filePath; }

        bool isValid() const { return reader != nullptr; }

    private:
        juce::String filePath;
        std::unique_ptr<juce::AudioFormatReader> reader;
        int numChannels = 0;
        juce::int64 totalFrames = 0;
        double sampleRate = 0.0;

        // Small cache for block reading if needed
        mutable juce::AudioBuffer<float> readCache;
        mutable juce::int64 cacheStartFrame = -1;
        mutable int cacheSize = 0;
        static constexpr int kCacheSize = 512; // frames to cache

        void updateCache(juce::int64 frameIndex) const;

        JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(SampleRef)
    };

} // namespace DrumEngine
