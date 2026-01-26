#include "SampleRef.h"

namespace DrumEngine
{

    SampleRef::~SampleRef()
    {
        reader.reset();
    }

    juce::Result SampleRef::loadFromFile(const juce::File &file)
    {
        if (!file.existsAsFile())
            return juce::Result::fail("Sample file does not exist: " + file.getFullPathName());

        filePath = file.getFullPathName();

        juce::AudioFormatManager formatManager;
        formatManager.registerBasicFormats();

        // Try to create a memory-mapped reader first
        reader.reset(formatManager.createReaderFor(file));

        if (!reader)
            return juce::Result::fail("Failed to create audio reader for: " + filePath);

        numChannels = reader->numChannels;
        totalFrames = reader->lengthInSamples;
        sampleRate = reader->sampleRate;

        if (numChannels < 1 || numChannels > 2)
        {
            reader.reset();
            return juce::Result::fail("Unsupported channel count: " + juce::String(numChannels) + " (must be 1 or 2)");
        }

        if (totalFrames <= 0)
        {
            reader.reset();
            return juce::Result::fail("Sample has no frames: " + filePath);
        }

        // Initialize cache
        readCache.setSize(2, kCacheSize);
        cacheStartFrame = -1;
        cacheSize = 0;

        return juce::Result::ok();
    }

    void SampleRef::getFrame(juce::int64 frameIndex, float &outLeft, float &outRight) const
    {
        if (!reader || frameIndex < 0 || frameIndex >= totalFrames)
        {
            outLeft = 0.0f;
            outRight = 0.0f;
            return;
        }

        // Check if frame is in cache
        if (frameIndex < cacheStartFrame || frameIndex >= cacheStartFrame + cacheSize)
        {
            updateCache(frameIndex);
        }

        // Read from cache
        int cacheOffset = static_cast<int>(frameIndex - cacheStartFrame);

        if (cacheOffset >= 0 && cacheOffset < cacheSize)
        {
            if (numChannels == 1)
            {
                // Mono: duplicate to both channels
                float mono = readCache.getSample(0, cacheOffset);
                outLeft = mono;
                outRight = mono;
            }
            else
            {
                // Stereo
                outLeft = readCache.getSample(0, cacheOffset);
                outRight = readCache.getSample(1, cacheOffset);
            }
        }
        else
        {
            outLeft = 0.0f;
            outRight = 0.0f;
        }
    }

    void SampleRef::updateCache(juce::int64 frameIndex) const
    {
        if (!reader)
            return;

        // Determine how many frames to read
        juce::int64 framesToRead = juce::jmin<juce::int64>(kCacheSize, totalFrames - frameIndex);
        if (framesToRead <= 0)
        {
            cacheStartFrame = -1;
            cacheSize = 0;
            return;
        }

        // Read into cache
        if (numChannels == 1)
        {
            // Read mono into first channel, will duplicate on getFrame
            int *channels[1] = {nullptr};
            reader->read(&readCache, 0, static_cast<int>(framesToRead), frameIndex, true, false);
        }
        else
        {
            // Read stereo
            reader->read(&readCache, 0, static_cast<int>(framesToRead), frameIndex, true, true);
        }

        cacheStartFrame = frameIndex;
        cacheSize = static_cast<int>(framesToRead);
    }

} // namespace DrumEngine
