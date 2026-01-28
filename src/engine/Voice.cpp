#include "Voice.h"

namespace DrumEngine
{

    //==============================================================================
    // MicVoice

    void MicVoice::start(std::shared_ptr<SampleRef> sample, float startGain, int fadeLenSamps, float rate)
    {
        currentSample = sample;
        gain = startGain;
        fadeLenSamples = fadeLenSamps;
        playbackPosition = 0.0;
        playbackRate = rate;
        fadePosition = 0;
        state = State::Playing;
    }

    void MicVoice::beginRelease()
    {
        if (state == State::Inactive)
            return;

        state = State::Releasing;
        fadePosition = 0;
    }

    void MicVoice::reset()
    {
        state = State::Inactive;
        currentSample = nullptr;
        playbackPosition = 0.0;
        playbackRate = 1.0f;
        fadePosition = 0;
    }

    void MicVoice::render(juce::AudioBuffer<float> &buffer, int startSample, int numSamples,
                          bool multiOutEnabled, float mixSlotGain)
    {
        if (state == State::Inactive || !currentSample || !currentSample->isValid())
            return;

        int bufferChannels = buffer.getNumChannels();
        if (bufferChannels < 2)
            return; // Need at least stereo

        // Always write to mix (channels 0-1)
        float *mixLeft = buffer.getWritePointer(0, startSample);
        float *mixRight = buffer.getWritePointer(1, startSample);

        // In multi-out mode, also write to individual slot output
        float *slotLeft = nullptr;
        float *slotRight = nullptr;

        if (multiOutEnabled)
        {
            // Individual mic outputs: mic 0 -> channels 2-3, mic 1 -> channels 4-5, etc.
            // Formula: channels (slotIndex * 2 + 2) and (slotIndex * 2 + 3)
            int leftChannel = slotIndex * 2 + 2;
            int rightChannel = slotIndex * 2 + 3;

            // Verify slotIndex is valid and channels exist
            jassert(slotIndex >= 0 && slotIndex < 8);

            if (rightChannel < bufferChannels)
            {
                slotLeft = buffer.getWritePointer(leftChannel, startSample);
                slotRight = buffer.getWritePointer(rightChannel, startSample);
            }
        }

        for (int i = 0; i < numSamples; ++i)
        {
            float sampleLeft = 0.0f;
            float sampleRight = 0.0f;

            if (state == State::Playing)
            {
                // Read from sample with cubic interpolation
                if (playbackPosition < currentSample->getTotalFrames() - 1)
                {
                    int idx = static_cast<int>(playbackPosition);
                    float frac = static_cast<float>(playbackPosition - idx);

                    // Get 4 samples for cubic interpolation (handle boundaries)
                    float L[4], R[4];
                    for (int j = 0; j < 4; ++j)
                    {
                        int sampleIdx = idx + j - 1;
                        sampleIdx = juce::jlimit(0, static_cast<int>(currentSample->getTotalFrames() - 1), sampleIdx);
                        currentSample->getFrame(sampleIdx, L[j], R[j]);
                    }

                    // Cubic interpolation (Catmull-Rom)
                    auto cubicInterp = [](float y0, float y1, float y2, float y3, float mu)
                    {
                        float a0 = -0.5f * y0 + 1.5f * y1 - 1.5f * y2 + 0.5f * y3;
                        float a1 = y0 - 2.5f * y1 + 2.0f * y2 - 0.5f * y3;
                        float a2 = -0.5f * y0 + 0.5f * y2;
                        float a3 = y1;
                        return a0 * mu * mu * mu + a1 * mu * mu + a2 * mu + a3;
                    };

                    sampleLeft = cubicInterp(L[0], L[1], L[2], L[3], frac);
                    sampleRight = cubicInterp(R[0], R[1], R[2], R[3], frac);

                    playbackPosition += playbackRate;

                    // Check if reached EOF
                    if (playbackPosition >= currentSample->getTotalFrames())
                    {
                        beginRelease();
                    }
                }
            }

            // Apply fade-out if releasing
            float fadeGain = 1.0f;
            if (state == State::Releasing)
            {
                if (fadePosition < fadeLenSamples)
                {
                    fadeGain = 1.0f - (static_cast<float>(fadePosition) / static_cast<float>(fadeLenSamples));
                    fadePosition++;
                }
                else
                {
                    // Fade complete
                    reset();
                    return;
                }
            }

            // Apply gain and fade
            sampleLeft *= gain * fadeGain;
            sampleRight *= gain * fadeGain;

            // Always write to mix output (with slot gain for volume/mute/solo)
            mixLeft[i] += sampleLeft * mixSlotGain;
            mixRight[i] += sampleRight * mixSlotGain;

            // Also write to individual slot output if multi-out enabled (raw, no slot gain)
            if (slotLeft && slotRight)
            {
                slotLeft[i] += sampleLeft;
                slotRight[i] += sampleRight;
            }
        }
    }

    //==============================================================================
    // VoicePool

    void VoicePool::allocate(int numVoices)
    {
        voices.clear();
        voices.reserve(numVoices);

        for (int i = 0; i < numVoices; ++i)
        {
            voices.push_back(std::make_unique<MicVoice>());
        }
    }

    void VoicePool::reset()
    {
        for (auto &voice : voices)
        {
            voice->reset();
        }
    }

    MicVoice *VoicePool::allocateVoice()
    {
        // Find inactive voice
        for (auto &voice : voices)
        {
            if (!voice->isActive())
                return voice.get();
        }

        // All voices active, steal oldest releasing voice or oldest playing voice
        MicVoice *oldestReleasing = nullptr;
        MicVoice *oldestPlaying = nullptr;

        for (auto &voice : voices)
        {
            if (voice->getState() == MicVoice::State::Releasing)
            {
                oldestReleasing = voice.get();
                break;
            }
            if (!oldestPlaying && voice->getState() == MicVoice::State::Playing)
            {
                oldestPlaying = voice.get();
            }
        }

        if (oldestReleasing)
        {
            oldestReleasing->reset();
            return oldestReleasing;
        }

        if (oldestPlaying)
        {
            oldestPlaying->reset();
            return oldestPlaying;
        }

        // Fallback: return first voice
        if (!voices.empty())
        {
            voices[0]->reset();
            return voices[0].get();
        }

        return nullptr;
    }

    void VoicePool::renderAll(juce::AudioBuffer<float> &buffer, int startSample, int numSamples,
                              bool multiOutEnabled, const std::array<float, 8> &slotGains)
    {
        for (auto &voice : voices)
        {
            if (voice->isActive())
            {
                float mixGain = slotGains[voice->slotIndex];
                voice->render(buffer, startSample, numSamples, multiOutEnabled, mixGain);
            }
        }
    }

} // namespace DrumEngine
