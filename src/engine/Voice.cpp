#include "Voice.h"

namespace DrumEngine
{

    //==============================================================================
    // MicVoice

    void MicVoice::start(std::shared_ptr<SampleRef> sample, float startGain, int fadeLenSamps)
    {
        currentSample = sample;
        gain = startGain;
        fadeLenSamples = fadeLenSamps;
        playbackFrame = 0;
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
        playbackFrame = 0;
        fadePosition = 0;
    }

    void MicVoice::render(juce::AudioBuffer<float> &buffer, int startSample, int numSamples,
                          bool multiOutEnabled)
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
                // Read from sample
                if (playbackFrame < currentSample->getTotalFrames())
                {
                    currentSample->getFrame(playbackFrame, sampleLeft, sampleRight);
                    playbackFrame++;

                    // Check if reached EOF
                    if (playbackFrame >= currentSample->getTotalFrames())
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

            // Always write to mix output
            mixLeft[i] += sampleLeft;
            mixRight[i] += sampleRight;

            // Also write to individual slot output if multi-out enabled
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
                              bool multiOutEnabled)
    {
        for (auto &voice : voices)
        {
            if (voice->isActive())
            {
                voice->render(buffer, startSample, numSamples, multiOutEnabled);
            }
        }
    }

} // namespace DrumEngine
