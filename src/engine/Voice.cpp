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
                          int outputChannel)
    {
        if (state == State::Inactive || !currentSample || !currentSample->isValid())
            return;

        int bufferChannels = buffer.getNumChannels();
        if (outputChannel + 1 >= bufferChannels)
            return; // Need stereo pair

        float *leftChannel = buffer.getWritePointer(outputChannel, startSample);
        float *rightChannel = buffer.getWritePointer(outputChannel + 1, startSample);

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

            // Mix into buffer
            leftChannel[i] += sampleLeft;
            rightChannel[i] += sampleRight;
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
                              int outputChannel, int slotFilter)
    {
        for (auto &voice : voices)
        {
            if (voice->isActive())
            {
                // If slotFilter is specified, only render voices from that slot
                if (slotFilter != -1 && voice->slotIndex != slotFilter)
                    continue;

                voice->render(buffer, startSample, numSamples, outputChannel);
            }
        }
    }

} // namespace DrumEngine
