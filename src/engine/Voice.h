#pragma once

#include "ResamplingMode.h"
#include "SampleRef.h"
#include <memory>
#include <vector>
#include <array>

namespace DrumEngine
{

    // Single mic voice (one-shot sample playback with fixed fade-out)
    class MicVoice
    {
    public:
        enum class State
        {
            Inactive,
            Playing,
            Releasing
        };

        MicVoice() = default;

        void start(std::shared_ptr<SampleRef> sample, float gain, int fadeLenSamples, float rate = 1.0f,
                   ResamplingMode mode = ResamplingMode::Ultra);
        void beginRelease();
        void reset();

        void render(juce::AudioBuffer<float> &buffer, int startSample, int numSamples,
                    bool multiOutEnabled, float slotGain);

        bool isActive() const { return state != State::Inactive; }
        State getState() const { return state; }

        int slotIndex = 0; // Which slot this voice belongs to (0-7)

    private:
        State state = State::Inactive;
        std::shared_ptr<SampleRef> currentSample;
        juce::int64 inputSampleIndex = 0;
        double playbackPosition = 0.0;
        float playbackRate = 1.0f;
        float gain = 1.0f;
        ResamplingMode resamplingMode = ResamplingMode::Ultra;

        // Resampling state (per channel)
        juce::WindowedSincInterpolator windowedSincInterpolators[2];
        juce::AudioBuffer<float> resampleInputBuffer;
        juce::AudioBuffer<float> resampleOutputBuffer;

        // Fade-out state
        int fadeLenSamples = 32;
        int fadePosition = 0; // 0..fadeLenSamples

        JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(MicVoice)
    };

    // Group of mic voices triggered together (one per slot)
    struct HitGroup
    {
        static constexpr int kMaxSlots = 8;
        std::array<MicVoice *, kMaxSlots> voices = {}; // nullptr if slot unused

        HitGroup() { voices.fill(nullptr); }

        void reset()
        {
            voices.fill(nullptr);
        }

        void beginRelease()
        {
            for (auto *voice : voices)
            {
                if (voice)
                    voice->beginRelease();
            }
        }

        bool isActive() const
        {
            for (auto *voice : voices)
            {
                if (voice && voice->isActive())
                    return true;
            }
            return false;
        }
    };

    // Pool of mic voices
    class VoicePool
    {
    public:
        VoicePool() = default;

        void allocate(int numVoices);
        void reset();

        MicVoice *allocateVoice();

        void renderAll(juce::AudioBuffer<float> &buffer, int startSample, int numSamples,
                       bool multiOutEnabled, const std::array<float, 8> &slotGains);

    private:
        std::vector<std::unique_ptr<MicVoice>> voices;

        JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(VoicePool)
    };

} // namespace DrumEngine
