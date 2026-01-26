#pragma once

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

        void start(std::shared_ptr<SampleRef> sample, float gain, int fadeLenSamples);
        void beginRelease();
        void reset();

        void render(juce::AudioBuffer<float> &buffer, int startSample, int numSamples,
                    int outputChannel = 0);

        int slotIndex = 0; // Which slot this voice belongs to (0-7)

        bool isActive() const { return state != State::Inactive; }
        State getState() const { return state; }

    private:
        State state = State::Inactive;
        std::shared_ptr<SampleRef> currentSample;
        juce::int64 playbackFrame = 0;
        float gain = 1.0f;

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
                       int outputChannel = 0, int slotFilter = -1);

    private:
        std::vector<std::unique_ptr<MicVoice>> voices;

        JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(VoicePool)
    };

} // namespace DrumEngine
