#pragma once

#include <juce_core/juce_core.h>
#include <juce_audio_processors/juce_audio_processors.h>
#include <unordered_map>

namespace DrumEngine
{
    /**
     * Utility functions for MIDI note handling, including:
     * - Default MIDI notes per instrument type (General MIDI standard)
     * - Conversion between MIDI note numbers and note names (e.g., 36 <-> "C1")
     * - DAW-specific octave offset detection for consistent note naming
     */
    class MidiNoteUtils
    {
    public:
        /**
         * Get the octave offset for the current host DAW.
         * Different DAWs use different octave numbering conventions:
         * - Ableton Live, Logic Pro: C3 = MIDI 60 (offset = -2)
         * - Pro Tools, Cubase, FL Studio, Reaper, most others: C4 = MIDI 60 (offset = -1)
         * @return The octave offset to use for note name conversion
         */
        static int getHostOctaveOffset()
        {
            static int cachedOffset = -1;
            static bool offsetCached = false;

            if (offsetCached)
                return cachedOffset;

            juce::PluginHostType hostType;

            // Ableton Live and Logic Pro use C3 = MIDI 60 (Yamaha convention)
            if (hostType.isAbletonLive() || hostType.isLogic())
            {
                cachedOffset = -2;
            }
            // Most other DAWs use C4 = MIDI 60 (Roland convention)
            else
            {
                cachedOffset = -1;
            }

            offsetCached = true;
            return cachedOffset;
        }

        /**
         * Get the default MIDI note for an instrument type.
         * Based on General MIDI drum mapping standard.
         * @param instrumentType The instrument type string (e.g., "kick", "snare", "tom")
         * @return The MIDI note number (0-127), or 38 (snare) as fallback
         */
        static int getDefaultMidiNoteForInstrument(const juce::String &instrumentType)
        {
            static const std::unordered_map<juce::String, int> defaultNotes = {
                {"kick", 36},       // Bass Drum / Kick
                {"snare", 38},      // Snare Drum
                {"tom", 45},        // Low Tom (default for generic "tom")
                {"lowtom", 45},     // Low Tom
                {"midtom", 47},     // Mid Tom
                {"hightom", 50},    // High Tom
                {"cymbal", 49},     // Crash Cymbal (default for generic "cymbal")
                {"crash", 49},      // Crash Cymbal
                {"ride", 51},       // Ride Cymbal
                {"hihat", 42},      // Closed Hi-Hat
                {"openhihat", 46},  // Open Hi-Hat
                {"closedhihat", 42} // Closed Hi-Hat
            };

            auto lower = instrumentType.toLowerCase();
            auto it = defaultNotes.find(lower);
            if (it != defaultNotes.end())
            {
                return it->second;
            }

            // Default to snare if instrument type not recognized
            return 38;
        }

        /**
         * Convert a MIDI note number to a note name (e.g., 36 -> "C1")
         * Uses the host DAW's octave convention automatically.
         * @param noteNumber MIDI note number (0-127)
         * @return Note name string (e.g., "C1", "D#2")
         */
        static juce::String midiNoteToNoteName(int noteNumber)
        {
            if (noteNumber < 0 || noteNumber > 127)
                return "Invalid";

            static const char *noteNames[] = {"C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B"};

            int octave = (noteNumber / 12) + getHostOctaveOffset();
            int note = noteNumber % 12;

            return juce::String(noteNames[note]) + juce::String(octave);
        }

        /**
         * Convert a note name to a MIDI note number (e.g., "C1" -> 36)
         * Uses the host DAW's octave convention automatically.
         * @param noteName Note name string (e.g., "C1", "D#2")
         * @return MIDI note number (0-127), or -1 if invalid
         */
        static int noteNameToMidiNote(const juce::String &noteName)
        {
            if (noteName.isEmpty())
                return -1;

            static const std::unordered_map<juce::String, int> noteValues = {
                {"C", 0}, {"C#", 1}, {"DB", 1}, {"D", 2}, {"D#", 3}, {"EB", 3}, {"E", 4}, {"F", 5}, {"F#", 6}, {"GB", 6}, {"G", 7}, {"G#", 8}, {"AB", 8}, {"A", 9}, {"A#", 10}, {"BB", 10}, {"B", 11}};

            // Parse the note name
            juce::String upper = noteName.toUpperCase().trim();

            // Find where the octave number starts
            int octaveStart = -1;
            for (int i = 0; i < upper.length(); ++i)
            {
                if (juce::CharacterFunctions::isDigit(upper[i]) || upper[i] == '-')
                {
                    octaveStart = i;
                    break;
                }
            }

            if (octaveStart == -1)
                return -1;

            juce::String noteStr = upper.substring(0, octaveStart);
            juce::String octaveStr = upper.substring(octaveStart);

            auto it = noteValues.find(noteStr);
            if (it == noteValues.end())
                return -1;

            int noteValue = it->second;
            int octave = octaveStr.getIntValue();

            // Apply host-specific octave offset
            int midiNote = (octave - getHostOctaveOffset()) * 12 + noteValue;

            if (midiNote < 0 || midiNote > 127)
                return -1;

            return midiNote;
        }
    };

} // namespace DrumEngine
