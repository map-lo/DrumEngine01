#include "PluginProcessor.h"
#include "PluginEditor.h"

//==============================================================================
AudioPluginAudioProcessorEditor::AudioPluginAudioProcessorEditor(AudioPluginAudioProcessor &p)
    : AudioProcessorEditor(&p), processorRef(p)
{
    // Load Preset Button
    loadPresetButton.setButtonText("Load Preset...");
    loadPresetButton.onClick = [this]
    { loadPresetButtonClicked(); };
    addAndMakeVisible(loadPresetButton);

    // Status Label
    statusLabel.setFont(juce::FontOptions(14.0f, juce::Font::bold));
    statusLabel.setJustificationType(juce::Justification::centred);
    statusLabel.setColour(juce::Label::textColourId, juce::Colours::lightgreen);
    addAndMakeVisible(statusLabel);

    // Preset Info Label
    presetInfoLabel.setFont(juce::FontOptions(12.0f));
    presetInfoLabel.setJustificationType(juce::Justification::topLeft);
    presetInfoLabel.setColour(juce::Label::textColourId, juce::Colours::white);
    addAndMakeVisible(presetInfoLabel);

    // Instructions Label
    instructionsLabel.setFont(juce::FontOptions(11.0f));
    instructionsLabel.setJustificationType(juce::Justification::centred);
    instructionsLabel.setColour(juce::Label::textColourId, juce::Colours::grey);
    instructionsLabel.setText(
        "Trigger with MIDI Note (default: 38/D1)\n"
        "Velocity: 1-127 selects velocity layer\n"
        "Max 3 concurrent hits, RR cycles per layer",
        juce::dontSendNotification);
    addAndMakeVisible(instructionsLabel);

    // Start timer to update status
    startTimer(100); // Update every 100ms

    // Initial status update
    updateStatusDisplay();

    setSize(500, 400);
}

AudioPluginAudioProcessorEditor::~AudioPluginAudioProcessorEditor()
{
    stopTimer();
}

//==============================================================================
void AudioPluginAudioProcessorEditor::paint(juce::Graphics &g)
{
    // Background gradient
    g.fillAll(juce::Colour(0xff1e1e1e));

    auto bounds = getLocalBounds();

    // Header background
    auto headerArea = bounds.removeFromTop(60);
    g.setGradientFill(juce::ColourGradient(
        juce::Colour(0xff2d2d30), 0, 0,
        juce::Colour(0xff1e1e1e), 0, headerArea.getHeight(),
        false));
    g.fillRect(headerArea);

    // Title
    g.setColour(juce::Colours::white);
    g.setFont(juce::FontOptions(24.0f, juce::Font::bold));
    g.drawText("DrumEngine01", headerArea.reduced(10), juce::Justification::centredLeft);

    // Separator line
    g.setColour(juce::Colour(0xff3e3e42));
    g.drawLine(10, 60, getWidth() - 10, 60, 2.0f);
}

void AudioPluginAudioProcessorEditor::resized()
{
    auto bounds = getLocalBounds();
    bounds.removeFromTop(70); // Skip header

    auto area = bounds.reduced(20);

    // Load button at top
    loadPresetButton.setBounds(area.removeFromTop(40).reduced(50, 0));
    area.removeFromTop(10);

    // Status label
    statusLabel.setBounds(area.removeFromTop(30));
    area.removeFromTop(10);

    // Preset info (flexible height)
    auto infoHeight = juce::jmin(150, area.getHeight() - 80);
    presetInfoLabel.setBounds(area.removeFromTop(infoHeight));

    // Instructions at bottom
    area.removeFromTop(10);
    instructionsLabel.setBounds(area.removeFromTop(70));
}

void AudioPluginAudioProcessorEditor::timerCallback()
{
    updateStatusDisplay();
}

void AudioPluginAudioProcessorEditor::loadPresetButtonClicked()
{
    auto chooserFlags = juce::FileBrowserComponent::openMode | juce::FileBrowserComponent::canSelectFiles;

    fileChooser = std::make_unique<juce::FileChooser>("Select Preset JSON File",
                                                      juce::File::getSpecialLocation(juce::File::userHomeDirectory),
                                                      "*.json");

    fileChooser->launchAsync(chooserFlags, [this](const juce::FileChooser &chooser)
                             {
        auto file = chooser.getResult();
        
        if (file == juce::File{})
            return;
        
        lastLoadedPreset = file.getFullPathName();
        
        // Attempt to load
        auto result = processorRef.loadPresetFromFile(file);
        
        if (result.wasOk())
        {
            lastStatusMessage = "✓ Preset loaded successfully!";
            statusIsError = false;
        }
        else
        {
            lastStatusMessage = "✗ Failed: " + result.getErrorMessage();
            statusIsError = true;
        }
        
        updateStatusDisplay(); });
}

void AudioPluginAudioProcessorEditor::updateStatusDisplay()
{
    auto info = processorRef.getPresetInfo();

    if (info.isPresetLoaded)
    {
        // Update preset info
        juce::String infoText;
        infoText << "Preset: " << info.presetName << "\n";
        infoText << "Type: " << info.instrumentType << "\n";
        infoText << "Fixed MIDI Note: " << juce::String(info.fixedMidiNote) << "\n";
        infoText << "Slots: " << juce::String(info.slotCount) << "\n";
        infoText << "Velocity Layers: " << juce::String(info.layerCount) << "\n";

        if (info.slotNames.size() > 0)
        {
            infoText << "\nMic Slots:\n";
            for (int i = 0; i < info.slotNames.size(); ++i)
                infoText << "  " << juce::String(i + 1) << ": " << info.slotNames[i] << "\n";
        }

        presetInfoLabel.setText(infoText, juce::dontSendNotification);

        // Update status if no manual message
        if (lastStatusMessage.isEmpty())
        {
            statusLabel.setText("Ready - Preset Loaded", juce::dontSendNotification);
            statusLabel.setColour(juce::Label::textColourId, juce::Colours::lightgreen);
        }
    }
    else
    {
        presetInfoLabel.setText("No preset loaded\n\nClick 'Load Preset...' to load a JSON preset file",
                                juce::dontSendNotification);

        if (lastStatusMessage.isEmpty())
        {
            statusLabel.setText("No Preset - Click Load Button", juce::dontSendNotification);
            statusLabel.setColour(juce::Label::textColourId, juce::Colours::orange);
        }
    }

    // Show any manual status message
    if (lastStatusMessage.isNotEmpty())
    {
        statusLabel.setText(lastStatusMessage, juce::dontSendNotification);
        statusLabel.setColour(juce::Label::textColourId,
                              statusIsError ? juce::Colours::red : juce::Colours::lightgreen);
    }
}
