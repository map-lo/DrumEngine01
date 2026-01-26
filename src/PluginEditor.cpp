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
    presetInfoLabel.setFont(juce::FontOptions(10.0f));
    presetInfoLabel.setJustificationType(juce::Justification::topLeft);
    presetInfoLabel.setColour(juce::Label::textColourId, juce::Colours::white);
    addAndMakeVisible(presetInfoLabel);

    // Instructions Label
    instructionsLabel.setFont(juce::FontOptions(10.0f));
    instructionsLabel.setJustificationType(juce::Justification::centred);
    instructionsLabel.setColour(juce::Label::textColourId, juce::Colours::grey);
    instructionsLabel.setText(
        "Trigger with MIDI Note (default: 38/D1) | Solo: only that slot plays",
        juce::dontSendNotification);
    addAndMakeVisible(instructionsLabel);

    // Output mode selector
    outputModeLabel.setFont(juce::FontOptions(11.0f));
    outputModeLabel.setJustificationType(juce::Justification::centredRight);
    outputModeLabel.setColour(juce::Label::textColourId, juce::Colours::white);
    outputModeLabel.setText("Output:", juce::dontSendNotification);
    addAndMakeVisible(outputModeLabel);

    outputModeCombo.addItem("Stereo", 1);
    outputModeCombo.addItem("Multi-Out (8x Stereo)", 2);
    outputModeCombo.setSelectedId(1, juce::dontSendNotification);
    outputModeCombo.onChange = [this]
    { onOutputModeChanged(); };
    addAndMakeVisible(outputModeCombo);

    // Setup slot controls
    for (int i = 0; i < 8; ++i)
    {
        auto &slot = slotControls[i];

        // Slot name label
        slot.nameLabel.setFont(juce::FontOptions(11.0f, juce::Font::bold));
        slot.nameLabel.setJustificationType(juce::Justification::centred);
        slot.nameLabel.setColour(juce::Label::textColourId, juce::Colours::white);
        slot.nameLabel.setText(juce::String(i + 1), juce::dontSendNotification);
        addAndMakeVisible(slot.nameLabel);

        // Volume slider (vertical)
        slot.volumeSlider.setSliderStyle(juce::Slider::LinearVertical);
        slot.volumeSlider.setRange(0.0, 1.0, 0.01);
        slot.volumeSlider.setValue(1.0);
        slot.volumeSlider.setTextBoxStyle(juce::Slider::NoTextBox, false, 0, 0);
        slot.volumeSlider.onValueChange = [this, i]
        { onSlotVolumeChanged(i); };
        addAndMakeVisible(slot.volumeSlider);

        // Mute button
        slot.muteButton.setButtonText("M");
        slot.muteButton.setClickingTogglesState(true);
        slot.muteButton.onClick = [this, i]
        { onSlotMuteClicked(i); };
        addAndMakeVisible(slot.muteButton);

        // Solo button
        slot.soloButton.setButtonText("S");
        slot.soloButton.setClickingTogglesState(true);
        slot.soloButton.onClick = [this, i]
        { onSlotSoloClicked(i); };
        addAndMakeVisible(slot.soloButton);
    }

    // Start timer to update status
    startTimer(100); // Update every 100ms

    // Initial status update
    updateStatusDisplay();
    updateSlotControls();

    setSize(900, 500);
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

    auto area = bounds.reduced(10);

    // Top section: load button and status
    auto topSection = area.removeFromTop(80);
    loadPresetButton.setBounds(topSection.removeFromTop(35).reduced(150, 0));
    topSection.removeFromTop(5);
    statusLabel.setBounds(topSection.removeFromTop(25));

    // Output mode selector
    auto outputModeArea = topSection.removeFromTop(25);
    outputModeLabel.setBounds(outputModeArea.removeFromLeft(60));
    outputModeCombo.setBounds(outputModeArea.removeFromLeft(200));

    area.removeFromTop(10);

    // Left side: slot controls
    auto leftPanel = area.removeFromLeft(600);

    // Slot mixer section
    const int slotWidth = 70;
    const int slotSpacing = 5;

    for (int i = 0; i < 8; ++i)
    {
        auto &slot = slotControls[i];
        auto slotArea = leftPanel.removeFromLeft(slotWidth);

        // Name label at top
        slot.nameLabel.setBounds(slotArea.removeFromTop(20));

        // Volume slider (most of the height)
        slot.volumeSlider.setBounds(slotArea.removeFromTop(slotArea.getHeight() - 65));

        slotArea.removeFromTop(5);

        // Mute and Solo buttons at bottom
        slot.muteButton.setBounds(slotArea.removeFromTop(28));
        slotArea.removeFromTop(2);
        slot.soloButton.setBounds(slotArea.removeFromTop(28));

        leftPanel.removeFromLeft(slotSpacing);
    }

    // Right side: preset info and instructions
    area.removeFromLeft(10);
    presetInfoLabel.setBounds(area.removeFromTop(area.getHeight() - 35));
    area.removeFromTop(5);
    instructionsLabel.setBounds(area);
}

void AudioPluginAudioProcessorEditor::timerCallback()
{
    updateStatusDisplay();
    updateSlotControls();
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

void AudioPluginAudioProcessorEditor::updateSlotControls()
{
    auto info = processorRef.getPresetInfo();

    for (int i = 0; i < 8; ++i)
    {
        auto &slot = slotControls[i];

        // Determine if this slot is active in the current preset
        bool isActive = info.isPresetLoaded && i < info.slotCount && info.activeSlots[i];
        slot.isActive = isActive;

        // Update visual appearance based on active state
        float alpha = isActive ? 1.0f : 0.3f;

        slot.nameLabel.setAlpha(alpha);
        slot.volumeSlider.setAlpha(alpha);
        slot.muteButton.setAlpha(alpha);
        slot.soloButton.setAlpha(alpha);

        // Update label text
        if (isActive && i < info.slotNames.size())
        {
            slot.nameLabel.setText(info.slotNames[i], juce::dontSendNotification);
        }
        else
        {
            slot.nameLabel.setText(juce::String(i + 1), juce::dontSendNotification);
        }

        // Disable inactive slots
        slot.volumeSlider.setEnabled(isActive);
        slot.muteButton.setEnabled(isActive);
        slot.soloButton.setEnabled(isActive);

        // Update button states from processor
        auto slotState = processorRef.getSlotState(i);
        slot.muteButton.setToggleState(slotState.muted, juce::dontSendNotification);
        slot.soloButton.setToggleState(slotState.soloed, juce::dontSendNotification);

        // Update button colors
        slot.muteButton.setColour(juce::TextButton::buttonOnColourId, juce::Colours::red);
        slot.soloButton.setColour(juce::TextButton::buttonOnColourId, juce::Colours::yellow);

        // Sync slider value (without triggering callback)
        if (std::abs(slot.volumeSlider.getValue() - slotState.volume) > 0.001)
        {
            slot.volumeSlider.setValue(slotState.volume, juce::dontSendNotification);
        }
    }
}

void AudioPluginAudioProcessorEditor::onSlotVolumeChanged(int slotIndex)
{
    if (slotIndex >= 0 && slotIndex < 8)
    {
        float volume = static_cast<float>(slotControls[slotIndex].volumeSlider.getValue());
        processorRef.setSlotVolume(slotIndex, volume);
    }
}

void AudioPluginAudioProcessorEditor::onSlotMuteClicked(int slotIndex)
{
    if (slotIndex >= 0 && slotIndex < 8)
    {
        bool muted = slotControls[slotIndex].muteButton.getToggleState();
        processorRef.setSlotMuted(slotIndex, muted);
    }
}

void AudioPluginAudioProcessorEditor::onSlotSoloClicked(int slotIndex)
{
    if (slotIndex >= 0 && slotIndex < 8)
    {
        bool soloed = slotControls[slotIndex].soloButton.getToggleState();
        processorRef.setSlotSoloed(slotIndex, soloed);
    }
}

void AudioPluginAudioProcessorEditor::onOutputModeChanged()
{
    int selectedId = outputModeCombo.getSelectedId();
    auto newMode = (selectedId == 2) ? AudioPluginAudioProcessor::OutputMode::MultiOut
                                     : AudioPluginAudioProcessor::OutputMode::Stereo;

    processorRef.setOutputMode(newMode);

    // Update status to inform user
    if (newMode == AudioPluginAudioProcessor::OutputMode::MultiOut)
    {
        statusLabel.setText("Multi-Out: Mix\u21921-2, Slot1\u21923-4, Slot2\u21925-6, etc.", juce::dontSendNotification);
        statusLabel.setColour(juce::Label::textColourId, juce::Colours::orange);
    }
    else
    {
        statusLabel.setText("Stereo mode: Mix on outputs 1-2", juce::dontSendNotification);
        statusLabel.setColour(juce::Label::textColourId, juce::Colours::lightblue);
    }
}
