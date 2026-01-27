#include "PluginProcessor.h"
#include "PluginEditor.h"

//==============================================================================
AudioPluginAudioProcessorEditor::AudioPluginAudioProcessorEditor(AudioPluginAudioProcessor &p)
    : AudioProcessorEditor(&p), processorRef(p)
{
    // Preset Browser Label
    presetBrowserLabel.setFont(juce::FontOptions(11.0f));
    presetBrowserLabel.setJustificationType(juce::Justification::centredRight);
    presetBrowserLabel.setColour(juce::Label::textColourId, juce::Colours::white);
    presetBrowserLabel.setText("Preset:", juce::dontSendNotification);
    addAndMakeVisible(presetBrowserLabel);

    // Preset Browser
    presetBrowser.onChange = [this]
    { onPresetSelected(); };
    addAndMakeVisible(presetBrowser);

    // Scan presets folder and populate browser
    scanPresetsFolder();

    // Load Preset Button (for manual file selection)
    loadPresetButton.setButtonText("Browse Files...");
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

    setSize(900, 550);
    setResizable(false, false);
}

AudioPluginAudioProcessorEditor::~AudioPluginAudioProcessorEditor()
{
    stopTimer();
}

//==============================================================================
void AudioPluginAudioProcessorEditor::paint(juce::Graphics &g)
{
    // Dark background
    g.fillAll(juce::Colour(0xff252525));

    auto bounds = getLocalBounds();

    // Header section
    auto headerArea = bounds.removeFromTop(100);

    // Header background gradient
    g.setGradientFill(juce::ColourGradient(
        juce::Colour(0xff3a3a3a), 0, 0,
        juce::Colour(0xff252525), 0, (float)headerArea.getHeight(),
        false));
    g.fillRect(headerArea);

    // Title
    g.setColour(juce::Colours::white);
    g.setFont(juce::FontOptions(28.0f, juce::Font::bold));
    auto titleArea = headerArea.withTrimmedTop(10).withTrimmedLeft(20);
    g.drawText("DrumEngine01", titleArea.removeFromTop(35), juce::Justification::topLeft);

    // Subtle separator line
    g.setColour(juce::Colour(0xff404040));
    g.drawLine(0, 100, (float)getWidth(), 100, 1.0f);

    // Mixer section background
    auto mixerBg = bounds.withTrimmedTop(10).withTrimmedBottom(10).withTrimmedLeft(10).withTrimmedRight(350);
    g.setColour(juce::Colour(0xff2a2a2a));
    g.fillRoundedRectangle(mixerBg.toFloat(), 8.0f);

    // Info panel background
    auto infoBg = bounds.withTrimmedTop(10).withTrimmedBottom(10).withTrimmedRight(10).removeFromRight(330);
    g.setColour(juce::Colour(0xff2a2a2a));
    g.fillRoundedRectangle(infoBg.toFloat(), 8.0f);
}

void AudioPluginAudioProcessorEditor::resized()
{
    auto bounds = getLocalBounds();

    // Header section (100px)
    auto headerArea = bounds.removeFromTop(100);

    // Preset browser and controls in header
    auto browserArea = headerArea.withTrimmedTop(45).withTrimmedLeft(20).withTrimmedRight(20);
    presetBrowserLabel.setBounds(browserArea.removeFromLeft(50));
    browserArea.removeFromLeft(5);
    presetBrowser.setBounds(browserArea.removeFromLeft(400));
    browserArea.removeFromLeft(10);
    loadPresetButton.setBounds(browserArea.removeFromLeft(100));
    browserArea.removeFromLeft(20);

    // Output mode in header
    outputModeLabel.setBounds(browserArea.removeFromLeft(50));
    browserArea.removeFromLeft(5);
    outputModeCombo.setBounds(browserArea.removeFromLeft(180));

    // Main content area
    auto contentArea = bounds.reduced(10);

    // Right panel for info (330px wide)
    auto rightPanel = contentArea.removeFromRight(330);
    rightPanel.removeFromLeft(10); // spacing

    // Status at top of info panel
    statusLabel.setBounds(rightPanel.removeFromTop(30).reduced(10, 5));
    rightPanel.removeFromTop(5);

    // Preset info
    presetInfoLabel.setBounds(rightPanel.removeFromTop(180).reduced(10));

    rightPanel.removeFromTop(10);

    // Instructions at bottom
    instructionsLabel.setBounds(rightPanel.reduced(10));

    // Mixer section (left side)
    auto mixerArea = contentArea.reduced(10);

    mixerArea.removeFromTop(10);

    // 8 channel strips
    const int slotWidth = 65;
    const int slotSpacing = 3;

    for (int i = 0; i < 8; ++i)
    {
        auto &slot = slotControls[i];
        auto slotArea = mixerArea.removeFromLeft(slotWidth);

        if (i < 7)
            mixerArea.removeFromLeft(slotSpacing);

        // Slot label at top
        slot.nameLabel.setBounds(slotArea.removeFromTop(25));

        // Volume fader
        slot.volumeSlider.setBounds(slotArea.removeFromTop(slotArea.getHeight() - 70));

        slotArea.removeFromTop(5);

        // Mute and Solo buttons
        slot.muteButton.setBounds(slotArea.removeFromTop(30));
        slotArea.removeFromTop(2);
        slot.soloButton.setBounds(slotArea.removeFromTop(30));
    }
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
        if (info.isPresetLoaded && i < info.slotNames.size())
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

void AudioPluginAudioProcessorEditor::scanPresetsFolder()
{
    presetList.clear();
    presetBrowser.clear();

    // For development, use absolute path
    juce::File kitsFolder("/Users/marian/Development/JUCE-Plugins/DrumEngine01/kits");

    if (!kitsFolder.exists() || !kitsFolder.isDirectory())
    {
        presetBrowser.addItem("No kits folder found", 1);
        presetBrowser.setEnabled(false);
        return;
    }

    presetBrowser.addItem("-- Select Preset --", 1);
    presetList.push_back({"-- Select Preset --", juce::File{}, 0, false});

    int itemId = 2;

    // Recursively scan folders
    std::function<void(const juce::File &, int)> scanFolder = [&](const juce::File &folder, int depth)
    {
        juce::Array<juce::File> subFolders;
        juce::Array<juce::File> jsonFiles;

        // Use findChildFiles instead of RangedDirectoryIterator
        auto allFiles = folder.findChildFiles(juce::File::findFilesAndDirectories, false, "*");

        for (const auto &file : allFiles)
        {
            if (file.isDirectory() && !file.getFileName().startsWith("."))
                subFolders.add(file);
            else if (file.hasFileExtension(".json"))
                jsonFiles.add(file);
        }

        // Sort folders and files alphabetically
        subFolders.sort();
        jsonFiles.sort();

        // Add folders first
        for (const auto &subFolder : subFolders)
        {
            juce::String indent = juce::String::repeatedString("  ", depth);
            juce::String displayName = indent + "\u25b6 " + subFolder.getFileName();

            presetBrowser.addItem(displayName, itemId);
            presetList.push_back({displayName, juce::File{}, depth, true});
            itemId++;

            // Recursively scan subfolder
            scanFolder(subFolder, depth + 1);
        }

        // Add JSON files in this folder
        for (const auto &jsonFile : jsonFiles)
        {
            juce::String indent = juce::String::repeatedString("  ", depth + 1);
            juce::String fileName = jsonFile.getFileNameWithoutExtension();
            juce::String displayName = indent + "\u2022 " + fileName;

            presetBrowser.addItem(displayName, itemId);
            presetList.push_back({displayName, jsonFile, depth, false});
            itemId++;
        }
    };

    scanFolder(kitsFolder, 0);

    presetBrowser.setSelectedId(1, juce::dontSendNotification);
}

void AudioPluginAudioProcessorEditor::onPresetSelected()
{
    int selectedId = presetBrowser.getSelectedId();
    if (selectedId <= 1)
        return; // "Select Preset" header selected

    loadPresetByIndex(selectedId - 1);
}

void AudioPluginAudioProcessorEditor::loadPresetByIndex(int index)
{
    if (index < 0 || index >= static_cast<int>(presetList.size()))
        return;

    const auto &entry = presetList[index];

    if (entry.isSeparator || !entry.file.existsAsFile())
        return; // Folder header, not a loadable preset

    lastLoadedPreset = entry.file.getFullPathName();

    auto result = processorRef.loadPresetFromFile(entry.file);

    if (result.wasOk())
    {
        lastStatusMessage = "✓ Loaded: " + entry.file.getFileNameWithoutExtension();
        statusIsError = false;
    }
    else
    {
        lastStatusMessage = "✗ Failed: " + result.getErrorMessage();
        statusIsError = true;
    }

    updateStatusDisplay();
}
