package main

import (
	"fmt"
	"log"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket/pcap"
)

var selectedItemStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("170"))

type interfaceSelectorModel struct {
	choices  []pcap.Interface // Items on the to-do list
	cursor   int              // Which to-do list item our cursor is pointing at
	selected string           // Which to-do list item are we selected?
	quitting bool
}

func newInterfaceSelectorModel() interfaceSelectorModel {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Error finding devices: %v", err)
	}

	var choices []pcap.Interface
	for _, device := range devices {
		// Only show interfaces that are up and not loopback, and have at least one address
		if len(device.Addresses) > 0 {
			choices = append(choices, device)
		}
	}

	return interfaceSelectorModel{
		choices: choices,
	}
}

func (m interfaceSelectorModel) Init() tea.Cmd {
	return nil
}

func (m interfaceSelectorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.quitting = true
			return m, tea.Quit

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}

		case "down", "j":
			if m.cursor < len(m.choices)-1 {
				m.cursor++
			}

		case "enter":
			m.selected = m.choices[m.cursor].Name
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m interfaceSelectorModel) View() string {
	if m.quitting {
		return ""
	}

	s := `Select a network interface:

`
	for i, choice := range m.choices {
		description := choice.Description
		if description == "" {
			description = "No description available"
		}

		line := fmt.Sprintf("[%s] %s", choice.Name, description)

		cursor := " " // no cursor
		if m.cursor == i {
			cursor = ">" // cursor!
			line = selectedItemStyle.Render(line)
		}

		s += fmt.Sprintf("%s %s\n", cursor, line)
	}

	s += "\n(press q to quit, enter to select)"
	return s
}

func selectInterface() (string, error) {
	p := tea.NewProgram(newInterfaceSelectorModel())
	m, err := p.Run()
	if err != nil {
		return "", fmt.Errorf("error running interface selector: %v", err)
	}

	selectedModel := m.(interfaceSelectorModel)
	if selectedModel.selected == "" && !selectedModel.quitting {
		return "", fmt.Errorf("no interface selected")
	}

	return selectedModel.selected, nil
}
