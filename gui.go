package vault

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/oarkflow/clipboard"
)

type GUI struct {
	app        fyne.App
	mainWindow fyne.Window
	vault      *Vault

	keyList     *widget.List
	search      *widget.Entry
	content     *widget.Entry
	keyData     []string
	fullKeyData []string // added field to hold full list of keys
	currentKey  string
}

func NewGUI(a fyne.App) *GUI {
	return &GUI{
		app:   a,
		vault: New(),
	}
}

func (g *GUI) Run() {
	g.showLogin()
	g.app.Run()
}

func (g *GUI) showLogin() {
	window := g.app.NewWindow("Vault Login")
	window.Resize(fyne.NewSize(400, 200))

	password := widget.NewPasswordEntry()

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Master Password", Widget: password},
		},
		OnSubmit: func() {
			// setup the prompt with provided master key
			g.vault.SetPrompt(func() error {
				enc, err := os.ReadFile(FilePath())
				if err != nil {
					return err
				}
				decoded, err := base64.StdEncoding.DecodeString(string(enc))
				if err != nil {
					return err
				}
				if len(decoded) < SaltSize() {
					return fmt.Errorf("corrupt vault file")
				}
				salt := decoded[:SaltSize()]
				g.vault.InitCipher([]byte(password.Text), salt)
				return g.vault.Load()
			})
			err := g.vault.PromptMaster()
			if err != nil {
				// If the vault file doesn't exist, ask user to create a new one.
				if strings.Contains(err.Error(), "no such file") {
					dialog.ShowConfirm("Vault Not Found",
						"Vault file does not exist. Create new one using this Master Password?",
						func(ok bool) {
							if ok {
								g.vault.InitCipher([]byte(password.Text), nil)
								// Create a new vault file. Assuming Save() creates it.
								if err := g.vault.Save(); err != nil {
									dialog.ShowError(err, window)
									return
								}
								window.Hide()
								g.showMain()
							}
						}, window)
					return
				}
				dialog.ShowError(err, window)
				return
			}
			window.Hide()
			g.showMain()
		},
	}
	// Allow Enter key to submit the form.
	password.OnSubmitted = func(str string) {
		form.OnSubmit()
	}

	window.SetContent(container.NewVBox(
		widget.NewLabel("Enter Master Password"),
		form,
	))
	// By default, focus the password text box.
	window.Canvas().Focus(password)
	window.Show()
}

func (g *GUI) showMain() {
	g.mainWindow = g.app.NewWindow("Secret Vault")
	g.mainWindow.Resize(fyne.NewSize(800, 600))

	toolbar := widget.NewToolbar(
		widget.NewToolbarAction(theme.ContentAddIcon(), g.addKey),
		widget.NewToolbarAction(theme.ViewRefreshIcon(), g.refreshKeys),
	)

	g.search = widget.NewEntry()
	g.search.SetPlaceHolder("Search keys...")
	g.search.OnChanged = g.filterKeys

	g.keyList = widget.NewList(
		func() int { return len(g.keyData) },
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewIcon(theme.DocumentIcon()),
				widget.NewLabel("template"),
				layout.NewSpacer(),
				widget.NewButtonWithIcon("", theme.ContentCopyIcon(), nil),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			row := obj.(*fyne.Container)
			label := row.Objects[1].(*widget.Label)
			btn := row.Objects[3].(*widget.Button)

			key := g.keyData[id]
			label.SetText(key)
			btn.OnTapped = func() {
				clipboard.WriteAll(key)
			}
		},
	)
	g.keyList.OnSelected = g.showKeyDetails

	g.content = widget.NewMultiLineEntry()
	g.content.Wrapping = fyne.TextWrapWord
	// Initially hide secret content by default.
	g.content.SetText("Secret hidden")

	copyButton := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		if g.currentKey == "" {
			dialog.ShowInformation("Info", "Select a key before copying", g.mainWindow)
			return
		}
		secret, err := g.vault.Get(g.currentKey)
		if err != nil {
			dialog.ShowError(err, g.mainWindow)
			return
		}
		clipboard.WriteAll(secret)
	})

	// Replace separate Reveal and Hide buttons with a single toggle button.
	var toggleButton *widget.Button
	toggleButton = widget.NewButton("Reveal", func() {
		if toggleButton.Text == "Reveal" {
			g.revealSecret()
			toggleButton.SetText("Hide")
		} else {
			g.content.SetText("Secret hidden")
			toggleButton.SetText("Reveal")
		}
	})

	editButton := widget.NewButtonWithIcon("Edit", theme.DocumentCreateIcon(), func() {
		g.editKey()
	})
	deleteButton := widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), func() {
		g.deleteKey()
	})

	sidebar := container.NewBorder(g.search, nil, nil, nil, g.keyList)
	detail := container.NewBorder(
		container.NewHBox(copyButton, toggleButton, editButton, deleteButton),
		nil, nil, nil,
		g.content,
	)
	split := container.NewHSplit(sidebar, detail)
	split.Offset = 0.3

	g.mainWindow.SetContent(container.NewBorder(toolbar, nil, nil, nil, split))
	g.refreshKeys()
	// When main window closes, quit the application.
	g.mainWindow.SetCloseIntercept(func() {
		g.app.Quit()
	})
	g.mainWindow.Show()
}

func (g *GUI) refreshKeys() {
	// always start from the full list, then apply filter
	g.fullKeyData = g.vault.List()
	g.filterKeys(g.search.Text)
}

func (g *GUI) filterKeys(query string) {
	if query == "" {
		g.keyData = make([]string, len(g.fullKeyData))
		copy(g.keyData, g.fullKeyData)
	} else {
		lower := strings.ToLower(query)
		filtered := make([]string, 0, len(g.fullKeyData))
		for _, key := range g.fullKeyData {
			if strings.Contains(strings.ToLower(key), lower) {
				filtered = append(filtered, key)
			}
		}
		g.keyData = filtered
	}
	g.keyList.Refresh()
}

func (g *GUI) showKeyDetails(id widget.ListItemID) {
	g.currentKey = g.keyData[id]
	// Do not show the actual secret by default.
	g.content.SetText("Secret hidden")
}

// New: revealSecret gets and displays the secret for currentKey.
func (g *GUI) revealSecret() {
	secret, err := g.vault.Get(g.currentKey)
	if err != nil {
		dialog.ShowError(err, g.mainWindow)
		return
	}
	g.content.SetText(secret)
}

func (g *GUI) addKey() {
	// create the entries *before* showing the form
	keyEntry := widget.NewEntry()
	valEntry := widget.NewMultiLineEntry()

	// Updated: use dialog.NewForm instead of dialog.ShowForm
	formDialog := dialog.NewForm("Add New Secret", "Save", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Key", keyEntry),
			widget.NewFormItem("Value", valEntry),
		},
		func(ok bool) {
			if !ok {
				return
			}
			if err := g.vault.Set(keyEntry.Text, valEntry.Text); err != nil {
				dialog.ShowError(err, g.mainWindow)
				return
			}
			g.refreshKeys()
		}, g.mainWindow)
	formDialog.Show()
}

func (g *GUI) editKey() {
	if g.currentKey == "" {
		return
	}
	valEntry := widget.NewMultiLineEntry()
	valEntry.SetText(g.content.Text)

	// Updated: use dialog.NewForm instead of dialog.ShowForm
	formDialog := dialog.NewForm("Edit Secret", "Save", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Value", valEntry),
		},
		func(ok bool) {
			if !ok {
				return
			}
			if err := g.vault.Set(g.currentKey, valEntry.Text); err != nil {
				dialog.ShowError(err, g.mainWindow)
				return
			}
			g.refreshKeys()
		}, g.mainWindow)
	formDialog.Show()
}

func (g *GUI) deleteKey() {
	if g.currentKey == "" {
		return
	}
	dialog.ShowConfirm("Delete Secret",
		"Delete \""+g.currentKey+"\"?",
		func(ok bool) {
			if !ok {
				return
			}
			if err := g.vault.Delete(g.currentKey); err != nil {
				dialog.ShowError(err, g.mainWindow)
				return
			}
			g.currentKey = ""
			g.content.SetText("")
			g.refreshKeys()
		}, g.mainWindow)
}

func RunGUI() {
	application := app.New()
	gui := NewGUI(application)
	gui.Run()
}
