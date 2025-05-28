package secretr

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/oarkflow/clipboard"
)

//go:embed assets/secretr.png
var defaultIcon []byte

type GUI struct {
	app            fyne.App
	mainWindow     fyne.Window
	secretr        *Secretr
	keyList        *widget.List
	search         *widget.Entry
	content        *widget.Entry
	keyData        []string
	fullKeyData    []string
	currentKey     string
	filterDropdown *widget.Select
}

func NewGUI(a fyne.App) *GUI {
	return &GUI{
		app:     a,
		secretr: New(),
	}
}

func (g *GUI) Run() {
	g.showLogin()
	g.app.Run()
}

func showConfirmWithEnter(parent fyne.Window, title string, message string, callback func(ok bool)) {
	oldHandler := parent.Canvas().OnTypedKey()
	confirmDialog := dialog.NewConfirm(title, message, func(ok bool) {
		parent.Canvas().SetOnTypedKey(oldHandler)
		callback(ok)
	}, parent)
	confirmDialog.Show()
	parent.Canvas().SetOnTypedKey(func(key *fyne.KeyEvent) {
		if key.Name == fyne.KeyReturn {
			confirmDialog.Hide()
			parent.Canvas().SetOnTypedKey(oldHandler)
			callback(true)
		}
	})
}

func (g *GUI) showLogin() {
	window := g.app.NewWindow("Secretr Login")
	window.Resize(fyne.NewSize(400, 200))
	// Center the window on screen.
	window.CenterOnScreen()
	password := widget.NewPasswordEntry()
	{
		// Increase input box width.
		size := password.MinSize()
		size.Width = 300
		password.Resize(size)
	}
	form := &widget.Form{
		Items: []*widget.FormItem{
			{Widget: password},
		},
		OnSubmit: func() {
			g.secretr.SetPrompt(func() error {
				enc, err := os.ReadFile(FilePath())
				if err != nil {
					return err
				}
				decoded, err := base64.StdEncoding.DecodeString(string(enc))
				if err != nil {
					return err
				}
				if len(decoded) < SaltSize() {
					return fmt.Errorf("corrupt secretr file")
				}
				salt := decoded[:SaltSize()]
				g.secretr.InitCipher([]byte(password.Text), salt)
				return g.secretr.Load()
			})
			err := g.secretr.PromptMaster()
			if err != nil {
				if strings.Contains(err.Error(), "no such file") {
					showConfirmWithEnter(window, "Secretr Not Found",
						"Secretr file does not exist. Create new one using this Master Password?",
						func(ok bool) {
							if ok {
								g.secretr.InitCipher([]byte(password.Text), nil)
								if err := g.secretr.Save(); err != nil {
									dialog.ShowError(err, window)
									return
								}
								window.Hide()
								g.showMain()
							}
						})
					return
				}
				dialog.ShowError(err, window)
				return
			}
			window.Hide()
			g.showMain()
		},
	}
	password.OnSubmitted = func(str string) {
		form.OnSubmit()
	}
	window.SetContent(container.NewCenter(
		container.NewVBox(
			widget.NewLabelWithStyle("Enter Master Password", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
			form,
		),
	))
	window.Canvas().Focus(password)
	window.Show()
}

func (g *GUI) showMain() {
	g.mainWindow = g.app.NewWindow("Secret Manager")
	g.mainWindow.Resize(fyne.NewSize(800, 600))
	// Center the window on screen.
	g.mainWindow.CenterOnScreen()
	toolbar := widget.NewToolbar(
		widget.NewToolbarAction(theme.ContentAddIcon(), g.addKey),             // Add Key
		widget.NewToolbarAction(theme.ViewRefreshIcon(), g.refreshKeys),       // Refresh Keys
		widget.NewToolbarAction(theme.AccountIcon(), g.addGroup),              // Add Group
		widget.NewToolbarAction(theme.DocumentSaveIcon(), g.generateSecret),   // Generate Secret
		widget.NewToolbarAction(theme.AccountIcon(), g.generateSSHKey),        // Generate SSH Key
		widget.NewToolbarAction(theme.FileImageIcon(), g.generateCertificate), // Generate Certificate
		widget.NewToolbarAction(theme.MailSendIcon(), g.signData),             // Sign Data
		widget.NewToolbarAction(theme.MailReplyIcon(), g.verifySignature),     // Verify Signature
		widget.NewToolbarAction(theme.DocumentIcon(), g.generateHash),         // Generate Hash
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
				if strings.HasPrefix(key, "ssh-key:") {
					name := strings.TrimPrefix(key, "ssh-key:")
					_ = clipboard.WriteAll(g.secretr.Store().SSHKeys[name])
				} else if strings.HasPrefix(key, "certificate:") {
					name := strings.TrimPrefix(key, "certificate:")
					_ = clipboard.WriteAll(g.secretr.Store().Certificates[name])
				} else {
					_ = clipboard.WriteAll(key)
				}
			}
		},
	)
	g.keyList.OnSelected = g.showKeyDetails
	g.content = widget.NewMultiLineEntry()
	g.content.Wrapping = fyne.TextWrapWord
	g.content.SetText("Secret hidden")
	copyButton := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		if g.currentKey == "" {
			dialog.ShowInformation("Info", "Select a key before copying", g.mainWindow)
			return
		}
		secret, err := g.secretr.Get(g.currentKey)
		if err != nil {
			dialog.ShowError(err, g.mainWindow)
			return
		}
		_ = clipboard.WriteAll(secret)
	})
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
	g.filterDropdown = widget.NewSelect([]string{"Secret Keys", "SSH Keys", "Certificates"}, func(selected string) {
		g.refreshKeys()
	})
	g.filterDropdown.SetSelected("Secret Keys") // Default selection
	sidebar := container.NewBorder(
		container.NewVBox(g.filterDropdown, g.search),
		nil, nil, nil, g.keyList,
	)
	detail := container.NewBorder(
		container.NewHBox(copyButton, toggleButton, editButton, deleteButton),
		nil, nil, nil,
		g.content,
	)
	split := container.NewHSplit(sidebar, detail)
	split.Offset = 0.3
	g.mainWindow.SetContent(container.NewBorder(toolbar, nil, nil, nil, container.NewPadded(split)))
	g.refreshKeys()
	g.mainWindow.SetCloseIntercept(func() {
		g.app.Quit()
	})
	g.mainWindow.Show()
}

func (g *GUI) refreshKeys() {
	switch g.filterDropdown.Selected {
	case "SSH Keys":
		g.fullKeyData = g.listSSHKeys()
	case "Certificates":
		g.fullKeyData = g.listCertificates()
	default: // "Secret Keys"
		g.fullKeyData = g.secretr.List()
	}
	g.filterKeys(g.search.Text)
}

func (g *GUI) listSSHKeys() []string {
	var keys []string
	for name := range g.secretr.Store().SSHKeys {
		keys = append(keys, "ssh-key:"+name)
	}
	return keys
}

func (g *GUI) listCertificates() []string {
	var keys []string
	for name := range g.secretr.Store().Certificates {
		keys = append(keys, "certificate:"+name)
	}
	return keys
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
	key := g.keyData[id]
	if strings.HasPrefix(key, "ssh-key:") || strings.HasPrefix(key, "certificate:") {
		g.content.SetText("Secret hidden")
		g.currentKey = key
	} else {
		g.currentKey = key
		g.content.SetText("Secret hidden")
	}
}

func (g *GUI) revealSecret() {
	if strings.HasPrefix(g.currentKey, "ssh-key:") {
		name := strings.TrimPrefix(g.currentKey, "ssh-key:")
		g.content.SetText(g.secretr.Store().SSHKeys[name])
	} else if strings.HasPrefix(g.currentKey, "certificate:") {
		name := strings.TrimPrefix(g.currentKey, "certificate:")
		g.content.SetText(g.secretr.Store().Certificates[name])
	} else {
		secret, err := g.secretr.Get(g.currentKey)
		if err != nil {
			dialog.ShowError(err, g.mainWindow)
			return
		}
		g.content.SetText(secret)
	}
}

func (g *GUI) addKey() {
	keyEntry := widget.NewEntry()
	valEntry := widget.NewMultiLineEntry()
	formDialog := dialog.NewForm("Add New Secret", "Save", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Key", keyEntry),
			widget.NewFormItem("Value", valEntry),
		},
		func(ok bool) {
			if !ok {
				return
			}
			if err := g.secretr.Set(keyEntry.Text, valEntry.Text); err != nil {
				dialog.ShowError(err, g.mainWindow)
				return
			}
			g.refreshKeys()
		}, g.mainWindow)
	formDialog.Show()
	g.mainWindow.Canvas().Focus(keyEntry)
}

func (g *GUI) editKey() {
	if g.currentKey == "" {
		return
	}
	valEntry := widget.NewMultiLineEntry()
	if strings.HasPrefix(g.currentKey, "ssh-key:") {
		name := strings.TrimPrefix(g.currentKey, "ssh-key:")
		valEntry.SetText(g.secretr.Store().SSHKeys[name])
	} else if strings.HasPrefix(g.currentKey, "certificate:") {
		name := strings.TrimPrefix(g.currentKey, "certificate:")
		valEntry.SetText(g.secretr.Store().Certificates[name])
	} else {
		valEntry.SetText(g.content.Text)
	}
	formDialog := dialog.NewForm("Edit Secret", "Save", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Value", valEntry),
		},
		func(ok bool) {
			if !ok {
				return
			}
			if strings.HasPrefix(g.currentKey, "ssh-key:") {
				name := strings.TrimPrefix(g.currentKey, "ssh-key:")
				g.secretr.Store().SSHKeys[name] = valEntry.Text
			} else if strings.HasPrefix(g.currentKey, "certificate:") {
				name := strings.TrimPrefix(g.currentKey, "certificate:")
				g.secretr.Store().Certificates[name] = valEntry.Text
			} else {
				if err := g.secretr.Set(g.currentKey, valEntry.Text); err != nil {
					dialog.ShowError(err, g.mainWindow)
					return
				}
			}
			g.refreshKeys()
		}, g.mainWindow)
	formDialog.Show()
	g.mainWindow.Canvas().Focus(valEntry)
}

func (g *GUI) deleteKey() {
	if g.currentKey == "" {
		return
	}
	if strings.HasPrefix(g.currentKey, "ssh-key:") {
		name := strings.TrimPrefix(g.currentKey, "ssh-key:")
		delete(g.secretr.Store().SSHKeys, name)
		g.refreshKeys()
		return
	}
	if strings.HasPrefix(g.currentKey, "certificate:") {
		name := strings.TrimPrefix(g.currentKey, "certificate:")
		delete(g.secretr.Store().Certificates, name)
		g.refreshKeys()
		return
	}
	showConfirmWithEnter(g.mainWindow, "Delete Secret",
		"Delete \""+g.currentKey+"\"?",
		func(ok bool) {
			if !ok {
				return
			}
			if err := g.secretr.Delete(g.currentKey); err != nil {
				dialog.ShowError(err, g.mainWindow)
				return
			}
			g.currentKey = ""
			g.content.SetText("")
			g.refreshKeys()
		})
}

func (g *GUI) addGroup() {
	appEntry := widget.NewEntry()
	nsEntry := widget.NewEntry()
	formDialog := dialog.NewForm("Add New Group", "Create", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Application", appEntry),
			widget.NewFormItem("Namespace", nsEntry),
		},
		func(ok bool) {
			if !ok {
				return
			}
			if err := g.secretr.AddGroup(appEntry.Text, nsEntry.Text); err != nil {
				dialog.ShowError(err, g.mainWindow)
				return
			}
			g.refreshKeys()
		}, g.mainWindow)
	formDialog.Show()
	g.mainWindow.Canvas().Focus(appEntry)
}

func (g *GUI) generateSecret() {
	appEntry := widget.NewEntry()
	nsEntry := widget.NewEntry()
	durationEntry := widget.NewEntry()
	formDialog := dialog.NewForm("Generate Unique Secret", "Generate", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Application", appEntry),
			widget.NewFormItem("Namespace", nsEntry),
			widget.NewFormItem("Duration (seconds)", durationEntry),
		},
		func(ok bool) {
			if !ok {
				return
			}
			duration, err := time.ParseDuration(durationEntry.Text + "s")
			if err != nil {
				dialog.ShowError(err, g.mainWindow)
				return
			}
			secret, err := g.secretr.GenerateUniqueSecret(appEntry.Text, nsEntry.Text, duration)
			if err != nil {
				dialog.ShowError(err, g.mainWindow)
				return
			}
			dialog.ShowInformation("Secret Generated", secret, g.mainWindow)
		}, g.mainWindow)
	formDialog.Show()
	g.mainWindow.Canvas().Focus(appEntry)
}

func (g *GUI) generateSSHKey() {
	nameEntry := widget.NewEntry()
	formDialog := dialog.NewForm("Generate SSH Key", "Generate", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Key Name", nameEntry),
		},
		func(ok bool) {
			if !ok {
				return
			}
			if err := g.secretr.GenerateSSHKey(nameEntry.Text); err != nil {
				dialog.ShowError(err, g.mainWindow)
				return
			}
			dialog.ShowInformation("SSH Key Generated", "SSH Key successfully generated.", g.mainWindow)
		}, g.mainWindow)
	formDialog.Show()
	g.mainWindow.Canvas().Focus(nameEntry)
}

func (g *GUI) generateCertificate() {
	nameEntry := widget.NewEntry()
	durationEntry := widget.NewEntry()
	formDialog := dialog.NewForm("Generate Certificate", "Generate", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Certificate Name", nameEntry),
			widget.NewFormItem("Duration (days)", durationEntry),
		},
		func(ok bool) {
			if !ok {
				return
			}
			duration, err := time.ParseDuration(durationEntry.Text + "d")
			if err != nil {
				dialog.ShowError(err, g.mainWindow)
				return
			}
			if err := g.secretr.GenerateCertificate(nameEntry.Text, duration); err != nil {
				dialog.ShowError(err, g.mainWindow)
				return
			}
			dialog.ShowInformation("Certificate Generated", "Certificate successfully generated.", g.mainWindow)
		}, g.mainWindow)
	formDialog.Show()
	g.mainWindow.Canvas().Focus(nameEntry)
}

func (g *GUI) verifySignature() {
	keyEntry := widget.NewEntry()
	dataEntry := widget.NewMultiLineEntry()
	signatureEntry := widget.NewEntry()
	formDialog := dialog.NewForm("Verify Signature", "Verify", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Key", keyEntry),
			widget.NewFormItem("Data", dataEntry),
			widget.NewFormItem("Signature", signatureEntry),
		},
		func(ok bool) {
			if !ok {
				return
			}
			valid, err := g.secretr.VerifySignature(keyEntry.Text, dataEntry.Text, signatureEntry.Text)
			if err != nil {
				dialog.ShowError(err, g.mainWindow)
				return
			}
			if valid {
				dialog.ShowInformation("Signature Verified", "The signature is valid.", g.mainWindow)
			} else {
				dialog.ShowError(fmt.Errorf("invalid signature"), g.mainWindow)
			}
		}, g.mainWindow)
	formDialog.Show()
	g.mainWindow.Canvas().Focus(keyEntry)
}

func (g *GUI) signData() {
	keyEntry := widget.NewEntry()
	dataEntry := widget.NewMultiLineEntry()
	formDialog := dialog.NewForm("Sign Data", "Sign", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Key", keyEntry),
			widget.NewFormItem("Data", dataEntry),
		},
		func(ok bool) {
			if !ok {
				return
			}
			signature, err := g.secretr.SignData(keyEntry.Text, dataEntry.Text)
			if err != nil {
				dialog.ShowError(err, g.mainWindow)
				return
			}
			dialog.ShowInformation("Data Signed", fmt.Sprintf("Signature: %s", signature), g.mainWindow)
		}, g.mainWindow)
	formDialog.Show()
	g.mainWindow.Canvas().Focus(keyEntry)
}

func (g *GUI) generateHash() {
	dataEntry := widget.NewMultiLineEntry()
	formDialog := dialog.NewForm("Generate Hash", "Generate", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Data", dataEntry),
		},
		func(ok bool) {
			if !ok {
				return
			}
			hash := g.secretr.GenerateHash(dataEntry.Text)
			dialog.ShowInformation("Hash Generated", fmt.Sprintf("Hash: %s", hash), g.mainWindow)
		}, g.mainWindow)
	formDialog.Show()
	g.mainWindow.Canvas().Focus(dataEntry)
}

func RunGUI() {
	application := app.New()
	application.Settings().SetTheme(theme.Current())
	resource := fyne.NewStaticResource("secretr.png", defaultIcon)
	application.SetIcon(resource)
	gui := NewGUI(application)
	gui.Run()
}
