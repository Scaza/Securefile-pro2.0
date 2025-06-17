#pragma once

#include "FileEncryptor.h"
#include "PasswordManager.h"
#include "RSAKeyManager.h"

namespace SecureFileApp {

    using namespace System;
    using namespace System::Windows::Forms;

    public ref class DecryptionForm : public Form {
    public:
        DecryptionForm() {
            InitializeComponent();
        }

    protected:
        ~DecryptionForm() {
            if (components) {
                delete components;
            }
        }

    private:
        TextBox^ filePathTextBox;
        TextBox^ passwordTextBox;
        Button^ browseButton;
        Button^ decryptButton;

        void InitializeComponent() {
            this->filePathTextBox = gcnew TextBox();
            this->passwordTextBox = gcnew TextBox();
            this->browseButton = gcnew Button();
            this->decryptButton = gcnew Button();

            // File Path TextBox
            this->filePathTextBox->Location = System::Drawing::Point(20, 20);
            this->filePathTextBox->Width = 200;
            this->filePathTextBox->PlaceholderText = "File to decrypt";

            // Password TextBox
            this->passwordTextBox->Location = System::Drawing::Point(20, 60);
            this->passwordTextBox->Width = 200;
            this->passwordTextBox->PlaceholderText = "Enter password";
            this->passwordTextBox->UseSystemPasswordChar = true;

            // Browse Button
            this->browseButton->Text = "Browse";
            this->browseButton->Location = System::Drawing::Point(230, 20);
            this->browseButton->Click += gcnew EventHandler(this, &DecryptionForm::OnBrowseClicked);

            // Decrypt Button
            this->decryptButton->Text = "Decrypt";
            this->decryptButton->Location = System::Drawing::Point(20, 100);
            this->decryptButton->Click += gcnew EventHandler(this, &DecryptionForm::OnDecryptClicked);

            // Add controls to the form
            this->Controls->Add(this->filePathTextBox);
            this->Controls->Add(this->passwordTextBox);
            this->Controls->Add(this->browseButton);
            this->Controls->Add(this->decryptButton);

            // Form properties
            this->Text = "Decrypt a File";
            this->Size = System::Drawing::Size(350, 200);
        }

        void OnBrowseClicked(Object^ sender, EventArgs^ e) {
            OpenFileDialog^ openFileDialog = gcnew OpenFileDialog();
            if (openFileDialog->ShowDialog() == DialogResult::OK) {
                filePathTextBox->Text = openFileDialog->FileName;
            }
        }

        void OnDecryptClicked(Object^ sender, EventArgs^ e) {
            String^ filePath = filePathTextBox->Text;
            String^ password = passwordTextBox->Text;

            if (String::IsNullOrEmpty(filePath) || String::IsNullOrEmpty(password)) {
                MessageBox::Show("Please provide both file path and password.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
                return;
            }

            // Call backend logic for decryption
            FileEncryptor decryptor;
            PasswordManager passwordManager;
            RSAKeyManager rsa;

            try {
                rsa.loadKeys();

                // Load encrypted AES key
                std::ifstream keyIn("encrypted_aes.key", std::ios::binary);
                if (!keyIn) {
                    MessageBox::Show("Error: Could not open encrypted_aes.key.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
                    return;
                }
                std::vector<unsigned char> encryptedAESKey((std::istreambuf_iterator<char>(keyIn)), {});
                keyIn.close();

                // Decrypt AES key
                std::vector<unsigned char> aesKey = rsa.decryptAESKey(encryptedAESKey);

                // Load salt
                std::ifstream saltIn("salt.bin", std::ios::binary);
                if (!saltIn) {
                    MessageBox::Show("Error: Could not open salt file.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
                    return;
                }
                std::vector<unsigned char> salt((std::istreambuf_iterator<char>(saltIn)), {});
                saltIn.close();

                // Set file paths and decrypt
                decryptor.setFilePaths(msclr::interop::marshal_as<std::string>(filePath), "decrypted_file.txt");
                decryptor.setKey(aesKey);
                decryptor.decryptFile();

                MessageBox::Show("File decrypted successfully!", "Success", MessageBoxButtons::OK, MessageBoxIcon::Information);
            }
            catch (const std::exception& ex) {
                MessageBox::Show(gcnew String(ex.what()), "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
            }
        }
    };
}#pragma once
