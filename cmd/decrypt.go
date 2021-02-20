/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "The decrypt command will decrypt a file",
	Long: `Krypt is a CLI that allows users to easily encrypt and decrypt files
    with sane defaults.  You can encrypt a file by simply calling
    encrypt and passing in a passphrase to hash.`,

	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("decrypt called")
		passphrase, _ := cmd.Flags().GetString("passphrase")
		filename, _ := cmd.Flags().GetString("filename")

		if passphrase == "" {
			return errors.New("Must specify a passphrase")
		}

		pdata := []byte(passphrase)
		sha256Bytes := sha256.Sum256(pdata)

		if filename == "" {
			return errors.New("Must specify a filename")
		}

		var outFilename string

		if filename[len(filename)-4:] == ".enc" {
			outFilename = strings.TrimRight(filename, ".enc")
		} else {
			outFilename = filename + ".dec"
		}

		fmt.Println("passphrase: " + passphrase)
		fmt.Println("filename: " + filename)
		fmt.Println("outFilename: " + outFilename)
		decryptFile(filename, outFilename, sha256Bytes[:])
		return nil
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// decryptCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// decryptCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	decryptCmd.Flags().StringP("passphrase", "p", "", "Passphrase to decrypt file")
	decryptCmd.Flags().StringP("filename", "f", "", "Filename to encrypt")
}

// decryptFile decrypts the file specified by filename with the given key. See
// doc for encryptFile for more details.
func decryptFile(filename string, outFilename string, sha256Bytes []byte) (string, error) {
	if len(outFilename) == 0 {
		outFilename = filename + ".dec"
	}

	ciphertext, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}

	of, err := os.Create(outFilename)
	if err != nil {
		return "", err
	}
	defer of.Close()

	// cipertext has the original plaintext size in the first 8 bytes, then IV
	// in the next 16 bytes, then the actual ciphertext in the rest of the buffer.
	// Read the original plaintext size, and the IV.
	var origSize uint64
	buf := bytes.NewReader(ciphertext)
	if err = binary.Read(buf, binary.LittleEndian, &origSize); err != nil {
		return "", err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err = buf.Read(iv); err != nil {
		return "", err
	}

	// The remaining ciphertext has size=paddedSize.
	paddedSize := len(ciphertext) - 8 - aes.BlockSize
	if paddedSize%aes.BlockSize != 0 {
		return "", fmt.Errorf("want padded plaintext size to be aligned to block size")
	}
	plaintext := make([]byte, paddedSize)

	block, err := aes.NewCipher(sha256Bytes)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext[8+aes.BlockSize:])

	if _, err := of.Write(plaintext[:origSize]); err != nil {
		return "", err
	}
	return outFilename, nil
}
