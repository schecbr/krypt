/*
Copyright © 2021 Brian Scheck <schecbr@gmail.com>

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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "The encrypt command will encrypt a file",
	Long: `Krypt is a CLI that allows users to easily encrypt and decrypt files
	with sane defaults.  You can encrypt a file by simply calling
	encrypt and passing in a passphrase to hash.`,

	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("encrypt called")
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

		outFilename := filename + ".enc"

		fmt.Println("passphrase: " + passphrase)
		fmt.Println("filename: " + filename)
		encryptFile(filename, outFilename, sha256Bytes[:])
		return nil
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().StringP("passphrase", "p", "", "Passphrase to create hash")
	encryptCmd.Flags().StringP("filename", "f", "", "Filename to encrypt")

}

func createHash(key string) []byte {
	//hasher := md5.New()
	//hasher.Write([]byte(key))
	sha256Bytes := sha256.Sum256([]byte(key))
	return sha256Bytes[:]
}

// encryptFile encrypts the file specified by filename with the given key,
// placing the result in outFilename (or filename + ".enc" if outFilename is
// empty). The key has to be 16, 24 or 32 bytes long to select between AES-128,
// AES-192 or AES-256. Returns the name of the output file if successful.

func encryptFile(filename string, outFilename string, sha256Bytes []byte) (string, error) {
	if len(outFilename) == 0 {
		outFilename = filename + ".enc"
	}

	plaintext, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}

	of, err := os.Create(outFilename)
	if err != nil {
		return "", err
	}
	defer of.Close()

	// Write the original plaintext size into the output file first, encoded in
	// a 8-byte integer.
	origSize := uint64(len(plaintext))
	if err = binary.Write(of, binary.LittleEndian, origSize); err != nil {
		return "", err
	}

	// Pad plaintext to a multiple of BlockSize with random padding.
	if len(plaintext)%aes.BlockSize != 0 {
		bytesToPad := aes.BlockSize - (len(plaintext) % aes.BlockSize)
		padding := make([]byte, bytesToPad)
		if _, err := rand.Read(padding); err != nil {
			return "", err
		}
		plaintext = append(plaintext, padding...)
	}

	// Generate random IV and write it to the output file.
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	if _, err = of.Write(iv); err != nil {
		return "", err
	}

	// Ciphertext has the same size as the padded plaintext.
	ciphertext := make([]byte, len(plaintext))

	// Use AES implementation of the cipher.Block interface to encrypt the whole
	// file in CBC mode.
	block, err := aes.NewCipher(sha256Bytes)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	if _, err = of.Write(ciphertext); err != nil {
		return "", err
	}
	return outFilename, nil
}
