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
	"fmt"
	"github.com/spf13/cobra"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "The encrypt command will encrypt a file",
	Long: "Krypt is CLI that allows users to easily encrypt and decrypt files with sane defaults.",

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("encrypt called")
		encryptFile("master.key", []byte("Hello World"), "password1")
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)

}

func createHash(key string) string {
        hasher := md5.New()
        hasher.Write([]byte(key))
        return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) []byte {
        block, _ := aes.NewCipher([]byte(createHash(passphrase)))
        gcm, err := cipher.NewGCM(block)
        if err != nil {
                panic(err.Error())
        }
        nonce := make([]byte, gcm.NonceSize())
        if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
                panic(err.Error())
        }
        ciphertext := gcm.Seal(nonce, nonce, data, nil)
        return ciphertext
}

func encryptFile(filename string, data []byte, passphrase string) {
        f, _ := os.Create(filename)
        defer f.Close()
        f.Write(encrypt(data, passphrase))
}

