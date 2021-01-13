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
	Long: 'Krypt is CLI that allows users to easily encrypt and decrypt files with sane defaults.'

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("encrypt called")
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)

}
