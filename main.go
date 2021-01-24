package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/kataras/iris/v12"
)

func main() {
	app := iris.New()

	fmt.Println("Starting the application...")
	// ciphertext := encrypt([]byte("Hello World"), "password")
	// fmt.Printf("Encrypted: %x\n", ciphertext)

	// plaintext := decrypt(ciphertext, "password")
	// fmt.Printf("Decrypted: %s\n", plaintext)

	encryptFile("encrypted.txt", []byte("Hello World"), "password")

	app.Get("/", index)

	app.Listen(":8080")
}

func index(c iris.Context) {
	// c.Header("Content-Type", "application/pdf")
	decryptFile("encrypted.txt", "password")

	c.SendFile("decrypted.txt", "res.txt")
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func decryptFile(filename string, passphrase string) error {
	f, err := os.Create("decrypted.txt")

	if err != nil {
		log.Println(err)
		return err
	}

	defer f.Close()

	data := getCleanContent(filename, passphrase)
	f.Write(data)

	return nil
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

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func encryptFile(filename string, data []byte, passphrase string) {
	log.Println("Encrypting file...")
	f, _ := os.Create(filename)
	defer f.Close()
	f.Write(encrypt(data, passphrase))
}

func getCleanContent(filename string, passphrase string) []byte {
	log.Println("Getting file content...")
	data, _ := ioutil.ReadFile(filename)

	return decrypt(data, passphrase)
}
