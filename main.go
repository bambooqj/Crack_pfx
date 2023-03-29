package main

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/pkcs12"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Result struct {
	sync.Mutex
	password string
}

func getPasswords(length int, charSet string, ch chan<- string, done <-chan struct{}) {
	if length == 1 {
		for _, char := range charSet {
			select {
			case ch <- string(char):
			case <-done:
				return
			}
		}
		return
	}
	getPasswordsWithPrefix("", length, charSet, ch, done)
}

func getPasswordsWithPrefix(prefix string, length int, charSet string, ch chan<- string, done <-chan struct{}) {
	if length == 0 {
		select {
		case ch <- prefix:
		case <-done:
		}
		return
	}
	for _, char := range charSet {
		getPasswordsWithPrefix(prefix+string(char), length-1, charSet, ch, done)
	}
}

func main() {
	// 从命令行参数中获取pfx文件路径和字节集

	pfxPath := flag.String("pfx", "12qwas.pfx", "path to pfx file")
	charSet := flag.String("charset", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-*/!@#$%^&*().", "character set")
	maxLength := flag.Int("maxlen", 6, "maximum password length")
	flag.Parse()

	pfxData, err := os.ReadFile(*pfxPath)
	if err != nil {
		fmt.Println(err)
		return
	}

	var wg sync.WaitGroup

	passwordChan := make(chan string, 1000)
	done := make(chan struct{})

	go func() {
		defer close(passwordChan)
		for i := 1; i <= *maxLength; i++ {
			getPasswords(i, *charSet, passwordChan, done)
		}
	}()

	res := Result{}
	const numWorkers = 1000
	sem := make(chan struct{}, numWorkers)

	attemptedPasswords := int64(0)
	totalPasswords := int64(0)
	for i := 1; i <= *maxLength; i++ {
		totalPasswords += int64(math.Pow(float64(len(*charSet)), float64(i)))
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				password, ok := <-passwordChan
				if !ok {
					break
				}
				res.Lock()
				if res.password != "" {
					res.Unlock()
					break
				}
				res.Unlock()

				sem <- struct{}{}
				go func(password string) {
					defer func() {
						<-sem
					}()
					_, err := pkcs12.ToPEM(pfxData, password)
					if err == nil {
						res.Lock()
						res.password = password
						res.Unlock()
						close(done)
					}
					if !strings.Contains(err.Error(), "decryption password incorrect") {
						fmt.Println("\npassword is: ", password)
						fmt.Println(err.Error())
					}
					atomic.AddInt64(&attemptedPasswords, 1)
					fmt.Printf("\r破解进度: %.2f / %.2f  正在测试密码: %s", float64(attemptedPasswords), float64(totalPasswords), password)
				}(password)
			}
		}()
	}
	wg.Wait()
	time.Sleep(time.Second * 2)

	res.Lock()
	foundPassword := res.password
	res.Unlock()

	if foundPassword != "" {
		fmt.Printf("\npassword is: %s\n", foundPassword)
	} else {
		fmt.Println("\n未找到密码")
	}
	fmt.Println("猜解完成")
}
