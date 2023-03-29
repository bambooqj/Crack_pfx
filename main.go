package main

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/pkcs12"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// 生成指定长度的密码并发送到通道中
func getPasswords(length int, charSet string, ch chan<- string) {
	if length == 1 {
		for _, char := range charSet {
			ch <- string(char)
		}
		return
	}
	getPasswordsWithPrefix("", length, charSet, ch)
}

// 生成以 prefix 为前缀的长度为 length 的密码并发送到通道中
func getPasswordsWithPrefix(prefix string, length int, charSet string, ch chan<- string) {
	if length == 0 {
		ch <- prefix
		return
	}
	for _, char := range charSet {
		getPasswordsWithPrefix(prefix+string(char), length-1, charSet, ch)
	}
}

func main() {
	// 从命令行参数中获取pfx文件路径和字节集
	pfxPath := flag.String("pfx", "12qwas.pfx", "path to pfx file")
	charSet := flag.String("charset", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-*/!@#$%^&*().", "character set")
	maxLength := flag.Int("maxlen", 6, "maximum password length")
	flag.Parse()

	// 读取pfx文件
	pfxData, err := os.ReadFile(*pfxPath)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 创建一个WaitGroup
	var wg sync.WaitGroup

	// 创建一个通道,用于存放可能的密码
	passwordChan := make(chan string, 1000)

	// 开始生成可能的密码
	go func() {
		defer close(passwordChan)
		for i := 1; i <= *maxLength; i++ {
			getPasswords(i, *charSet, passwordChan)
		}
	}()

	respass := ""
	const numWorkers = 1000
	sem := make(chan struct{}, numWorkers)

	attemptedPasswords := int64(0) // 新增：用于存储尝试的密码数量
	totalPasswords := int64(math.Pow(float64(len(*charSet)), float64(*maxLength)))

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for password := range passwordChan {
				if respass != "" {
					// 已找到正确密码，退出
					break
				}
				select {
				case <-time.After(10 * time.Millisecond):
					// 超时，跳过此次密码测试
				case sem <- struct{}{}:
					// 在限制的协程数内测试密码
					go func(password string) {
						defer func() {
							<-sem // 从sem通道中读取一个值，以便其他的goroutine可以向sem通道写入新的值
						}()
						if _, err := pkcs12.ToPEM(pfxData, password); err == nil {
							respass = password
						}
						// 新增：增加尝试的密码数量并打印破解进度
						atomic.AddInt64(&attemptedPasswords, 1)
						fmt.Printf("\r破解进度: %.2f / %.2f ", float64(attemptedPasswords), float64(totalPasswords))
					}(password)
				}
			}
		}()
	}
	// 等待所有任务完成
	wg.Wait()
	time.Sleep(time.Second * 2)
	if respass != "" {
		fmt.Printf("\npassword is: %s\n", respass)
	} else {
		fmt.Println("\n未找到密码")
	}
	fmt.Println("猜解完成")
}
